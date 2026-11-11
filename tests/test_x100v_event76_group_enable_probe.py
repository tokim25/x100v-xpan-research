"""Stock event-76 group-46/66 enable gates, with synthetic ARM controls."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def source():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    expected = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == expected["secondary_sha256"]
    return image, expected["secondary_load"]


def test_group_callbacks_and_event76_rows_are_pinned():
    image, base = source()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    callback_table = 0x022DDF70
    assert callback_table + 8 * 46 + 4 == 0x022DE0E4
    assert callback_table + 8 * 66 + 4 == 0x022DE184
    assert word(0x022DE0E4) == 0x01F2C754
    assert word(0x022DE184) == 0x01F2C6BC

    assert [(word(a), word(a + 4)) for a in
            (0x022DC910, 0x022DC918, 0x022DC920)] == [
        (46, 0x022DB2C0), (66, 0x022DB31C), (15, 0x022DB3B4),
    ]
    assert [word(a) for a in (0x022DB2D8, 0x022DB2E4,
                              0x022DB358, 0x022DB364,
                              0x022DB3F0, 0x022DB3FC,
                              0x022DB408)] == [76] * 7

    # Both callbacks use the same per-slot group bitmap; group 46 alone
    # has the additional +0x967 guard.
    assert [word(a) for a in (0x01F2C6CC, 0x01F2C708,
                              0x01F2C764, 0x01F2C774,
                              0x01F2C7AC)] == [
        0xE5D035E8, 0xE3A01042, 0xE5D035E8,
        0xE5D03967, 0xE3A0102E,
    ]
    assert branch_target(word(0x01F2C710), 0x01F2C710) == 0x01F5AA48
    assert branch_target(word(0x01F2C7B4), 0x01F2C7B4) == 0x01F5AA48


def test_original_arm_group46_is_stricter_than_group66():
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_SP,
    )

    image, base = source()
    stop = 0x39000000
    context = 0x38010000
    slot = 7
    group_bitmap = 0x03426AB0 + 0x1488 * slot

    def run(entry, flag_5e8, flag_967, class_result, field_5ac, field_3038):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x01F2C000, 0x1000)
        uc.mem_write(0x01F2C000, image[0x01F2C000 - base:0x01F2D000 - base])
        uc.mem_map(context, 0x4000)
        uc.mem_map(0x38020000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_write(context + 0x5E8, bytes([flag_5e8]))
        uc.mem_write(context + 0x967, bytes([flag_967]))
        uc.mem_write(context + 0x5AC, bytes([field_5ac]))
        uc.mem_write(context + 0x3038, struct.pack("<H", field_3038))
        calls = []

        def intercept(engine, address, size, _):
            if address in (0x01F2C6C8, 0x01F2C760):
                engine.reg_write(UC_ARM_REG_R0, context)
                engine.reg_write(UC_ARM_REG_PC, address + 4)
            elif address in (0x01F2C6E0, 0x01F2C784):
                engine.reg_write(UC_ARM_REG_R0, class_result)
                engine.reg_write(UC_ARM_REG_PC, address + 4)
            elif address in (0x01F2C710, 0x01F2C7B4):
                calls.append((engine.reg_read(UC_ARM_REG_R0),
                              engine.reg_read(UC_ARM_REG_R1)))
                engine.reg_write(UC_ARM_REG_PC, stop)

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, slot)
        uc.reg_write(UC_ARM_REG_SP, 0x38021000)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(entry, stop, count=100)
        return calls

    for group, entry in ((66, 0x01F2C6BC), (46, 0x01F2C754)):
        assert run(entry, 0, 1, 0, 6, 0) == []
        assert run(entry, 1, 1, 0, 6, 0) == [(group_bitmap, group)]
        assert run(entry, 1, 1, 1, 6, 0) == []
        assert run(entry, 1, 1, 1, 11, 0) == [(group_bitmap, group)]
        assert run(entry, 1, 1, 1, 6, 1) == [(group_bitmap, group)]

    assert run(0x01F2C6BC, 1, 0, 0, 6, 0) == [(group_bitmap, 66)]
    assert run(0x01F2C754, 1, 0, 0, 6, 0) == []
