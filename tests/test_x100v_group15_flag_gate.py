"""Bounded original-ARM check of the group-15 event-list enable gate."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_group15_callback_and_flag_gate_original_arm():
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_SP,
    )

    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # Callback-table index 13 can set group bit 15. Index 15 itself is null.
    assert word(0x022DDFDC) == 0x01F2B488
    assert word(0x022DDFEC) == 0
    assert branch_target(word(0x01F2B89C), 0x01F2B89C) == 0x01F5AA48
    assert word(0x01F2B864) == 0xE5D535E8  # ldrb r3,[r5,#0x5e8]

    slot = 7
    context = 0x38010000
    stop = 0x39000000
    bitmap = 0x03426AB0 + 0x1488 * slot

    def run(flag, class_result, field_3038):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x01F2B000, 0x2000)
        uc.mem_write(0x01F2B000, image[0x01F2B000 - base:0x01F2D000 - base])
        uc.mem_map(0x03420000, 0x20000)
        uc.mem_map(context, 0x4000)
        uc.mem_map(0x38020000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_write(context + 0x5E8, bytes([flag]))
        uc.mem_write(context + 0x5B0, b"\x20")
        uc.mem_write(context + 0x3038, struct.pack("<H", field_3038))
        calls = []

        def intercept(engine, address, _size, _user_data):
            instruction = word(address)
            if instruction & 0x0F000000 != 0x0B000000:
                return
            target = branch_target(instruction, address)
            if target == 0x01F272B4:  # per-slot context resolver
                engine.reg_write(UC_ARM_REG_R0, context)
            elif target == 0x01F0FE2C:  # synthetic class control
                engine.reg_write(UC_ARM_REG_R0, class_result)
            elif target == 0x01F5AA48:  # record group-bit setter call
                calls.append((engine.reg_read(UC_ARM_REG_R0),
                              engine.reg_read(UC_ARM_REG_R1)))
            else:
                raise AssertionError(f"unexpected call {target:#x} at {address:#x}")
            engine.reg_write(UC_ARM_REG_PC, address + 4)

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, slot)
        uc.reg_write(UC_ARM_REG_SP, 0x38021000)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(0x01F2B488, stop, count=500)
        return calls

    for class_result, field_3038 in ((0, 0), (1, 1), (1, 0), (2, 0)):
        for flag in (0, 1, 2, 3, 255):
            calls = run(flag, class_result, field_3038)
            assert all(address == bitmap for address, _bit in calls)
            expected = flag in (1, 2) and (class_result != 1 or field_3038 == 1)
            assert ((bitmap, 15) in calls) == expected
