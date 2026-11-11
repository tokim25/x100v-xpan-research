"""Bounded stock event-76 to key-30 route; no live-camera scheduling claim."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def source_image():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    return image, source["secondary_load"]


def test_event_76_and_58_share_group_but_not_case_or_gate():
    image, base = source_image()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # The event table has distinct descriptors but the same callback.
    assert [word(0x022D9798 + 4 * i) for i in (0, 2, 5)] == [58, 0xDC, 0x01F32B7C]
    assert [word(0x022D9948 + 4 * i) for i in (0, 2, 5)] == [76, 0xE2, 0x01F32B7C]
    # The callback's switch indexes by event ID minus 0x1e.
    assert word(0x01F32B98 + 4 * (58 - 0x1E)) == 0x01F33024
    assert word(0x01F32B98 + 4 * (76 - 0x1E)) == 0x01F331C4
    assert word(0x022DC920) == 15
    assert word(0x022DC924) == 0x022DB3B4
    records = [struct.unpack_from("<III", image, address - base)
               for address in (0x022DB3D8, 0x022DB3F0,
                               0x022DB3FC, 0x022DB408)]
    assert records == [
        (58, 0, 0x022DB464),
        (76, 0, 0x022DB474),
        (76, 0x022DE370, 0x022DB480),
        (76, 0x022DE378, 0x022DB488),
    ]
    assert [word(0x022DB464 + 4 * i) for i in range(2)] == [103, 0xFFFFFFFF]
    assert [word(0x022DB474 + 4 * i) for i in range(3)] == [105, 51, 0xFFFFFFFF]
    assert [word(0x022DB480 + 4 * i) for i in range(2)] == [205, 0xFFFFFFFF]
    assert [word(0x022DB488 + 4 * i) for i in range(2)] == [199, 0xFFFFFFFF]


def test_non_special_classifier_routes_original_arm_to_key_30():
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R5,
    )

    image, base = source_image()
    word = lambda address: struct.unpack_from("<I", image, address - base)[0]
    assert branch_target(word(0x01F331C4), 0x01F331C4) == 0x01F0FE2C
    assert word(0x01F331C8) == 0xE3500001  # classifier == 1?
    assert branch_target(word(0x01F331CC), 0x01F331CC) == 0x01F33308
    assert word(0x01F33308) == 0xE3A0101E  # key 30
    assert branch_target(word(0x01F33310), 0x01F33310) == 0x01F21978

    stop = 0x38000000
    for classifier in (0, 2, 3, 4, 5, 6):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x01F33000, 0x1000)
        uc.mem_write(0x01F33000, image[0x01F33000 - base:0x01F34000 - base])
        uc.mem_map(stop, 0x1000)
        calls = []

        def intercept(engine, address, size, _):
            if address == 0x01F331C4:  # replace the classifier only
                engine.reg_write(UC_ARM_REG_R0, classifier)
                engine.reg_write(UC_ARM_REG_PC, 0x01F331C8)
            elif address == 0x01F33310:  # observe before request-builder BL
                calls.append((engine.reg_read(UC_ARM_REG_R0),
                              engine.reg_read(UC_ARM_REG_R1)))
                engine.reg_write(UC_ARM_REG_PC, stop)

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, 7)
        uc.reg_write(UC_ARM_REG_R5, 7)
        uc.emu_start(0x01F331C4, stop, count=32)
        assert calls == [(7, 30)]


def test_group15_list_order_and_forward_scheduler_stride_are_pinned():
    image, base = source_image()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # A group-15 scan encounters 58 before the three 76 alternatives.
    assert [word(a) for a in (0x022DB3D8, 0x022DB3F0,
                              0x022DB3FC, 0x022DB408)] == [58, 76, 76, 76]
    # The scheduler's row loop increments its index and advances one
    # 0x48-byte row before comparing with the row count and loading the
    # next row's ID. This is a conditional, per-pass order only.
    assert [word(a) for a in (0x01F1C4C8, 0x01F1C4CC,
                              0x01F1C4D0, 0x01F1C4D4,
                              0x01F1C4E0)] == [
        0xE2866001, 0xE2844048, 0xE1D930B0, 0xE1530006, 0xE5145004
    ]
