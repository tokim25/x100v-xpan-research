"""Pinned stock command-14 registration tuple and immutable key-47 banks."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_command14_registration_tuple_matches_raw_descriptor_lookup():
    source = SOURCES["x100v_3_01"]
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    def read(address, size):
        return image[address - base:address - base + size]

    assert read(0x022E0E4C, 8) == bytes.fromhex("060300001c112e02")
    assert read(0x022E0E54, 8) == bytes.fromhex("07030000841f2e02")
    for address in (0x022E114C, 0x022E1F9C):
        assert read(address, 8) == bytes.fromhex("14002f0000000000")
    assert word(0x01F3C028) == 0xE5D2903B  # group from object +0x3b
    assert [word(a) for a in (0x01F3C0D8, 0x01F3C0E4, 0x01F3C110,
                              0x01F3C11C, 0x01F3C120)] == [
        0xE1570003, 0xE5D43001, 0xE5D53001, 0xE5D52003, 0xE5D51002,
    ]
    assert branch_target(word(0x01F3C128), 0x01F3C128) == 0x01F3BF1C
    assert branch_target(word(0x01F3BF98), 0x01F3BF98) == 0x01ED3BFC
    assert [word(a) for a in (0x01F4F944, 0x01F4F948, 0x01F4F94C)] == [
        0xE3A02000, 0xE3A0102F, 0xE1A00004,
    ]
    assert branch_target(word(0x01F4F950), 0x01F4F950) == 0x01F4F328
    assert read(0x022DF784, 20) == bytes.fromhex(
        "140028002900280029000000200d020609000000")
    assert branch_target(word(0x01F4F938), 0x01F4F938) == 0x01F3CBE8
    assert branch_target(word(0x01F3CC1C), 0x01F3CC1C) == 0x01F3C480
    assert branch_target(word(0x01F3C498), 0x01F3C498) == 0x01F3C148
    assert branch_target(word(0x01F3C15C), 0x01F3C15C) == 0x01F3BFFC

    # Both branches of the group-6 setup use the same selector storage and
    # initialize object +0x3c from a runtime RAM source (not a fixed ID).
    assert [word(a) for a in (0x01F4B33C, 0x01F4B340,
                              0x01F4B4C4, 0x01F4B4C8)] == [
        0xE3A09006, 0xE5C59808, 0xE5D33808, 0xE5C4303B,
    ]
    assert branch_target(word(0x01F4B488), 0x01F4B488) == 0x01F4B540
    assert branch_target(word(0x01F4B550), 0x01F4B550) == 0x01F4AFAC
    assert [word(a) for a in (0x01F4B084, 0x01F4B088,
                              0x01ED6438, 0x01ED643C, 0x01ED6440)] == [
        0xE5D32808, 0xE5C4203B, 0xE280303C, 0xE8910007, 0xE8830007,
    ]
    assert word(0x01F4B2F8) == word(0x01F4B6A8) == 0x028A8A98
    assert [word(a) for a in (0x01F4ACAC, 0x01F4ACB0)] == [
        0xE3A02007, 0xE5C32808,
    ]
    assert word(0x01F4ADF0) == 0x028A8048
    # Source ID is an allocated key-0 handle, not the key-0x2f record.
    assert [word(a) for a in (0x01ED3FA0, 0x01ED3FAC,
                              0x01ED3FC4, 0x01ED3FCC,
                              0x01ED3E80, 0x01ED3E84,
                              0x01ED3F04, 0x01ED3F20,
                              0x01ED3F24)] == [
        0xE3A0200C, 0xE3A02004, 0xE1A00001, 0xE5C45008,
        0xE1D730F0, 0xE3530000, 0xE1C420B0, 0xE5843004,
        0xE5C45002,
    ]
    assert branch_target(word(0x01ED3FC8), 0x01ED3FC8) == 0x01ED3E38
    assert branch_target(word(0x01ED3E54), 0x01ED3E54) == 0x01ED228C
    assert read(0x022C6D6C, 12) == struct.pack("<3I", 128, 0, 0)
    assert branch_target(word(0x01F4B64C), 0x01F4B64C) == 0x01F3A7F8
    assert word(0x01F3A898) == 0xE3013218  # transport message ID
    assert branch_target(word(0x01F3A8C4), 0x01F3A8C4) == 0x0113D87C

    header_base = 0x022C346C + 20 * (0x2F - 0x1B)
    observed = [struct.unpack_from("<5I", image, header_base + bank * 0x5F0 - base)
                for bank in range(8)]
    assert [header[0] for header in observed] == [8, 0, 3, 0, 0, 0, 3, 3]
    assert [header[2] for header in observed] == [
        0x022D10BC, 0, 0x022CB07C, 0, 0, 0, 0x022C94EC, 0x022D1298,
    ]
    assert [read(observed[bank][2], 1)[0] for bank in (0, 2, 6, 7)] == [0, 0, 2, 2]
    assert read(observed[6][2], 3 * 28) == read(observed[7][2], 3 * 28)
    assert [word(a) for a in (0x01F4F3BC, 0x01F4F3C0,
                              0x01F4F3D8, 0x01F4F3EC)] == [
        0xE5D48000, 0xE5947004, 0xE59600B0, 0xE5961038,
    ]
    layout_base = 0x022D3D04
    layout_rows = [(
        word(layout_base + i * 0x120),
        word(layout_base + i * 0x120 + 0x38),
        word(layout_base + i * 0x120 + 0xB0),
        word(layout_base + i * 0x120 + 0xB4),
    ) for i in range(22)]
    assert [row[0] for row in layout_rows] == [
        1, 0x13, 0x27, 0x28, 0x29, 0x2A, 0xFF, 0x47, 0x5B,
        0xFE, 0x3F, 0x71, 0x72, 0x73, 0x74, 0x44, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7A,
    ]
    assert {row[1] for row in layout_rows} == {0, 1, 8, 12, 0x1A8}
    assert {(row[2], row[3]) for row in layout_rows} == {(5, 1), (0, 0)}


def test_original_arm_group6_7_command14_preflight_arguments():
    """Execute only the stock group-table preflight with synthetic RAM.

    Stop at the registration helper: this proves arguments and local order,
    not successful registration or ordinary-still reachability.
    """
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_A15)

    source = SOURCES["x100v_3_01"]
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def run(group, selector):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for page, size in ((0x01F3B000, 0x2000), (0x022E0000, 0x2000)):
            uc.mem_map(page, size)
            uc.mem_write(page, image[page - base:page - base + size])
        uc.mem_map(0x30000000, 0x20000)
        uc.mem_map(0x32000000, 0x1000)
        uc.mem_write(0x30000000, struct.pack("<I", 0x30001000))
        uc.mem_write(0x3000103B, bytes([group]))
        uc.reg_write(UC_ARM_REG_R0, 0x30000000)
        uc.reg_write(UC_ARM_REG_R1, 0x14)
        uc.reg_write(UC_ARM_REG_R2, selector)
        uc.reg_write(UC_ARM_REG_SP, 0x3001FF00)
        uc.reg_write(UC_ARM_REG_LR, 0x32000000)
        reached = []

        def stop(engine, address, size, user_data):
            if address == 0x01F3BF1C:
                reached.append((engine.reg_read(UC_ARM_REG_R0),
                                engine.reg_read(UC_ARM_REG_R1),
                                engine.reg_read(UC_ARM_REG_R2)))
                engine.emu_stop()
            elif address == 0x32000000:
                engine.emu_stop()

        uc.hook_add(UC_HOOK_CODE, stop)
        uc.emu_start(0x01F3BFFC, 0, count=300, timeout=1_000_000)
        return reached

    expected = [(0x30000000, 0x2F, 0)]
    assert run(6, 0) == expected
    assert run(7, 0) == expected
    assert run(6, 1) == []  # selector-0 record does not match stage 1
