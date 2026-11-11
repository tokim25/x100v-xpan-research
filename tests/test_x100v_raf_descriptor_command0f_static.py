"""Bounded stock command-0f write to the candidate RAF descriptor slot."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_script_stage_audit import rows_for
from tools.x100v_fw_explore import branch_target


def source():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    expected = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == expected["secondary_sha256"]
    return image, expected["secondary_load"]


def test_command_0f_is_unique_to_key17_and_event50_can_request_it():
    image, base = source()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    rows = rows_for(image)
    assert len(rows) == 42
    assert [r["key"] for r in rows if 0x0F in bytes.fromhex(r["opcodes_hex"])] == [17]
    assert bytes.fromhex(rows[17]["opcodes_hex"]) == bytes.fromhex("0f0d0e9d9e")
    assert rows[17]["address"] == "0x22df438"

    # Event 50's descriptor points to the shared callback; its distinct
    # jump-table case begins at 0x01f32e4c. A gated branch can reach the
    # key-17 request, but this is not normal-still execution evidence.
    assert [word(0x022D96D8 + 4 * i) for i in (0, 2, 5)] == [50, 0xE1, 0x01F32B7C]
    assert word(0x01F32B98 + 4 * (50 - 0x1E)) == 0x01F32E4C
    assert [word(a) for a in (0x01F32EC0, 0x01F32EC4)] == [0xE3A01011, 0xE1A00005]
    assert branch_target(word(0x01F32EC8), 0x01F32EC8) == 0x01F21978

    # The four stored group lists containing event 50 are not an execution
    # order. The rows have different prerequisites and predicates.
    assert [(word(a), word(a + 4)) for a in
            (0x022DC8F0, 0x022DC900, 0x022DC8D0, 0x022DC9D0)] == [
        (10, 0x022DB108), (69, 0x022DB1F0),
        (61, 0x022DC6E4), (67, 0x022DC644),
    ]
    assert [word(a) for a in (0x022DB150, 0x022DB15C, 0x022DB1FC,
                              0x022DC6F0, 0x022DC644)] == [50] * 5


def test_command_0f_has_a_conditional_in_place_raf_descriptor_transform():
    image, base = source()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # The handler checks context+0x48, passes the same slot as input/output
    # to the transform, then copies seven words back to context+0x48.
    assert [word(a) for a in (0x01F3E814, 0x01F3E818,
                              0x01F3E82C, 0x01F3E830, 0x01F3E834,
                              0x01F3E83C, 0x01F3E840)] == [
        0xE2853901, 0xE2852048, 0x05941000, 0x02811048,
        0x13A01000, 0xE1A02008, 0xE1A00005,
    ]
    assert branch_target(word(0x01F3E844), 0x01F3E844) == 0x01EDACF0
    assert [word(a) for a in (0x01F3E854, 0x01F3E858,
                              0x01F3E85C, 0x01F3E860)] == [
        0xE8BE000F, 0xE8AC000F, 0xE89E0007, 0xE88C0007,
    ]

    # The callee's seven-word output write is separate from command-0x15's
    # +0xd4/+0xf0 JPEG/compression descriptor. No actual crop is inferred.
    assert [word(a) for a in (0x01EDB030, 0x01EDB034,
                              0x01EDB038, 0x01EDB03C)] == [
        0xE8BC000F, 0xE8A4000F, 0xE89C0007, 0xE8840007,
    ]


def test_event50_direct_slot_key17_request_requires_bit15_clear():
    """Original ARM, synthetic gate values; not a normal-still trace."""
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R5

    image, base = source()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    assert [word(a) for a in (0x01F32E5C, 0x01F32E68, 0x01F32E7C,
                              0x01F32E84, 0x01F33514)] == [
        0xE3A0100F, 0xE3500001, 0xE1550003, 0x0A00000D, 0x03426AB0,
    ]
    assert branch_target(word(0x01F32E64), 0x01F32E64) == 0x01F5AAD4
    assert branch_target(word(0x01F32E84), 0x01F32E84) == 0x01F32EC0
    # The helper returns 1 when the requested bit is already set, not when
    # it is clear; the event case skips the key-17 request on return 1.
    assert [word(a) for a in (0x01F5AAF4, 0x01F5AAF8,
                              0x01F5AAFC, 0x01F5AB00)] == [
        0xE7902101, 0xE1D33002, 0x03A00001, 0x13A00000,
    ]

    stop = 0x38000000
    for bit15_already_set in (False, True):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x01F32000, 0x2000)
        uc.mem_write(0x01F32000, image[0x01F32000 - base:0x01F34000 - base])
        uc.mem_map(0x0341D000, 0x1000)
        uc.mem_write(0x0341D174, struct.pack("<I", 7))  # direct-slot match
        uc.mem_map(stop, 0x1000)
        reached = []

        def intercept(engine, address, size, _):
            if address == 0x01F32E64:  # replace only the bitmap helper
                engine.reg_write(UC_ARM_REG_R0, int(bit15_already_set))
                engine.reg_write(UC_ARM_REG_PC, 0x01F32E68)
            elif address == 0x01F32EC8:
                reached.append(("key17", engine.reg_read(UC_ARM_REG_R0),
                                engine.reg_read(UC_ARM_REG_R1)))
                engine.reg_write(UC_ARM_REG_PC, stop)
            elif address == 0x01F32ED4:
                reached.append(("skipped",))
                engine.reg_write(UC_ARM_REG_PC, stop)

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, 7)
        uc.reg_write(UC_ARM_REG_R5, 7)
        uc.emu_start(0x01F32E4C, stop, count=64)
        assert reached == ([('skipped',)] if bit15_already_set
                           else [('key17', 7, 17)])


def test_bit15_is_same_slot_group15_enable_and_event76_has_other_groups():
    image, base = source()

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # Event 50's guard reads group bitmap base + 0x1488*slot, whereas the
    # group-15 enabler ORs bit 15 at the same per-slot root. If group 15 is
    # already enabled for that slot, the direct key-17 request is skipped.
    assert 0x0341CCB8 + 0x9DF8 == 0x03426AB0
    assert word(0x01F33514) == 0x03426AB0
    assert [word(a) for a in (0x01F2B880, 0x01F2B884, 0x01F2B888,
                              0x01F2B88C, 0x01F2B890, 0x01F2B894,
                              0x01F2B898)] == [
        0xE3010488, 0xE3093DF8, 0xE0243490, 0xE30C0CB8,
        0xE3400341, 0xE3A0100F, 0xE0800004,
    ]
    assert branch_target(word(0x01F2B89C), 0x01F2B89C) == 0x01F5AA48

    # The key-30-producing event 76 is also listed under groups 46 and
    # 66; group-15 suppression does not establish global exclusion.
    assert [(word(a), word(a + 4)) for a in
            (0x022DC910, 0x022DC918, 0x022DC920)] == [
        (46, 0x022DB2C0), (66, 0x022DB31C), (15, 0x022DB3B4),
    ]
    assert [word(a) for a in (0x022DB2D8, 0x022DB2E4, 0x022DB358,
                              0x022DB364, 0x022DB3F0, 0x022DB3FC,
                              0x022DB408)] == [76] * 7
