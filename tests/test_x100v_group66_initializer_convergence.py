"""Bounded stock-ARM check of the still-context flag initializer tail."""

import hashlib
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs

from tools.fuji_xpan_validation import SOURCES


def test_mode_dispatch_reconverges_at_group66_flag_clear():
    source = SOURCES["x100v_3_01"]
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def instruction(address):
        offset = address - base
        return next(decoder.disasm(image[offset:offset + 4], address))

    assert [(instruction(address).mnemonic, instruction(address).op_str)
            for address in (0x01F6B4BC, 0x01F6B4C0, 0x01F6B4C4,
                            0x01F6B4C8, 0x01F6B4CC, 0x01F6B4D0)] == [
        ("cmp", "r3, #6"), ("beq", "#0x1f6ba58"),
        ("cmp", "r3, #8"), ("beq", "#0x1f6ba78"),
        ("cmp", "r3, #3"), ("beq", "#0x1f6ba68"),
    ]
    assert (instruction(0x01F6BA54).mnemonic,
            instruction(0x01F6BA54).op_str) == ("b", "#0x1f6b4b8")

    # The four mode branches store 1/2/3/4 at +0x2fc0, then converge
    # before the unconditional zero store at +0x5e8. This does not model
    # runtime reachability or any later writer.
    for branch, mode, target in (
        (0x01F6BA64, 2, 0x01F6B4E0),
        (0x01F6BA74, 3, 0x01F6B4E0),
        (0x01F6BA84, 4, 0x01F6B4E0),
    ):
        assert instruction(branch - 4).op_str == f"r2, [r3, #0xfc0]"
        assert instruction(branch - 8).op_str == f"r2, #{mode}"
        assert (instruction(branch).mnemonic, instruction(branch).op_str) == (
            "b", f"#0x{target:x}")
    assert (instruction(0x01F6B4DC).mnemonic,
            instruction(0x01F6B4DC).op_str) == ("strb", "r2, [r3, #0xfc0]")
    assert (instruction(0x01F6B4E0).mnemonic,
            instruction(0x01F6B4E0).op_str) == ("mov", "r3, #0")
    assert (instruction(0x01F6B4E4).mnemonic,
            instruction(0x01F6B4E4).op_str) == ("strb", "r3, [r4, #0x5e8]")


def test_initializer_post_clear_copy_destinations_are_disjoint():
    source = SOURCES["x100v_3_01"]
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    start, end = 0x01F6B4E8, 0x01F6B5D8
    code = image[start - base:end - base]
    instructions = list(decoder.disasm(code, start))
    assert sum(ins.size for ins in instructions) == end - start
    assert [(ins.address, ins.op_str) for ins in instructions if ins.mnemonic == "bl"] == [
        (0x01F6B53C, "#0x1f52cc8"),
        (0x01F6B554, "#0x1140808"),
        (0x01F6B56C, "#0x1140808"),
        (0x01F6B578, "#0x1f52cf4"),
        (0x01F6B590, "#0x1140174"),
    ]
    # Exact source-byte address setup: +0x303c, +0x32ca, +0x32de,
    # +0x5270 and +0x62a. Their observed writes do not span +0x5e8.
    assert [(ins.address, ins.op_str) for ins in instructions
            if ins.address in (0x01F6B538, 0x01F6B54C, 0x01F6B550,
                               0x01F6B564, 0x01F6B568, 0x01F6B570,
                               0x01F6B574, 0x01F6B588, 0x01F6B58C)] == [
        (0x01F6B538, "r0, r5, #0x3c"),
        (0x01F6B54C, "r0, r4, #0x32c0"),
        (0x01F6B550, "r0, r0, #0xa"),
        (0x01F6B564, "r0, r4, #0x32c0"),
        (0x01F6B568, "r0, r0, #0x1e"),
        (0x01F6B570, "r0, r4, #0x5200"),
        (0x01F6B574, "r0, r0, #0x70"),
        (0x01F6B588, "r0, r4, #0x620"),
        (0x01F6B58C, "r0, r0, #0xa"),
    ]
