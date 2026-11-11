"""Bounded direct STRB-offset screen for the stock group-66 context gate."""
import hashlib
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

from tools.fuji_xpan_validation import SOURCES


def test_group66_flag_zero_initializer_and_direct_offset_candidates():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # Ghidra: group 66 reads this byte from the selected per-slot context.
    assert word(0x01F2C6CC) == 0xE5D035E8
    # The context initializer sets it to zero, not to an enabling value.
    assert word(0x01F6B4E0) == 0xE3A03000
    assert word(0x01F6B4E4) == 0xE5C435E8
    # The lookalikes are respectively based on param_1+0x5000 and a global.
    assert word(0x01F5C978) == 0xE28AAA05
    assert (word(0x02021B10), word(0x02021B14)) == (0xE3053208, 0xE34032CA)

    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    direct_byte_store_offsets = []
    for offset in range(0, len(image) - 3, 4):
        if struct.unpack_from("<I", image, offset)[0] & 0xFFF != 0x5E8:
            continue
        instruction = next(decoder.disasm(image[offset:offset + 4], base + offset), None)
        if (instruction and instruction.mnemonic.startswith("strb")
                and "#0x5e8" in instruction.op_str):
            direct_byte_store_offsets.append(base + offset)
    assert direct_byte_store_offsets == [
        0x01F5C984, 0x01F6B4E4, 0x02021B18, 0x0235F150,
    ]


def test_group66_wide_store_lookalikes_are_not_direct_slot_byte_writers():
    """Enumerate exact +0x5e8 stores and pin bases of the wide-store lookalikes."""
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    stores = []
    for offset in range(0, len(image) - 3, 4):
        if word(base + offset) & 0xFFF != 0x5E8:
            continue
        instruction = next(decoder.disasm(image[offset:offset + 4], base + offset), None)
        if (instruction and instruction.mnemonic.startswith("str")
                and "#0x5e8" in instruction.op_str):
            stores.append(base + offset)
    assert stores == [
        0x01F5C984, 0x01F6B4E4, 0x01F782FC, 0x01F78368,
        0x02021B18, 0x020C7958, 0x020C7F7C, 0x020C8534,
        0x021245C8, 0x0235F150,
    ]

    # PC-relative literals used as r3 for three wide table-initializer stores.
    assert word(0x020C720C) == 0x025E05D0  # 0x020C7914 -> 0x020C7958
    assert word(0x020C7238) == 0x025DCF58  # 0x020C7F2C -> 0x020C7F7C
    assert word(0x020C9484) == 0x025DCF58  # 0x020C84E4 -> 0x020C8534
    # 0x021244AC/B0 builds another fixed global base in r3.
    assert (word(0x021244AC), word(0x021244B0)) == (
        0xE30C3558, 0xE34032A3,
    )


def _common_split_store_candidates(image, load):
    """Return local candidates; no CFG or register-liveness claim."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    direct_split_stores = []
    register_index_stores = []

    for offset in range(0, len(image) - 3, 4):
        word = struct.unpack_from("<I", image, offset)[0]
        is_add_imm = word & 0x0FE00000 == 0x02800000
        is_movw = word & 0x0FF00000 == 0x03000000
        if not (is_add_imm or is_movw):
            continue
        instruction = next(decoder.disasm(image[offset:offset + 4], load + offset), None)
        if instruction is None or len(instruction.operands) < 3 and not is_movw:
            continue
        if is_add_imm:
            if (not instruction.mnemonic.startswith("add")
                    or instruction.operands[2].type != ARM_OP_IMM):
                continue
            immediate = instruction.operands[2].imm
            if not 0x500 <= immediate <= 0x5E8:
                continue
        else:
            if (instruction.mnemonic != "movw"
                    or instruction.operands[1].type != ARM_OP_IMM
                    or instruction.operands[1].imm != 0x5E8):
                continue

        destination = instruction.operands[0].reg
        # A local straight-line window only. Branches/clobbers would
        # make a match a candidate, never a writer proof.
        end = min(offset + 132, len(image))
        for tail in range(offset + 4, end - 3, 4):
            store = next(decoder.disasm(image[tail:tail + 4], load + tail), None)
            if (store is None or not store.mnemonic.startswith("str")
                    or len(store.operands) < 2
                    or store.operands[1].type != ARM_OP_MEM):
                continue
            memory = store.operands[1].mem
            if is_add_imm and (memory.base == destination
                               and memory.index == 0
                               and memory.disp == 0x5E8 - immediate):
                direct_split_stores.append((load + offset, load + tail))
            if is_movw and memory.index == destination:
                register_index_stores.append((load + offset, load + tail))
    return direct_split_stores, register_index_stores


def test_group66_common_split_offset_direct_store_forms_both_partitions():
    """Bound two local addressing idioms, not helpers or whole-context copies."""
    source = SOURCES["x100v_3_01"]

    for partition, load in (("primary", source["primary_load"]),
                            ("secondary", source["secondary_load"])):
        number = 6 if partition == "primary" else 7
        image = Path(f"out/fw-cache/x100v-301-part{number}.bin").read_bytes()
        assert hashlib.sha256(image).hexdigest() == source[f"{partition}_sha256"]
        assert _common_split_store_candidates(image, load) == ([], [])


def test_common_split_store_screen_positive_controls():
    """The exact two search idioms are detectable in independent small vectors."""
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    base = SOURCES["x100v_3_01"]["secondary_load"]
    add_word = struct.unpack_from("<I", image, 0x01E8831C - base)[0]
    movw_word = struct.unpack_from("<I", image, 0x01BF9A5C - base)[0]
    assert _common_split_store_candidates(
        struct.pack("<II", add_word, 0xE5C20008), 0x1000
    ) == ([(0x1000, 0x1004)], [])
    assert _common_split_store_candidates(
        struct.pack("<II", movw_word, 0xE7C21000), 0x2000
    ) == ([], [(0x2000, 0x2004)])


def test_cross_partition_helper_writes_a_fields_not_flag_directly():
    """Pin the original ARM of the primary helper reached from the still root.

    This covers its direct stores, not indirect/global side effects elsewhere.
    """
    source = SOURCES["x100v_3_01"]
    image = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == source["primary_sha256"]
    base = source["primary_load"]
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    def instructions(address, size):
        data = image[address - base:address - base + size]
        decoded = list(decoder.disasm(data, address))
        assert sum(item.size for item in decoded) == size
        return [(item.address, item.mnemonic, item.op_str) for item in decoded]

    wrapper = instructions(0x0115E3E4, 20)
    assert wrapper[2] == (0x0115E3EC, "strb", "r2, [r0, #0xae4]")
    assert wrapper[3] == (0x0115E3F0, "bl", "#0x115e358")

    child = instructions(0x0115E358, 140)
    context_stores = [
        (address, mnemonic, operands)
        for address, mnemonic, operands in child
        if mnemonic.startswith("str") and ("[r0," in operands or "[r4," in operands)
    ]
    assert context_stores == [
        (0x0115E37C, "str", "r5, [r0, #0xa40]"),
        (0x0115E39C, "strh", "r2, [r4, r3]"),
        (0x0115E3B8, "str", "r3, [r4, #0xa38]"),
        (0x0115E3D8, "strh", "r2, [r4, r3]"),
    ]
    assert (0x0115E398, "movw", "r3, #0xa3c") in child
    assert (0x0115E3D4, "movw", "r3, #0xb94") in child
    assert not any("#0x5e8" in operands for _, _, operands in wrapper + child)
