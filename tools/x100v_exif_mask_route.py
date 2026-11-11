"""Pin the X100V 3.01 EXIF descriptor-mask route in the official update.

This is static evidence about one constructor path, not a live mask read or
proof that an ordinary still uses the path. It does not patch firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_fw_explore import LOADS

# Pinned source instructions for context -> constructor -> global state -> loop.
WORDS = {
    0x01EE46F0: 0xE2841A03, 0x01EE46F4: 0xE5911034,
    0x01EE46F8: 0xE5831648, 0x01EE4A18: 0xE2853A12,
    0x01EE4A1C: 0xE5932648, 0x01EE4A20: 0xE58D200C,
    0x01EE4A48: 0xEBFFFEC9, 0x01EE4590: 0xE59B6010,
    0x01EE4598: 0xE6FF3076, 0x01EE459C: 0xE58D3000,
    0x01EE45A0: 0xE3A03000, 0x01EE45A4: 0xE1A01003,
    0x01EE45A8: 0xE3A00001, 0x01EE45AC: 0xEBC5CA59,
    0x01056F20: 0xE30CCBEC, 0x01056F24: 0xE340C196,
    0x01056F28: 0xE1CC00B0, 0x01056F2C: 0xE1CC10B2,
    0x01056F30: 0xE1CC20B4, 0x01056F34: 0xE58C3008,
    0x01056F38: 0xE1DB30B4, 0x01056F3C: 0xE1CC30BC,
    0x010663C0: 0xE30C3BEC, 0x010663C4: 0xE3403196,
    0x010663C8: 0xE1D3A0BC, 0x010663CC: 0xE1D330B0,
    0x010663D8: 0xE30085E0, 0x010663DC: 0xE340813F,
    0x010663E0: 0xE0888083, 0x0106648C: 0xE1D830B0,
    0x01066490: 0xE1A03083, 0x01066494: 0xE19A30B3,
    0x01066498: 0xE1D33002,
}


def mask_allows(mask_word: int, descriptor_flags: int = 1) -> bool:
    """The stock `bics`/`beq` result, given a supplied mask word."""
    if not 0 <= mask_word <= 0xFFFF or not 0 <= descriptor_flags <= 0xFFFF:
        raise ValueError("mask and flags must be halfwords")
    return (mask_word & ~descriptor_flags & 0xFFFF) == 0


def inspect(update: Path) -> dict:
    primary, secondary = load_images(update)
    images = {6: primary, 7: secondary}
    for address, expected in WORDS.items():
        part = 6 if address < LOADS[7] else 7
        actual = struct.unpack_from("<I", images[part], address - LOADS[part])[0]
        if actual != expected:
            raise ValueError(f"stock instruction differs at {address:#x}")
    base = LOADS[6]
    group = 1  # mov r0, #1 at 0x01ee45a8
    table_index = struct.unpack_from("<H", primary, 0x013F05E0 - base + 2 * group)[0]
    if table_index != 2:
        raise ValueError("stock group-1 mask index changed")
    flags = {}
    for tag, address in ((0xA002, 0x013F0928), (0xA003, 0x013F0948)):
        raw_tag, raw_flags = struct.unpack_from("<HH", primary, address - base)
        if (raw_tag, raw_flags) != (tag, 1):
            raise ValueError(f"dimension descriptor changed at {address:#x}")
        flags[f"{tag:04x}"] = raw_flags
    return {
        "scope": "Static constructor-to-mask provenance in official X100V 3.01; no live values or full caller",
        "update_sha256": hashlib.sha256(update.read_bytes()).hexdigest(),
        "primary_sha256": hashlib.sha256(primary).hexdigest(),
        "secondary_sha256": hashlib.sha256(secondary).hexdigest(),
        "pinned_instruction_words": {f"{a:#010x}": f"{w:#010x}" for a, w in WORDS.items()},
        "constructor_group": group,
        "mask_source": "low16(*(context+0x3034)) via secondary 0x01ee46f4/0x01ee4a1c/0x01ee4598 and primary 0x01056f3c",
        "mask_table_index": table_index,
        "mask_halfword_offset_from_source": 2 * table_index,
        "dimension_descriptor_flags": flags,
        "conditional_mask_examples": {str(v): mask_allows(v) for v in (0, 1, 2, 3)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.update)
    with args.report.open("x") as file:
        json.dump(result, file, indent=2)
        file.write("\n")
    print("group-1 mask route pinned; live mask remains unknown")


if __name__ == "__main__":
    main()
