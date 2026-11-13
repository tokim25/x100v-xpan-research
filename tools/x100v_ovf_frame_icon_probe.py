"""Offline probe: draw the 3:2 bright-frame icon at the 16:9 setting (X100V 3.01).

Overlay code at 0x03790b60..0x03790dec chooses one of three screen objects
by the IMAGE SIZE property 0x3bf, through predicates 0x03767d2c (1:1),
0x03767be4 (3:2) and 0x03767c88 (16:9). The objects sit in an overlay table
of 0x54-byte records and name full-plane 640x480 icons:

    0x03b032f0  0xFF000599  ICO_BR_FRAME_LX12_1_1
    0x03b03344  0xFF00059A  ICO_BR_FRAME_LX12_3_2
    0x03b03398  0xFF00059B  ICO_BR_FRAME_LX12_16_9

Each branch loads its record pointer from a literal pool word. This probe
changes the 16:9 branch's word at 0x03790e08 to the 3:2 record. If these
icons are the OVF's solid bright frame, the frame at the 16:9 setting
becomes 3:2 on the camera. It is a discriminator, not a 65:24 frame: the
firmware has no 65:24 icon.

Static reading only. Which screen this code draws is unproven.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_exif_buffer_emulator import load_overlay

OVERLAY_LOAD = 0x03720000
OVERLAY_SHA256 = "cb8770127a28edff2474ce8f05d7ccb39a33a39e02801a2449182fb5843855b3"
POOL = {"1:1": 0x03790E00, "3:2": 0x03790E04, "16:9": 0x03790E08}
RECORDS = {"1:1": 0x03B032F0, "3:2": 0x03B03344, "16:9": 0x03B03398}
ICONS = {"1:1": 0xFF000599, "3:2": 0xFF00059A, "16:9": 0xFF00059B}
LOADERS = {"1:1": 0x03790D90, "3:2": 0x03790DB8, "16:9": 0x03790DE0}  # ldr r0, [pc, #imm]


def word(overlay: bytes, address: int) -> int:
    return struct.unpack_from("<I", overlay, address - OVERLAY_LOAD)[0]


def check_stock(overlay: bytes) -> None:
    for aspect, pool in POOL.items():
        if word(overlay, pool) != RECORDS[aspect]:
            raise ValueError(f"{aspect} pool word is not the stock record pointer")
        if word(overlay, RECORDS[aspect] + 4) != ICONS[aspect]:
            raise ValueError(f"{aspect} record does not name the expected icon")
        if word(overlay, RECORDS[aspect] + 0x18) != (480 << 16 | 640):
            raise ValueError(f"{aspect} record is not a 640x480 object")
        load = word(overlay, LOADERS[aspect])
        if load & 0xFFFFF000 != 0xE59F0000 or LOADERS[aspect] + 8 + (load & 0xFFF) != pool:
            raise ValueError(f"{aspect} branch does not load its pool word into r0")


def writes_for(overlay: bytes) -> list[dict]:
    check_stock(overlay)
    at = POOL["16:9"] - OVERLAY_LOAD
    return [{"field": "ovf-frame-icon-16x9-draws-3x2", "partition": 9, "partition_offset": at,
             "address": f"0x{POOL['16:9']:08x}",
             "before_hex": struct.pack("<I", RECORDS["16:9"]).hex(),
             "after_hex": struct.pack("<I", RECORDS["3:2"]).hex()}]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True, help="official X100V 3.01 FPUPDATE.DAT")
    parser.add_argument("--output", type=Path, required=True, help="manifest JSON to write")
    args = parser.parse_args()
    overlay = load_overlay(args.stock)
    if hashlib.sha256(overlay).hexdigest() != OVERLAY_SHA256:
        raise SystemExit("overlay differs from the pinned X100V 3.01 image")
    writes = writes_for(overlay)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "kind": "16:9 bright-frame object swapped for the 3:2 one; one overlay literal; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(args.stock.read_bytes()).hexdigest(),
        "overlay_sha256": OVERLAY_SHA256,
        "writes": writes}, indent=2) + "\n")
    for w in writes:
        print(w["field"], w["address"], w["before_hex"], "->", w["after_hex"])


if __name__ == "__main__":
    main()
