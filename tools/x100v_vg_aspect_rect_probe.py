"""Offline probe: give aspect code 2 the 65:24 rectangle in the VG aspect tables (X100V 3.01).

Secondary routine 0x01ea64d4 copies two 16-byte rectangles (x, y, width,
height as uint32) for an aspect code below 8: one from a 640x480 table at
0x022bf028, and one from a per-display table at 0x022bf0a8, eight rows
further on when its flag argument is set. Stock rows for code 2 are 16:9
and rows for code 4 are 65:24:

    0x022bf048  (0,  60,  640, 360)   code 2, 640x480
    0x022bf0c8  (0,  47,  900, 506)   code 2, 900x600 LCD
    0x022bf148  (0, 120, 1280, 720)   code 2, finder panel

The routine sits beside the code that logs "REC_VG_LIB ASPECT" and
"REC_VG_LIB CPV&OVFSW". No earlier card changed these rows, and the OVF's
solid bright frame is still unexplained, so this probe reshapes the three
code-2 rows to a centred 65:24: same x and width, height floor(w * 24 / 65).

Static reading only. What these rectangles draw is not established.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions

ROWS = {0x022BF048: (0, 60, 640, 360), 0x022BF0C8: (0, 47, 900, 506), 0x022BF148: (0, 120, 1280, 720)}
STOCK_6524_640 = (0x022BF068, (0, 122, 640, 236))  # code 4 in the 640x480 table


def rect_6524(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, w, h = rect
    new_h = w * 24 // 65
    return x, y + (h - new_h) // 2, w, new_h


def writes_for(secondary: bytes) -> list[dict]:
    address, rect = STOCK_6524_640
    if struct.unpack_from("<4I", secondary, address - LOADS[7]) != rect:
        raise ValueError("code 4 row is not the stock 65:24 rectangle")
    writes = []
    for address, rect in ROWS.items():
        at = address - LOADS[7]
        if struct.unpack_from("<4I", secondary, at) != rect:
            raise ValueError(f"{address:#x} is not the stock 16:9 rectangle")
        new = rect_6524(rect)
        writes.append({"field": f"vg-aspect-rect-code2-{rect[2]}x{rect[3]}", "partition": 7,
                       "partition_offset": at + 4, "address": f"0x{address + 4:08x}",
                       "before_hex": struct.pack("<3I", *rect[1:]).hex(),
                       "after_hex": struct.pack("<3I", *new[1:]).hex(),
                       "stock_rect": list(rect), "new_rect": list(new)})
    return writes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True, help="official X100V 3.01 FPUPDATE.DAT")
    parser.add_argument("--output", type=Path, required=True, help="manifest JSON to write")
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    writes = writes_for(stock_partitions(raw)[7])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "kind": "three VG aspect rectangles for code 2 reshaped to 65:24; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "reader": "0x01ea64d4, called from 0x01e9d968 and 0x01ea660c", "writes": writes}, indent=2) + "\n")
    for w in writes:
        print(w["field"], w["address"], w["stock_rect"], "->", w["new_rect"])


if __name__ == "__main__":
    main()
