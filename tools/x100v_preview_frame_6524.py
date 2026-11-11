"""Offline writes that give the 16:9 preview windows a centred 65:24 shape (X100V 3.01).

The preview selector 0x01eb21dc is the only reader of the rectangle table at
0x022bf858: 32-byte records, 17 rows per family, each an outer frame and an
inner window (x, y, w, h halfwords at +0 and +8). Preview code 2 (16:9)
selects family-0 rows 2, 9 and 15; families 1 and 2 also carry a 16:9 inner
window at row 15. Every 16:9 window is full width, centred, with height
w * 9 / 16 (rounded down, or to nearest for the 375-wide row); the dormant
65:24 rows 4 and 11 use w * 24 / 65 rounded down. These writes keep x and w and replace y and h with
floor(w * 24 / 65), centred in the outer frame.

Static data only: whether the inner window clips or scales the live image is
not established, and no display or camera behaviour is claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions

TABLE = 0x022BF858
RECORD = 32
ROWS = 17
TARGETS = ((0, 2), (0, 9), (0, 15), (1, 15), (2, 15))  # (family, row) with a 16:9 inner window


def record_address(family: int, row: int) -> int:
    return TABLE + (family * ROWS + row) * RECORD


def window_6524(outer: tuple[int, int, int, int], inner: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    ox, oy, ow, oh = outer
    x, _, w, _ = inner
    h = w * 24 // 65
    return x, oy + (oh - h) // 2, w, h


def is_16x9_window(outer, inner) -> bool:
    ox, oy, ow, oh = outer
    x, y, w, h = inner
    return w == ow and h in (w * 9 // 16, (w * 9 + 8) // 16) and y == oy + (oh - h) // 2


def writes_for(secondary: bytes) -> list[dict]:
    writes = []
    for family, row in TARGETS:
        address = record_address(family, row)
        at = address - LOADS[7]
        rec = secondary[at:at + RECORD]
        outer, inner = struct.unpack_from("<4H", rec, 0), struct.unpack_from("<4H", rec, 8)
        if not is_16x9_window(outer, inner):
            raise ValueError(f"family {family} row {row} is not the stock 16:9 window")
        new = window_6524(outer, inner)
        before = struct.pack("<3H", *inner[1:])  # y, w, h at +10..+15
        after = struct.pack("<3H", *new[1:])
        writes.append({"field": f"preview-window-f{family}-r{row}", "partition": 7, "address": address + 10,
                       "partition_offset": at + 10, "before_hex": before.hex(), "after_hex": after.hex(),
                       "stock_inner": list(inner), "new_inner": list(new), "outer": list(outer)})
    return writes


def table_diff(stock: bytes, patched: bytes) -> list[int]:
    start, end = TABLE - LOADS[7], TABLE - LOADS[7] + 3 * ROWS * RECORD
    return [start + i for i in range(end - start) if stock[start + i] != patched[start + i]]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    secondary = stock_partitions(raw)[7]
    writes = writes_for(secondary)
    patched = bytearray(secondary)
    for w in writes:
        new = bytes.fromhex(w["after_hex"])
        patched[w["partition_offset"]:w["partition_offset"] + len(new)] = new
    changed = table_diff(secondary, bytes(patched))
    allowed = {w["partition_offset"] + k for w in writes for k in (0, 1, 4, 5)}
    manifest = {
        "kind": "16:9 preview windows reshaped to centred 65:24; static data writes, offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "table": f"0x{TABLE:08x}",
        "reader": "0x01eb21dc (only reference)",
        "changed_bytes": len(changed),
        "changes_only_inner_y_and_h": bool(changed) and set(changed) <= allowed,
        "writes": writes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: v for k, v in manifest.items() if k != "writes"}, indent=2))
    for w in writes:
        print(w["field"], w["stock_inner"], "->", w["new_inner"])


if __name__ == "__main__":
    main()
