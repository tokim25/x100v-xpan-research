"""Offline writes that give two finder-panel 16:9 windows a centred 65:24 shape (X100V 3.01).

The primary partition holds a live-view layout table at 0x014b83b8, read by
0x011ab780 as [variant < 2][layout < 8][aspect slot < 7], 56-byte records
of 14 int32: panel (w, h), outer window (w, h, x, y), margins (top, bottom,
left, right) and image window (w, h, x, y). Helper 0x011e6bb0 maps the
stored aspect pair 9:16 to slot 2.

Variant 1, layouts 6 and 7 sit on the 1280x960 finder panel and are the
only finder-panel records whose window changes with the aspect (3:2, 16:9
and 1:1). Card 5l tests whether either one draws what the OVF shows. Each
write keeps the width and x, sets the height to floor(w * 24 / 65), and
keeps the 16:9 window's vertical centre, moving the removed rows into the
top and bottom margins.

Static data only: which display or mode reads these records is not
established, and no OVF behaviour is claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions

TABLE = 0x014B83B8
RECORD = 0x38
VARIANT_STRIDE = 0xC40
LAYOUT_STRIDE = 0x188
SLOT_16X9 = 2
TARGETS = ((1, 6), (1, 7))  # (variant, layout)
# Variant 0, layouts 0 to 3: the 900x600 LCD window and three windows on the
# 1280x960 finder panel. Card 5m tests whether they frame the LCD and EVF.
LIVE_VIEW_TARGETS = ((0, 0), (0, 1), (0, 2), (0, 3))
# Variant 1, layouts 4 and 5: two windows on a 720x480 plane, 472x314 at
# (40, 83) and 184x120 at (520, 180) for 3:2. They are layouts 6 and 7 at
# 720/1280 scale, so card 6b tests whether they draw the OVF bright frame
# and the rangefinder window. Their stock 16:9 heights are 264 and 102.
OVF_FRAME_TARGETS = ((1, 4), (1, 5))
TARGET_SETS = {"finder": ("finder-window", TARGETS), "live-view": ("live-view-window", LIVE_VIEW_TARGETS),
               "ovf-frame": ("ovf-frame-window", OVF_FRAME_TARGETS)}


def record_address(variant: int, layout: int, slot: int) -> int:
    return TABLE + variant * VARIANT_STRIDE + layout * LAYOUT_STRIDE + slot * RECORD


def is_consistent(rec: tuple[int, ...]) -> bool:
    """The image window is the outer window minus the margins."""
    _, _, ow, oh, ox, oy, top, bottom, left, right, w, h, x, y = rec
    return (w == ow - left - right and h == oh - top - bottom
            and x == ox + left and y == oy + top)


def is_16x9(rec: tuple[int, ...]) -> bool:
    w, h = rec[10], rec[11]
    return is_consistent(rec) and abs(h * 16 - w * 9) <= 32  # within two rows of 16:9


def record_6524(rec: tuple[int, ...]) -> tuple[int, ...]:
    """Same width and x; height w*24/65 (floor) around the old vertical centre."""
    pw, ph, ow, oh, ox, oy, top, bottom, left, right, w, h, x, y = rec
    nh = w * 24 // 65
    ntop = top + (h - nh) // 2
    nbottom = oh - ntop - nh
    return (pw, ph, ow, oh, ox, oy, ntop, nbottom, left, right, w, nh, x, oy + ntop)


def writes_for(primary: bytes, target_set: str = "finder") -> list[dict]:
    prefix, targets = TARGET_SETS[target_set]
    writes = []
    for variant, layout in targets:
        address = record_address(variant, layout, SLOT_16X9)
        at = address - LOADS[6]
        rec = struct.unpack_from("<14i", primary, at)
        if not is_16x9(rec):
            raise ValueError(f"variant {variant} layout {layout} slot 2 is not the stock 16:9 window")
        new = record_6524(rec)
        # Changed fields are the top/bottom margins and image h/y; write the span +0x18..+0x37.
        before = primary[at + 0x18:at + RECORD]
        after = struct.pack("<8i", *new[6:])
        writes.append({"field": f"{prefix}-v{variant}-l{layout}-16x9", "partition": 6,
                       "partition_offset": at + 0x18, "before_hex": before.hex(), "after_hex": after.hex(),
                       "address": f"0x{address + 0x18:08x}", "stock_record": list(rec), "new_record": list(new)})
    return writes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True, help="official X100V 3.01 FPUPDATE.DAT")
    parser.add_argument("--output", type=Path, required=True, help="manifest JSON to write")
    parser.add_argument("--targets", choices=sorted(TARGET_SETS), default="finder")
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    primary = stock_partitions(raw)[6]
    writes = writes_for(primary, args.targets)
    manifest = {
        "kind": f"{len(writes)} {args.targets} 16:9 layout windows reshaped to centred 65:24; static data writes, offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "table": f"0x{TABLE:08x}",
        "reader": "0x011ab780 (index [variant][layout][slot]); slot from 0x011e6bb0",
        "writes": writes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    for w in writes:
        print(w["field"], w["address"], w["stock_record"][10:], "->", w["new_record"][10:])


if __name__ == "__main__":
    main()
