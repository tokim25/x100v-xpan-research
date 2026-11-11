"""Offline write that gives the 16:9 setting the stock 65:24 focus grid (X100V 3.01).

Helper 0x011e62dc copies an eight-row table from 0x012911ac and returns the
focus grid (rows, columns) for a stored aspect pair. Stock rows include
(9, 16) -> 7 by 13 and (24, 65) -> 5 by 13. Routine 0x011e63a4 centres the
grid in the live-view window with

    y0 = y_offset + ((window_height - cell * rows) >> 1)

using an unsigned shift. Card 5m shortened the 16:9 window to 65:24, so
seven rows no longer fit, the difference went negative and the shift turned
it into a huge offset. This write changes the 9:16 row count from 7 to 5,
the count the firmware itself uses for 24:65.

Static reading plus a numeric model of that one expression. The cell size
comes from camera parameter 0x5d41, which is not in the update file, so the
model takes it as an input. No camera behaviour is claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions

TABLE = 0x012911AC
ROW_BYTES = 16
ROW_16X9 = 2
STOCK_ROW = (9, 16, 7, 13)
NEW_ROWS = 5
ROW_24X65 = (24, 65, 5, 13)


def grid_y_offset(window_height: int, cell: int, rows: int, y_offset: int = 0) -> int:
    """The firmware's vertical grid origin: 32-bit wrap, then a logical shift."""
    return (y_offset + (((window_height - cell * rows) & 0xFFFFFFFF) >> 1)) & 0xFFFFFFFF


def fits(window_height: int, cell: int, rows: int) -> bool:
    return cell * rows <= window_height


def writes_for(primary: bytes) -> list[dict]:
    at = TABLE + ROW_16X9 * ROW_BYTES - LOADS[6]
    if struct.unpack_from("<4I", primary, at) != STOCK_ROW:
        raise ValueError("focus-grid row 2 is not the stock 9:16 row")
    if struct.unpack_from("<4I", primary, TABLE + 5 * ROW_BYTES - LOADS[6]) != ROW_24X65:
        raise ValueError("focus-grid row 5 is not the stock 24:65 row")
    before = primary[at + 8:at + 12]
    return [{"field": "focus-grid-16x9-rows", "partition": 6, "partition_offset": at + 8,
             "before_hex": before.hex(), "after_hex": struct.pack("<I", NEW_ROWS).hex(),
             "address": f"0x{TABLE + ROW_16X9 * ROW_BYTES + 8:08x}"}]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True, help="official X100V 3.01 FPUPDATE.DAT")
    parser.add_argument("--output", type=Path, required=True, help="manifest JSON to write")
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    writes = writes_for(stock_partitions(raw)[6])
    manifest = {
        "kind": "focus-grid row count for the 9:16 pair changed from 7 to 5; static data write, offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "table": f"0x{TABLE:08x}",
        "reader": "0x011e62dc, called from 0x011e63a4, 0x020766a4, 0x020bdcb0, 0x020ccad4 and 0x0216ac34",
        "writes": writes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    for w in writes:
        print(w["field"], w["address"], w["before_hex"], "->", w["after_hex"])


if __name__ == "__main__":
    main()
