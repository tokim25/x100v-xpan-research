"""Offline probe: scale the X100V 3.01 OVF bright frame for aspect code 2 to 65:24.

Secondary routine 0x01e9dfc8 multiplies the calibrated frame height by the
float at 0x01e9e660 when context +0x70 is 2. This probe multiplies that
float by 128/195. See results/x100v-ovf-bright-frame-scale-20261112.md.

Usage: python -m tools.x100v_ovf_frame_scale_6524 FPUPDATE.DAT manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions

LITERAL = 0x01E9E660
STOCK_LITERAL = bytes.fromhex("8773583f")
# Aspect test, then the four loads of the literal.
PINNED = {0x01E9E0E4: "7030d3e5", 0x01E9E0E8: "020053e3", 0x01E9E2EC: "db7a9fed",
          0x01E9E39C: "af7a9fed", 0x01E9E40C: "936adfed", 0x01E9E584: "359adfed"}


def scale_6524(stock: bytes) -> bytes:
    (value,) = struct.unpack("<f", stock)
    return struct.pack("<f", value * 128 / 195)


def writes_for(secondary: bytes) -> list[dict]:
    for address, word in PINNED.items():
        at = address - LOADS[7]
        if secondary[at:at + 4].hex() != word:
            raise ValueError(f"{address:#x} is not the stock instruction")
    at = LITERAL - LOADS[7]
    if secondary[at:at + 4] != STOCK_LITERAL:
        raise ValueError("literal is not the stock 16:9 height factor")
    new = scale_6524(STOCK_LITERAL)
    return [{"field": "ovf-bright-frame-height-factor-code2", "partition": 7, "partition_offset": at,
             "address": f"0x{LITERAL:08x}", "before_hex": STOCK_LITERAL.hex(), "after_hex": new.hex(),
             "stock_factor": struct.unpack("<f", STOCK_LITERAL)[0], "new_factor": struct.unpack("<f", new)[0]}]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("stock", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    writes = writes_for(stock_partitions(raw)[7])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "kind": "OVF bright-frame height factor for aspect code 2 at 65:24; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "reader": "0x01e9dfc8", "writes": writes}, indent=2) + "\n")
    print(writes[0]["address"], writes[0]["stock_factor"], "->", writes[0]["new_factor"])


if __name__ == "__main__":
    main()
