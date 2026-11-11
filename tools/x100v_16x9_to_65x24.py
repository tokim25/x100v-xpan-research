"""Emit the 16:9-to-65:24 still-dimension writes for X100V 3.01.

Every stored L/M/S 16:9 still-image height becomes the 65:24 height at the
same width: the nearest multiple of 8 to width x 24/65, the rule the GFX100
5.18 65:24 rows follow. The per-aspect size list also gets the 65:24 ratio
fields GFX uses. Movie rows, the 4992-wide crop size and sensor readout
windows keep 16:9. With --ratio-code it also rewrites the 16:9 ratio
arithmetic in place: the record-buffer crop helper, the ratio-pair writer and
the two geometry branches. Movies share those sites, so a card built with
them changes 16:9 movie geometry too. Each old value is checked against the
decoded stock partitions before any write is emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import decode_partition
from tools.x100v_update_package import (PRIMARY_DECODED_SHA256, PRIMARY_LOAD, STOCK_SHA256,
                                        read_primary)

SECONDARY_LOAD = 0x01BA0000
SECONDARY_HEADER = 0x560060
SECONDARY_DECODED_SHA256 = "b116e52462f245b7bfa341ebf75a644baa32590d3957518dbea436456169cb35"
LOADS = {6: PRIMARY_LOAD, 7: SECONDARY_LOAD}

WIDTH = {"L": 6240, "M": 4416, "S": 3120, "small": 768}
STOCK_16_9 = {"L": 3512, "M": 2488, "S": 1760, "small": 432}
# Fraction and integer part of width/height, as stored in the per-aspect list.
RATIO_16_9 = (50972, 1)
RATIO_65_24 = (46421, 2)


# 16:9 ratio code, rewritten in place: (field, partition, address, stock words, new words).
# Geometry branches compute width * 24 / 65 as umull by 0xFC0FC0FD, then >> 38,
# exact for the unsigned range used; the branch back stays unchanged.
CODE_SITES = [
    ("crop-helper-code2-ratio", 6, 0x0115EF2C,
     [0xE3A02009, 0xE3A0E010],  # mov r2,#9; mov lr,#16
     [0xE3A02018, 0xE3A0E041]),  # mov r2,#24; mov lr,#65
    ("ratio-pair-code2-first", 7, 0x01F69464, [0xE3A03009], [0xE3A03018]),
    ("ratio-pair-code2-second", 7, 0x01F6946C, [0xE3A03010], [0xE3A03041]),
    ("geometry-code2-r6", 7, 0x01ED6DCC,
     [0xE3A06009, 0xE0060596, 0xE286300F, 0xE3560000, 0xB1A06003, 0xE1A06246],
     [0xE3A06018, 0xE0030596, 0xE30C60FD, 0xE34F6C0F, 0xE0862396, 0xE1A06326]),
    ("geometry-code2-r2", 7, 0x01ED6E00,
     [0xE3A02009, 0xE0020092, 0xE282300F, 0xE3520000, 0xB1A02003, 0xE1A02242],
     [0xE3A02018, 0xE0030092, 0xE30C20FD, 0xE34F2C0F, 0xE0821392, 0xE1A02322]),
]


def height_65_24(width: int) -> int:
    return round(width * 24 / 65 / 8) * 8


def ratio_fields(num: int, den: int) -> tuple[int, int]:
    whole, rest = divmod(num, den)
    return rest * 65536 // den, whole


def sites() -> list[tuple[str, int, int, str, int]]:
    """(field, partition, address, struct format, stock value) for each height."""
    out = []
    size_rows = {"L": 0x013E29E8, "M": 0x013E29AC, "S": 0x013E2970}  # IDs 2, 9, 16
    for s, row in size_rows.items():
        out.append((f"size-table-{s}-height", 6, row + 0xC, "<I", STOCK_16_9[s]))
    for i, s in enumerate("LMS"):  # crop height table, 5 columns, code-2 column
        out.append((f"crop-height-{s}", 6, 0x014A75C0 + 20 * i + 8, "<I", STOCK_16_9[s]))
    for s, rows in {"L": (5, 6), "M": (13, 14), "S": (21, 22)}.items():
        for r in rows:  # 57-row capacity table, 8-byte rows, height at +6
            out.append((f"capacity-row-{r}-height", 6, 0x014A6230 + 8 * r + 6, "<H", STOCK_16_9[s]))
    for r in range(24, 36):  # byte-count rows, 16 bytes, height at +2
        s = "LMS"[(r - 24) // 2 % 3]
        out.append((f"byte-count-row-{r}-height", 6, 0x01519744 + 16 * r + 2, "<H", STOCK_16_9[s]))
    for s, base in {"L": 0x022E2B40, "M": 0x022E2C30, "S": 0x022E2D20}.items():
        for k in range(4):  # per-size records, 20 bytes, height word at +4
            out.append((f"size-record-{s}-{k}-height", 7, base + 20 * k + 4, "<I", STOCK_16_9[s]))
    return out


def list_sites() -> list[tuple[str, int, bytes, bytes]]:
    """Per-aspect size list, 16:9 group: (height, fraction, integer) halfwords."""
    out = []
    for j, s in enumerate(("L", "M", "S", "small")):
        address = 0x022E9FB4 + 8 * j + 2
        old = struct.pack("<3H", STOCK_16_9[s], *RATIO_16_9)
        new = struct.pack("<3H", height_65_24(WIDTH[s]), *RATIO_65_24)
        out.append((f"aspect-list-16x9-{s}", address, old, new))
    return out


def writes_for(partitions: dict[int, bytes], ratio_code: bool = False) -> list[dict]:
    def check(field: str, part: int, address: int, old: bytes) -> int:
        offset = address - LOADS[part]
        if partitions[part][offset:offset + len(old)] != old:
            raise ValueError(f"{field}: stock bytes at {address:#x} differ")
        return offset

    writes = []
    for field, part, address, fmt, stock in sites():
        old = struct.pack(fmt, stock)
        width = next(WIDTH[s] for s in "LMS" if STOCK_16_9[s] == stock)
        new = struct.pack(fmt, height_65_24(width))
        writes.append({"field": field, "partition": part, "address": address,
                       "partition_offset": check(field, part, address, old),
                       "before_hex": old.hex(), "after_hex": new.hex()})
    for field, address, old, new in list_sites():
        writes.append({"field": field, "partition": 7, "address": address,
                       "partition_offset": check(field, 7, address, old),
                       "before_hex": old.hex(), "after_hex": new.hex()})
    for field, part, address, stock, new in CODE_SITES if ratio_code else ():
        old = struct.pack(f"<{len(stock)}I", *stock)
        writes.append({"field": field, "partition": part, "address": address,
                       "partition_offset": check(field, part, address, old),
                       "before_hex": old.hex(),
                       "after_hex": struct.pack(f"<{len(new)}I", *new).hex()})
    return writes


def stock_partitions(raw: bytes) -> dict[int, bytes]:
    if hashlib.sha256(raw).hexdigest() != STOCK_SHA256:
        raise ValueError("not the pinned X100V 3.01 update")
    _, primary = read_primary(raw)
    secondary = decode_partition(bytes(b ^ 0xFF for b in raw[532:]), SECONDARY_HEADER)
    for name, data, digest in (("primary", primary, PRIMARY_DECODED_SHA256),
                               ("secondary", secondary, SECONDARY_DECODED_SHA256)):
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"decoded {name} partition hash differs")
    return {6: primary, 7: secondary}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ratio-code", action="store_true",
                        help="also rewrite the 16:9 ratio arithmetic (shared with movies)")
    args = parser.parse_args()
    writes = writes_for(stock_partitions(args.stock.read_bytes()), args.ratio_code)
    manifest = {
        "kind": ("16:9 stored as 65:24: dimension data and ratio code" if args.ratio_code
                 else "16:9 still sizes stored as 65:24 (dimension data only)") + "; offline only",
        "source_update_sha256": STOCK_SHA256,
        "source_primary_sha256": PRIMARY_DECODED_SHA256,
        "source_secondary_sha256": SECONDARY_DECODED_SHA256,
        "height_rule": "nearest multiple of 8 to width x 24/65 (reproduces GFX 5.18 4304, 3048, 1480, 376)",
        "untouched": "movie rows (3840/1920/1280 wide), the 4992-wide crop size, sensor readout windows, display list and frame graphics"
                     + ("" if args.ratio_code else ", 16:9 ratio constants in code"),
        "movie_effect": ("16:9 movies share the rewritten ratio code; do not record movies from a card built with it"
                         if args.ratio_code else "none"),
        "write_count": len(writes),
        "writes": writes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n")
    print(len(writes), "writes")


if __name__ == "__main__":
    main()
