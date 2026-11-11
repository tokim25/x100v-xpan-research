"""Audit the stock X100V count-cost size table against the merged package.

This reads firmware bytes only. It does not run the estimator or infer a live
record state, runtime coefficient, free-space value, or shutter outcome.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256, CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_update_package import read_primary

TABLE = 0x01519744
ROWS = 132
STRIDE = 16
GEOMETRIES = (
    (6240, 3512, 2304),
    (4416, 2488, 1632),
    (3120, 1760, 1152),
)


def rows_from(primary: bytes) -> list[dict]:
    offset = TABLE - SOURCES["x100v_3_01"]["primary_load"]
    data = primary[offset:offset + ROWS * STRIDE]
    if len(data) != ROWS * STRIDE:
        raise ValueError("count-cost table incomplete")
    rows = []
    for index in range(ROWS):
        raw = data[index * STRIDE:(index + 1) * STRIDE]
        width, height = struct.unpack_from("<HH", raw)
        rows.append({
            "index": index, "address": f"0x{TABLE + index * STRIDE:08x}",
            "width": width, "height": height,
            "mode": raw[4], "variant": struct.unpack_from("<b", raw, 5)[0],
            "selector": raw[6], "runtime_coefficient_byte": raw[7],
            "divisor_byte": raw[8], "parameter": struct.unpack_from("<I", raw, 12)[0],
        })
    return rows


def verify(stock_primary: bytes, candidate_dat: bytes) -> dict:
    expected = SOURCES["x100v_3_01"]["primary_sha256"]
    if hashlib.sha256(stock_primary).hexdigest() != expected:
        raise ValueError("unrecognized stock primary")
    if hashlib.sha256(candidate_dat).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized merged package")
    candidate_primary = read_primary(candidate_dat)[1]
    if hashlib.sha256(candidate_primary).hexdigest() != CANDIDATE_PRIMARY_SHA256:
        raise ValueError("unrecognized merged primary")
    stock_rows = rows_from(stock_primary)
    candidate_rows = rows_from(candidate_primary)
    if stock_rows != candidate_rows:
        raise AssertionError("count-cost table differs in merged image")
    comparisons = []
    for width, old_height, new_height in GEOMETRIES:
        old = [r for r in stock_rows if (r["width"], r["height"]) == (width, old_height)]
        new = [r for r in stock_rows if (r["width"], r["height"]) == (width, new_height)]
        if len(old) != 4 or new:
            raise AssertionError(f"unexpected size-cost rows for {width}")
        comparisons.append({
            "width": width, "old_height": old_height,
            "new_height": new_height,
            "old_matching_rows": old,
            "new_matching_rows": new,
        })
    return {
        "scope": "on-disk stock/merged primary count-cost table bytes only",
        "stock_primary_sha256": expected,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "table_address": f"0x{TABLE:08x}", "table_rows": ROWS,
        "table_stride": STRIDE, "candidate_table_unchanged": True,
        "comparisons": comparisons,
        "runtime_coefficients_known": False,
        "estimator_executed": False,
        "camera_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock-primary", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.stock_primary.read_bytes(), args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print("132 count-cost rows audited; 12 old-size matches, no 65:24-size matches")


if __name__ == "__main__":
    main()
