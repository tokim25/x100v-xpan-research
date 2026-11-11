"""Exercise the decoded offline code-4 package's preview lookup in synthetic RAM.

This verifies original keys, new code-4 keys, and descriptor dimensions.
It does not execute cache refresh, full preview processing, capture, or UI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, read_preview_key_table
from tools.x100v_preview_alias_candidate import execute
from tools.x100v_update_package import STOCK_SHA256, read_primary

CANDIDATE_DAT_SHA256 = "20fd97a054f66502a0f58fa42c0adcc24e14377f6d02df75dcfd197eed4b9cf5"
CANDIDATE_PRIMARY_SHA256 = "0cb9fb15e124205b6d7f745568f2f6373f3e3a4abb03a9b05c6e6cbf025b7e53"
NEW = (
    ((0, 1, 4), 5, (6240, 2304)),
    ((0, 0, 4), 6, (6240, 2304)),
    ((1, 1, 4), 13, (4416, 1632)),
    ((1, 0, 4), 14, (4416, 1632)),
    ((2, 1, 4), 21, (3120, 1152)),
    ((2, 0, 4), 22, (3120, 1152)),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if sha(stock_dat) != STOCK_SHA256 or sha(candidate_dat) != CANDIDATE_DAT_SHA256:
        raise ValueError("stock or offline candidate package identity changed")
    primary = read_primary(stock_dat)[1]
    candidate = read_primary(candidate_dat)[1]
    source = SOURCES["x100v_3_01"]
    if sha(primary) != source["primary_sha256"] or sha(candidate) != CANDIDATE_PRIMARY_SHA256:
        raise ValueError("decoded primary identity changed")
    rows = read_preview_key_table(primary, source["primary_load"], source["preview_key_table"], 57)
    candidate_rows = read_preview_key_table(candidate, source["primary_load"], source["preview_key_table"], 57)
    if rows != candidate_rows:
        raise AssertionError("merged package changed an original preview-key row")

    old_cases = 0
    for row in rows:
        key = tuple(row["key"])
        for bypass in (0, 1, 2):
            index = 0 if bypass == 1 else row["index"]
            dims = [0, 0] if bypass == 1 else [row["width"], row["height"]]
            lookup = execute(candidate, key, bypass)
            descriptor = execute(candidate, key, bypass, descriptor=True)
            if lookup["row_index"] != index or descriptor["dimensions"] != dims:
                raise AssertionError(f"old preview key changed: {key}/{bypass}")
            old_cases += 1

    new_cases = []
    for key, index, dims in NEW:
        for bypass in (0, 1, 2):
            lookup = execute(candidate, key, bypass)
            descriptor = execute(candidate, key, bypass, descriptor=True)
            wanted_index = 0 if bypass == 1 else index
            wanted_dims = [0, 0] if bypass == 1 else list(dims)
            if lookup["row_index"] != wanted_index or descriptor["dimensions"] != wanted_dims:
                raise AssertionError(f"new preview key differs: {key}/{bypass}")
            new_cases.append({"key": list(key), "bypass": bypass,
                              "index": lookup["row_index"], "dimensions": descriptor["dimensions"]})

    misses = ((3, 1, 4), (7, 0, 4), (255, 0, 4), (0, 2, 4), (0, 255, 4), (0, 1, 5))
    for key in misses:
        if execute(candidate, key)["row_index"] != 57:
            raise AssertionError(f"unsupported key unexpectedly resolved: {key}")
    return {
        "scope": "actual decoded offline package; original ARM lookup and descriptor prefix; synthetic RAM only",
        "source_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "old_key_bypass_cases": old_cases,
        "new_code4_cases": new_cases,
        "unchanged_miss_cases": [list(key) for key in misses],
        "cache_refresh_executed": False,
        "full_preview_or_capture_executed": False,
        "camera_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.stock.read_bytes(), args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"{report['old_key_bypass_cases']} old-key cases, "
          f"{len(report['new_code4_cases'])} new-key cases, "
          f"{len(report['unchanged_miss_cases'])} miss controls passed")


if __name__ == "__main__":
    main()
