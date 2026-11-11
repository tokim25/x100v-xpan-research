"""Compare stock and merged original-ARM cache stores through row 1 only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_encoder_dimension_emulator import load_images as load_primary_kernel
from tools.x100v_estimate_leaf_emulator import load_defaults, load_volume
from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_refresh_caller_emulator import FIRST_STORE_DONE, execute

CAPACITIES = (100_000_000, 500_000_000)


def verify(stock_update: Path, candidate_update: Path) -> dict:
    candidate_bytes = candidate_update.read_bytes()
    if hashlib.sha256(candidate_bytes).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized offline candidate")
    stock, secondary = load_images(stock_update)
    primary_again, kernel = load_primary_kernel(stock_update)
    if stock != primary_again:
        raise AssertionError("primary decoders disagree")
    volume, defaults = load_volume(stock_update), load_defaults(stock_update)
    from tools.x100v_update_package import read_primary
    candidate = read_primary(candidate_bytes)[1]
    cases = []
    for capacity in CAPACITIES:
        for level in range(3):
            for second in range(2):
                pair = []
                for aspect, patched in ((2, False), (4, True)):
                    result = execute(stock, secondary, volume, candidate,
                                     level=level, second=second, aspect=aspect,
                                     bypass=0, scenario="valid", patched=patched,
                                     through_recompute_probe=True,
                                     through_first_count_result=True,
                                     through_first_count_store=True,
                                     through_second_count_store=True,
                                     settings_defaults=defaults, kernel=kernel,
                                     volume_free_bytes=capacity,
                                     candidate_profile="merged")
                    entries, returns = result["count_entries"], result["count_returns"]
                    observations = result["observations"]
                    if (result["stop_pc"] != hex(FIRST_STORE_DONE)
                            or len(entries) != 2 or len(returns) != 2
                            or [entry["row_index"] for entry in entries] != [0, 1]
                            or result["cache_write_bytes"] != 8
                            or result["first_count_stored"] != min(returns[0])
                            or result["second_count_stored"] != min(returns[1])
                            or [item[0] for item in observations.get("free_byte_oracle_calls", [])] != [6, 5, 6, 5]
                            or [item[2] for item in observations.get("first_count_copy_calls", [])] != [80]*6
                            or result["publisher_executed"] or result["export_executed"]):
                        raise AssertionError("second-row boundary differs")
                    pair.append((entries[0]["descriptor_hex"], entries[1]["descriptor_hex"],
                                 result["first_count_stored"], result["second_count_stored"]))
                    cases.append(dict(capacity_oracle_bytes=capacity, level=level,
                                      second=second, aspect=aspect, patched=patched,
                                      row0=pair[-1][2], row1=pair[-1][3],
                                      table_copy_calls=6, free_byte_requests=[6, 5, 6, 5],
                                      instructions=result["instructions"],
                                      stop_pc=result["stop_pc"]))
                if pair[0] != pair[1]:
                    raise AssertionError("stock/merged row-0/1 descriptor or count differs")
    return dict(scope=__doc__, stock_primary_sha256=hashlib.sha256(stock).hexdigest(),
                candidate_update_sha256=CANDIDATE_DAT_SHA256, cases=cases,
                first_two_rows_stored=True, other_55_rows_executed=False,
                cache_export_executed=False, camera_executed=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.stock, args.candidate)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"{len(result['cases'])} row-0/1 ARM cases passed")


if __name__ == "__main__":
    main()
