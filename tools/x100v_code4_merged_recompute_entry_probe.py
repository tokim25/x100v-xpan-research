"""Bound stock/code-4 valid-state recomputation at its first count call.

The original ARM runs through setup and descriptor construction only. The
first count estimator, remaining 56 rows, export, and camera are not run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_estimate_leaf_emulator import load_volume
from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_refresh_caller_emulator import FIRST_COUNT, execute
from tools.x100v_update_package import read_primary


def verify(stock_update: Path, candidate_update: Path) -> dict:
    candidate_bytes = candidate_update.read_bytes()
    if hashlib.sha256(candidate_bytes).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized merged-code4 offline candidate")
    stock, secondary = load_images(stock_update)
    volume = load_volume(stock_update)
    candidate = read_primary(candidate_bytes)[1]
    cases = []
    for level in range(3):
        for second in range(2):
            pair = []
            for aspect, patched in ((2, False), (4, True)):
                result = execute(stock, secondary, volume, candidate,
                                 level=level, second=second, aspect=aspect,
                                 bypass=0, scenario="valid", patched=patched,
                                 through_recompute_probe=True,
                                 candidate_profile="merged")
                count = result["first_count"]
                if (result["stop_pc"] != hex(FIRST_COUNT)
                        or not result["recompute_setup_executed"]
                        or result["recomputation_executed"]
                        or result["publisher_executed"]
                        or result["export_executed"]
                        or result["cache_write_bytes"] != 0
                        or result["dimension_stub_executed"] != (aspect == 4)
                        or count is None):
                    raise AssertionError("first count-entry boundary differs")
                pair.append(count["descriptor_hex"])
                cases.append(dict(level=level, second=second, aspect=aspect,
                                  patched=patched, stop_pc=result["stop_pc"],
                                  row_index=count["row_index"],
                                  registers=count["registers"],
                                  stack_arg=count["stack_arg"],
                                  descriptor_hex=count["descriptor_hex"],
                                  dimension_stub_executed=result["dimension_stub_executed"],
                                  instructions=result["instructions"]))
            if pair[0] != pair[1]:
                raise AssertionError("stock and merged first-row descriptors differ")
    return dict(scope=__doc__, stock_primary_sha256=hashlib.sha256(stock).hexdigest(),
                candidate_update_sha256=CANDIDATE_DAT_SHA256, cases=cases,
                synthetic_runtime_halfword_0x0191e9e8=100,
                first_count_executed=False, full_recomputation_executed=False,
                export_executed=False, camera_executed=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.stock, args.candidate)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} stock/code4 recompute-entry cases passed")


if __name__ == "__main__":
    main()
