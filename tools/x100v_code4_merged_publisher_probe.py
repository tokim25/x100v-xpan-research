"""Compare stock and merged-code4 refresh boundaries through local status write.

This is synthetic original-ARM execution with a 100-byte copy oracle, not a
camera run or a proof that a live cache is safe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_estimate_leaf_emulator import load_volume
from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_refresh_caller_emulator import RECOMPUTE, PUBLISH_DONE, execute
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
            for scenario in ("clear", "valid"):
                for aspect, patched in ((2, False), (4, True)):
                    result = execute(stock, secondary, volume, candidate,
                                     level=level, second=second, aspect=aspect,
                                     bypass=0, scenario=scenario, patched=patched,
                                     through_threshold=True, through_publisher=True,
                                     candidate_profile="merged")
                    expected = PUBLISH_DONE if scenario == "clear" else RECOMPUTE
                    if result["stop_pc"] != hex(expected):
                        raise AssertionError("unexpected stock/code4 publisher boundary")
                    if scenario == "clear" and (result["published_status"] != 2 or
                            result["publisher_arguments"] != [0, 0, 0]):
                        raise AssertionError("clear-state publisher output differs")
                    if scenario == "valid" and result["publisher_executed"]:
                        raise AssertionError("valid state should stop before recomputation")
                    cases.append(dict(level=level, second=second,
                                      aspect=aspect, scenario=scenario,
                                      patched=patched, stop_pc=result["stop_pc"],
                                      selected_index=result["selected_index"],
                                      published_status=result["published_status"],
                                      copy_calls=len(result["observations"].get("copy_calls", [])),
                                      instructions=result["instructions"]))
    return dict(scope=__doc__, stock_primary_sha256=hashlib.sha256(stock).hexdigest(),
                candidate_update_sha256=CANDIDATE_DAT_SHA256,
                cases=cases, local_copy_oracle=True, callback_executed=False,
                recomputation_executed=False, camera_executed=False,
                firmware_modified=False)


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
    print(f"{len(report['cases'])} original-ARM stock/code4 publisher-boundary cases passed")


if __name__ == "__main__":
    main()
