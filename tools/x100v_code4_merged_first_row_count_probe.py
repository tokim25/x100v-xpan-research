"""Compare stock/code-4 row-0 cache counts under declared free-space oracles.

Original ARM computes and stores only the first of 57 rows. The three exact
80-byte stock-table copies and request-5/6 free-byte responses are host oracles;
all other observed code is from pinned images. No camera or full cache export.
"""
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
from tools.x100v_update_package import read_primary

CAPACITY_VECTORS = ((1_000_000, 0), (100_000_000, 1), (500_000_000, 8))


def verify(stock_update: Path, candidate_update: Path) -> dict:
    candidate_bytes = candidate_update.read_bytes()
    if hashlib.sha256(candidate_bytes).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized merged-code4 offline candidate")
    stock, secondary = load_images(stock_update)
    primary_again, kernel = load_primary_kernel(stock_update)
    if stock != primary_again:
        raise AssertionError("independent primary decoders disagree")
    volume, defaults = load_volume(stock_update), load_defaults(stock_update)
    candidate = read_primary(candidate_bytes)[1]
    table_offset = 0x1290644 - 0xF21000
    if stock[table_offset:table_offset + 3*80] != candidate[table_offset:table_offset + 3*80]:
        raise AssertionError("stock/code4 count-helper tables differ")
    cases = []
    for capacity, expected_count in CAPACITY_VECTORS:
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
                                     settings_defaults=defaults, kernel=kernel,
                                     volume_free_bytes=capacity,
                                     candidate_profile="merged")
                    observations = result["observations"]
                    if (result["stop_pc"] != hex(FIRST_STORE_DONE)
                            or result["first_count_result"] != expected_count
                            or result["first_count_stored"] != expected_count
                            or result["cache_write_bytes"] != 4
                            or result["dimension_stub_executed"] != (aspect == 4)
                            or len(observations.get("coefficient_writes", [])) != 132
                            or observations.get("coefficient_flag_write") is not True
                            or [item[0] for item in observations.get("free_byte_oracle_calls", [])] != [6, 5]
                            or [item[2] for item in observations.get("first_count_copy_calls", [])] != [80, 80, 80]
                            or result["publisher_executed"] or result["export_executed"]
                            or not result["recomputation_executed"]):
                        raise AssertionError("row-0 count/store boundary differs")
                    pair.append(result["first_count"]["descriptor_hex"])
                    cases.append(dict(capacity_oracle_bytes=capacity, level=level,
                                      second=second, aspect=aspect, patched=patched,
                                      stop_pc=result["stop_pc"],
                                      first_count=result["first_count_result"],
                                      cache_row0=result["first_count_stored"],
                                      dimension_stub_executed=result["dimension_stub_executed"],
                                      coefficient_writes=132,
                                      table_copy_calls=3,
                                      free_byte_requests=[6, 5],
                                      instructions=result["instructions"]))
                if pair[0] != pair[1]:
                    raise AssertionError("stock/code4 row-0 descriptors differ")
    return dict(scope=__doc__, stock_primary_sha256=hashlib.sha256(stock).hexdigest(),
                candidate_update_sha256=CANDIDATE_DAT_SHA256,
                kernel_sha256=hashlib.sha256(kernel).hexdigest(),
                volume_sha256=hashlib.sha256(volume).hexdigest(),
                defaults_sha256=hashlib.sha256(defaults).hexdigest(),
                cases=cases, row0_stored=True, other_56_rows_executed=False,
                cache_export_executed=False, camera_executed=False,
                active_camera_settings_observed=False)


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
    print(f"{len(report['cases'])} original-ARM row-0 count/store cases passed")


if __name__ == "__main__":
    main()
