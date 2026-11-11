"""Run the merged image's refresh-row key copy and dimension prefix in ARM.

This checks the geometry supplied to a count estimator, not the estimator,
published status, runtime cache freshness, or camera safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, read_preview_key_table
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256, CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_preview_alias_candidate import execute
from tools.x100v_update_package import read_primary

BASE = 0x00F21000
ROW_COPY = 0x0115D870
STOP = 0x34000000
REUSED = ((0, 1, 5, 3512), (0, 0, 6, 3512),
          (1, 1, 13, 2488), (1, 0, 14, 2488),
          (2, 1, 21, 1760), (2, 0, 22, 1760))
CODE4_HEIGHT = (2304, 1632, 1152)


def copied_key(primary: bytes, index: int) -> bytes:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_WRITE, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP,
    )

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x0115D000, 0x014A6000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, primary[page - BASE:page - BASE + 0x1000])
    uc.mem_map(0x30000000, 0x1000)
    uc.mem_map(0x33000000, 0x1000)
    uc.mem_map(STOP, 0x1000)
    record = bytearray(36)
    record[6] = 4  # active code-4 aspect before the row-copy call
    uc.mem_write(0x30000000, bytes(record))

    def check_write(machine, access, address, size, value, _):
        if not (0x30000000 <= address and address + size <= 0x30000024 or
                0x33000000 <= address and address + size <= 0x33001000):
            raise AssertionError(f"unexpected row-copy write at {address:#x}")

    uc.hook_add(UC_HOOK_MEM_WRITE, check_write)
    for reg, value in ((UC_ARM_REG_R0, index), (UC_ARM_REG_R1, 0),
                       (UC_ARM_REG_R2, 0x30000000),
                       (UC_ARM_REG_SP, 0x33000800), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    uc.emu_start(ROW_COPY, STOP, count=40)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise AssertionError("row copy did not return")
    return bytes(uc.mem_read(0x30000000, 36))


def verify(candidate_dat: bytes) -> dict:
    if hashlib.sha256(candidate_dat).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized offline merged package")
    primary = read_primary(candidate_dat)[1]
    if hashlib.sha256(primary).hexdigest() != CANDIDATE_PRIMARY_SHA256:
        raise ValueError("decoded primary identity changed")
    source = SOURCES["x100v_3_01"]
    rows = read_preview_key_table(primary, source["primary_load"],
                                  source["preview_key_table"], 57)
    results = []
    for level, second, index, old_height in REUSED:
        copied = copied_key(primary, index)
        row = rows[index]
        expected_key = (level, second, 2)
        actual_key = (copied[5], copied[4], copied[6])
        if tuple(row["key"]) != expected_key or actual_key != expected_key:
            raise AssertionError(f"refresh row {index} did not force code 2")
        old = execute(primary, actual_key, descriptor=True)
        direct = execute(primary, (level, second, 4), descriptor=True)
        if old["dimensions"] != [row["width"], old_height]:
            raise AssertionError(f"refresh row {index} dimension differs")
        if direct["dimensions"] != [row["width"], CODE4_HEIGHT[level]]:
            raise AssertionError(f"direct code-4 dimension differs for {index}")
        results.append({"index": index, "initial_aspect": 4,
                        "refresh_copied_key": list(actual_key),
                        "refresh_dimension_input": old["dimensions"],
                        "direct_code4_key": [level, second, 4],
                        "direct_code4_dimensions": direct["dimensions"],
                        "row_copy_executed": True,
                        "dimension_prefix_executed": True})
    return {"scope": "actual decoded merged primary; two original-ARM routines, synthetic RAM",
            "candidate_update_sha256": CANDIDATE_DAT_SHA256,
            "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
            "cases": results,
            "count_estimator_executed": False,
            "cache_refresh_caller_executed": False,
            "status_publisher_executed": False,
            "camera_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(f"{len(result['cases'])} refresh-row/code-4 geometry contrasts passed")


if __name__ == "__main__":
    main()
