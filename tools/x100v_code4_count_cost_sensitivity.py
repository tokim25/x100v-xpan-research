"""Bound the preview size-cost arithmetic against controlled coefficients.

Executes only original ARM arithmetic from 0x01168d98 through 0x01168ddc.
The shared 64-bit division helper is supplied by an explicit integer oracle;
no complete count estimator, cache refresh, or camera is run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_count_cost_table_audit import GEOMETRIES, verify as audit_table
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256, CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_update_package import read_primary

BASE = 0x00F21000
ARM_START = 0x01168D98
ARM_STOP = 0x01168DE0
DIVISIONS = (0x01168DC8, 0x01168DD4)
STACK = 0x33000000
COEFFICIENTS = (0, 1, 16, 20, 21, 22, 24, 32, 64, 255)
SELECTORS = (0, 2)


def integer_reference(width: int, height: int, coefficient: int,
                      divisor: int, selector: int) -> int:
    """Independent integer translation of the bounded ARM arithmetic."""
    if not (0 <= width <= 65535 and 0 <= height <= 65535 and
            0 <= coefficient <= 255 and 1 <= divisor <= 255):
        raise ValueError("invalid arithmetic fixture")
    size = ((width * height * 10 * coefficient) // divisor) // 0x50
    return size + (0x3000 if selector <= 1 else 0)


def arm_arithmetic(primary: bytes, width: int, height: int,
                   coefficient: int, divisor: int, selector: int) -> dict:
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
        UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R11,
        UC_ARM_REG_SP,
    )

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    page = ARM_START & ~0xFFF
    uc.mem_map(page, 0x1000)
    uc.mem_write(page, primary[page - BASE:page - BASE + 0x1000])
    uc.mem_map(STACK, 0x1000)
    frame = STACK + 0x800
    uc.mem_write(frame - 0x28, bytes((coefficient, divisor)))
    for reg, value in (
        (UC_ARM_REG_R4, width), (UC_ARM_REG_R5, height),
        (UC_ARM_REG_R6, selector), (UC_ARM_REG_R11, frame),
        (UC_ARM_REG_SP, STACK + 0x700),
    ):
        uc.reg_write(reg, value)
    seen = []

    def divide_helper(machine, address, size, _):
        if address not in DIVISIONS:
            return
        numerator = ((machine.reg_read(UC_ARM_REG_R1) << 32) |
                     machine.reg_read(UC_ARM_REG_R0))
        denominator = ((machine.reg_read(UC_ARM_REG_R3) << 32) |
                       machine.reg_read(UC_ARM_REG_R2))
        if denominator == 0:
            raise AssertionError("zero divisor in original ARM")
        quotient, remainder = divmod(numerator, denominator)
        machine.reg_write(UC_ARM_REG_R0, quotient & 0xFFFFFFFF)
        machine.reg_write(UC_ARM_REG_R1, quotient >> 32)
        machine.reg_write(UC_ARM_REG_R2, remainder & 0xFFFFFFFF)
        machine.reg_write(UC_ARM_REG_R3, remainder >> 32)
        machine.reg_write(UC_ARM_REG_PC, address + 4)
        seen.append(address)

    uc.hook_add(UC_HOOK_CODE, divide_helper)
    uc.emu_start(ARM_START, ARM_STOP, count=100, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != ARM_STOP or seen != list(DIVISIONS):
        raise AssertionError(f"bounded ARM did not finish: PC={uc.reg_read(UC_ARM_REG_PC):#x}, divisions={seen}")
    return {"cost": uc.reg_read(UC_ARM_REG_R0), "division_sites": [f"0x{x:08x}" for x in seen]}


def verify(stock_primary: bytes, candidate_dat: bytes) -> dict:
    table_audit = audit_table(stock_primary, candidate_dat)
    candidate_primary = read_primary(candidate_dat)[1]
    if hashlib.sha256(candidate_primary).hexdigest() != CANDIDATE_PRIMARY_SHA256:
        raise ValueError("candidate identity changed")
    start = ARM_START - BASE
    stop = ARM_STOP - BASE
    if stock_primary[start:stop] != candidate_primary[start:stop]:
        raise AssertionError("cost arithmetic changed in merged image")
    arm_cases = []
    for width, old_height, new_height in GEOMETRIES:
        for height in (old_height, new_height):
            for coefficient in COEFFICIENTS:
                for selector in SELECTORS:
                    actual = arm_arithmetic(candidate_primary, width, height,
                                            coefficient, 10, selector)
                    expected = integer_reference(width, height, coefficient, 10, selector)
                    if actual["cost"] != expected:
                        raise AssertionError(f"ARM/reference mismatch: {width}x{height}, {coefficient}, {selector}")
                    arm_cases.append({"width": width, "height": height,
                                      "coefficient": coefficient, "selector": selector,
                                      "cost": actual["cost"]})
    thresholds = []
    for width, old_height, new_height in GEOMETRIES:
        fallback = integer_reference(width, new_height, 32, 10, 0)
        threshold = next(c for c in range(256)
                         if integer_reference(width, old_height, c, 10, 0) >= fallback)
        if threshold == 0 or integer_reference(width, old_height, threshold - 1, 10, 0) >= fallback:
            raise AssertionError("threshold is not minimal")
        thresholds.append({"width": width, "old_height": old_height,
                           "new_height": new_height, "new_fallback_coefficient": 32,
                           "new_fallback_cost": fallback,
                           "minimum_old_coefficient_for_cost_at_least_new": threshold,
                           "old_cost_below_threshold": integer_reference(width, old_height, threshold - 1, 10, 0),
                           "old_cost_at_threshold": integer_reference(width, old_height, threshold, 10, 0)})
    return {
        "scope": "stock/merged original ARM arithmetic slice with explicit 64-bit division oracle; synthetic inputs",
        "stock_primary_sha256": SOURCES["x100v_3_01"]["primary_sha256"],
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "table_rows_unchanged": table_audit["candidate_table_unchanged"],
        "arithmetic_bytes_unchanged": True,
        "arm_reference_cases": len(arm_cases),
        "arm_case_vectors": arm_cases,
        "thresholds": thresholds,
        "runtime_old_coefficients_known": False,
        "full_estimator_executed": False,
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
    print(f"{report['arm_reference_cases']} ARM/reference cases passed; thresholds recorded")


if __name__ == "__main__":
    main()
