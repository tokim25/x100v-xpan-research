"""Execute the stock capacity-count tail with explicit synthetic estimates.

Starts after the estimator calls, not at a firmware function entry. Does not
model media, estimator properties, preview caches, capture, or boot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_encoder_dimension_emulator import load_images, verify_images

ENTRY, STOP = 0x011673D8, 0x01167414
STACK, FRAME = 0x20000000, 0x20000E00


def execute(primary: bytes, kernel: bytes, available: int, cost_a: int, cost_b: int, cap: int) -> dict:
    verify_images(primary, kernel)
    if not (0 <= available <= 0xFFFFFFFFFFFFFFFF
            and all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in (cost_a, cost_b, cap))):
        raise ValueError("fixture outside register domains")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R5, UC_ARM_REG_R6,
        UC_ARM_REG_R7, UC_ARM_REG_R11, UC_ARM_REG_SP, UC_ARM_REG_PC)

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x01167000, 4096)
    uc.mem_write(0x01167000, primary[0x01167000 - 0x00F21000:0x01168000 - 0x00F21000])
    uc.mem_map(0x0005A000, 4096)
    uc.mem_write(0x0005A000, kernel[0x1A000:0x1B000])
    uc.mem_map(STACK, 4096)
    uc.mem_write(FRAME + 0x24, struct.pack("<I", cap))
    visited = []
    ranges = ((ENTRY, STOP), (0x01167594, 0x011675F4), (0x0005AD28, 0x0005AF34))

    def instruction(machine, address, size, _):
        if not any(start <= address < end for start, end in ranges):
            raise RuntimeError(f"capacity tail escaped at {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if not STACK <= address <= STACK + 4096 - size:
            raise RuntimeError(f"capacity tail unexpected write: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    for reg, value in ((UC_ARM_REG_R0, cost_b), (UC_ARM_REG_R5, cost_a),
                       (UC_ARM_REG_R6, available & 0xFFFFFFFF), (UC_ARM_REG_R7, available >> 32),
                       (UC_ARM_REG_R11, FRAME), (UC_ARM_REG_SP, FRAME - 0x100)):
        uc.reg_write(reg, value)
    uc.emu_start(ENTRY, STOP, count=4000, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise RuntimeError("capacity tail did not reach epilogue")
    return {"count_u32": uc.reg_read(UC_ARM_REG_R0), "instructions": len(visited),
            "stock_division_executed": 0x0005AD28 in visited}


def verify(primary: bytes, kernel: bytes) -> dict:
    import unicorn
    # Independent fixed outputs; these costs are not measured camera estimates.
    vectors = [
        ("cost_a_zero", 1000, 0, 30, 100, 0),
        ("cost_b_zero", 1000, 20, 0, 100, 0),
        ("no_capacity", 0, 20, 30, 100, 0),
        ("below_first", 29, 20, 30, 100, 0),
        ("first_boundary", 30, 20, 30, 100, 1),
        ("below_second", 59, 20, 30, 100, 1),
        ("second_boundary", 60, 20, 30, 100, 2),
        ("below_third", 89, 20, 30, 100, 2),
        ("third_boundary", 90, 20, 30, 100, 3),
        ("next_increment", 110, 20, 30, 100, 4),
        ("tail_clamp", 1000, 20, 30, 10, 10),
        ("costs_20_30", 1000, 20, 30, 1000, 48),
        ("larger_costs_30_45", 1000, 30, 45, 1000, 31),
        ("smaller_costs_5_10", 1000, 5, 10, 1000, 197),
        ("64_bit_capacity", 0x100000000, 0x10000000, 0x10000000, 100, 16),
        ("early_two_not_tail_clamped", 60, 20, 30, 1, 2),
    ]
    cases = []
    for name, available, cost_a, cost_b, cap, expected in vectors:
        result = execute(primary, kernel, available, cost_a, cost_b, cap)
        if result["count_u32"] != expected:
            raise AssertionError(f"capacity fixture failed: {name}: {result}")
        cases.append({"name": name, "available": available, "cost_a": cost_a,
                      "cost_b": cost_b, "cap": cap, "expected_count": expected, **result})
    return {"scope": __doc__, "unicorn_version": unicorn.__version__,
            "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
            "cases": cases, "real_estimator_values_observed": False,
            "code2_cache_safe_for_code4_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} stock capacity-tail fixtures passed; synthetic estimates only")


if __name__ == "__main__":
    main()
