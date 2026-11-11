"""Execute stock and ratio-only patched ARM crop code on synthetic RAM.

No camera, boot, encoder, filesystem service, or MMIO is emulated. Cortex-A15
is an instruction-set execution choice for ARM integer division, not a claim
about the camera's processor. The actual candidate must match the pinned plan.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_firmware_probe import HEADER_SIZE
from tools.fuji_xpan_validation import SOURCES, decode_partition, plan_x100v_code4_ratio_stub, parse_primary_records
from tools.x100v_ratio_offline_candidate import apply_exact_partition_writes

ENTRY = 0x0115EEE0
END = 0x0115EFF4
STUB = 0x0128FB14
OUTPUT = 0x10000000
STACK = 0x20000000
STOP = 0x30000000


def load_stock(update: Path, model: str) -> bytes:
    source = SOURCES[model]
    data = update.read_bytes()
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("unrecognized stock update")
    stock = decode_partition(bytes(b ^ 255 for b in data[HEADER_SIZE:]), source["primary_header"])
    if hashlib.sha256(stock).hexdigest() != source["primary_sha256"]:
        raise ValueError("unrecognized stock primary")
    return stock


def load_images(update: Path, candidate: Path) -> tuple[bytes, bytes]:
    source = SOURCES["x100v_3_01"]
    stock = load_stock(update, "x100v_3_01")
    patched = candidate.read_bytes()
    expected = apply_exact_partition_writes(stock, plan_x100v_code4_ratio_stub(stock, source)["writes"])
    if patched != expected:
        raise ValueError("candidate differs from exact ratio-only plan")
    return stock, patched


def execute(image: bytes, width: int, height: int, code: int, model: str = "x100v_3_01") -> dict:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
        UC_ARM_REG_LR, UC_ARM_REG_PC)

    if not 0 < width <= 65535 or not 0 < height <= 65535 or not 0 <= code <= 255:
        raise ValueError("fixture outside bounded input domain")
    source = SOURCES[model]
    load = source["primary_load"]
    entry = source["crop_ratio_helper"]
    end = entry + source["crop_ratio_common_body_offset"] + source["crop_ratio_common_body_size"]
    ranges = [(entry, end)]
    if model == "x100v_3_01":
        ranges.append((STUB, STUB + 12))
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    for start, end in ranges:
        uc.mem_map(start & ~4095, 4096)
        uc.mem_write(start, image[start - load:end - load])
    uc.mem_map(OUTPUT, 4096)
    uc.mem_map(STACK, 4096)
    uc.mem_write(OUTPUT, b"\xcc" * 32)
    visited = []

    def instruction(machine, address, size, _):
        if not any(start <= address < end for start, end in ranges):
            raise RuntimeError(f"execution escaped crop helper: {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if not (OUTPUT <= address and address + size <= OUTPUT + 24 or
                STACK <= address and address + size <= STACK + 4096):
            raise RuntimeError(f"unexpected crop write: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    for register, value in ((UC_ARM_REG_R0, width), (UC_ARM_REG_R1, height),
                           (UC_ARM_REG_R2, code), (UC_ARM_REG_R3, OUTPUT),
                           (UC_ARM_REG_SP, STACK + 0xF00), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(register, value)
    uc.emu_start(entry, STOP, count=200, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise RuntimeError("crop helper did not return")
    return {"words": list(struct.unpack("<6I", uc.mem_read(OUTPUT, 24))),
            "instructions": len(visited), "stub_executed": STUB in visited}


def verify(stock: bytes, patched: bytes) -> dict:
    import unicorn
    # Six words: width, height, top, bottom, left, right. Explicit independent
    # vectors include alignment rounding; these are not copied from the model.
    vectors = [
        ("L", 6240, 4160, [6240, 2304, 928, 928, 0, 0]),
        ("M", 4416, 2944, [4416, 1628, 658, 658, 0, 0]),
        ("S", 3120, 2080, [3120, 1152, 464, 464, 0, 0]),
        ("already_65_24", 6240, 2304, [6240, 2304, 0, 0, 0, 0]),
        ("width_crop", 6240, 2000, [5416, 2000, 0, 0, 412, 412]),
    ]
    cases = []
    for name, width, height, expected in vectors:
        result = execute(patched, width, height, 4)
        if result["words"] != expected or not result["stub_executed"]:
            raise AssertionError(f"patched ARM fixture failed: {name}: {result}")
        cases.append({"name": name, "input": [width, height, 4], "expected": expected, **result})
    stock_control = execute(stock, 6240, 4160, 4)
    if stock_control["words"] != [5544, 4160, 0, 0, 348, 348] or stock_control["stub_executed"]:
        raise AssertionError("stock 4:3-default control failed")
    unchanged = []
    for code in (0, 1, 2, 3, 5, 6, 7, 8, 255):
        before, after = execute(stock, 6240, 4160, code), execute(patched, 6240, 4160, code)
        if before != after or after["stub_executed"]:
            raise AssertionError(f"non-code-4 behavior changed: {code}")
        unchanged.append({"code": code, **after})
    return {"scope": "isolated stock and modified ARM crop helper; no boot or camera evidence",
            "unicorn_version": unicorn.__version__, "cpu_model": "Cortex-A15 (ISA harness only)",
            "stock_primary_sha256": hashlib.sha256(stock).hexdigest(),
            "candidate_primary_sha256": hashlib.sha256(patched).hexdigest(),
            "code4_cases": cases, "stock_code4_control": stock_control,
            "unchanged_other_codes": unchanged,
            "medium_geometry_conflict": {"helper_height": 1628, "existing_table_candidate_height": 1632,
                "resolved": False}}


def compare_gfx(gfx: bytes, patched: bytes) -> dict:
    source = SOURCES["gfx100_5_18"]
    records = {row["id"]: row for row in parse_primary_records(gfx, source["primary_table"])}
    # Fixed independent vectors from rational geometry, including four-pixel
    # truncation, compared with actual stock selectable output rows.
    vectors = [("L", 0, 4, [11648, 8736], [11648, 4300, 2218, 2218, 0, 0], [11648, 4304]),
               ("M", 7, 11, [8256, 6192], [8256, 3048, 1572, 1572, 0, 0], [8256, 3048]),
               ("S", 14, 18, [4000, 3000], [4000, 1476, 762, 762, 0, 0], [4000, 1480])]
    cases = []
    for name, base_id, output_id, dimensions, expected, table in vectors:
        base, output = records[base_id], records[output_id]
        if [base["width"], base["height"]] != dimensions or [output["width"], output["height"]] != table:
            raise AssertionError("GFX stock size-table fixture changed")
        if output["code"] >> 8 != 4 or output["enabled_byte"] != 1:
            raise AssertionError("GFX row is not enabled aspect 4")
        result = execute(gfx, *dimensions, 4, model="gfx100_5_18")
        if result["words"] != expected:
            raise AssertionError(f"GFX ARM fixture failed: {name}: {result}")
        cases.append({"name": name, "input": dimensions, "expected": expected,
                      "stock_output_row": table, "height_delta_table_minus_helper": table[1] - expected[1], **result})
    cross = []
    for width, height in ((6240, 4160), (4416, 2944), (3120, 2080), (6240, 2000)):
        gfx_result = execute(gfx, width, height, 4, model="gfx100_5_18")
        x_result = execute(patched, width, height, 4)
        if gfx_result["words"] != x_result["words"]:
            raise AssertionError("X100V patched helper differs from stock GFX helper")
        cross.append({"input": [width, height], "matching_words": gfx_result["words"]})
    return {"stock_update_sha256": source["sha256"], "stock_primary_sha256": hashlib.sha256(gfx).hexdigest(),
            "native_size_cases": cases, "cross_model_same_input_cases": cross,
            "conclusion": "Stock GFX also has four-pixel helper/table differences; equality is not an established cross-path invariant.",
            "camera_behavior_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--gfx100", type=Path)
    args = parser.parse_args()
    stock, patched = load_images(args.update, args.candidate)
    report = verify(stock, patched)
    if args.gfx100:
        report["gfx_reference"] = compare_gfx(load_stock(args.gfx100, "gfx100_5_18"), patched)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("5 patched ARM vectors, stock control, and 9 unchanged-code comparisons passed")
    print("Unresolved: M helper yields 4416x1628; existing size-table candidate is 4416x1632")
    if args.gfx100:
        print("Stock GFX also differs at L/S; 4 same-input cross-model ARM comparisons passed")


if __name__ == "__main__":
    main()
