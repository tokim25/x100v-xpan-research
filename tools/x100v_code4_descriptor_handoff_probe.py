"""Bounded ARM test of crop-result destination versus encoder descriptor choice.

The producer and consumer are run separately with synthetic context.  External
validation calls are given explicit synthetic return values.  This does not
prove that both commands run for one physical still image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_center_window_probe import SIZES
from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_code4_capture_geometry_probe import CANDIDATE_SECONDARY_SHA256
from tools.x100v_update_package import STOCK_SHA256, read_secondary

BASE7 = SOURCES["x100v_3_01"]["secondary_load"]
CTX = 0x33000000
WRAPPER = 0x34000000
STACK = 0x35000000
COPY_START = 0x01F3F034
COPY_END = 0x01F3F07C
SELECT_START = 0x01F40B94
SELECT_STOPS = {0x01F40BE4, 0x01F40CB8}
VALIDATION_CALLS = {
    0x01F40BD0, 0x01F40D98, 0x01F40DE4, 0x01F40E84, 0x01F40EAC,
    0x01F40E5C,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_uc(secondary: bytes):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, length in ((0x01F3F000, 0x1000), (0x01F40000, 0x2000)):
        uc.mem_map(address, length)
        uc.mem_write(address, secondary[address - BASE7:address - BASE7 + length])
    uc.mem_map(CTX, 0x5000)  # validator argument at context +0x49d8
    for address in (WRAPPER, STACK):
        uc.mem_map(address, 0x1000)
    uc.mem_write(WRAPPER, struct.pack("<I", CTX))
    return uc


def run_copy(secondary: bytes, state: int, bit10: int, command_arg: int,
             descriptor: bytes) -> dict:
    from unicorn.arm_const import UC_ARM_REG_FP, UC_ARM_REG_PC, UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_SP

    uc = new_uc(secondary)
    uc.mem_write(CTX + 0x5B0, bytes([state]))
    uc.mem_write(CTX + 0xB34, struct.pack("<I", bit10 << 10))
    uc.mem_write(STACK + 0x800 - 0x64, descriptor)
    uc.mem_write(CTX + 0xD4, bytes([0xD4]) * 28)
    uc.mem_write(CTX + 0xF0, bytes([0xF0]) * 28)
    uc.reg_write(UC_ARM_REG_R4, WRAPPER)
    uc.reg_write(UC_ARM_REG_R6, command_arg)
    uc.reg_write(UC_ARM_REG_FP, STACK + 0x800)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x600)
    uc.emu_start(COPY_START, COPY_END, count=45)
    if uc.reg_read(UC_ARM_REG_PC) != COPY_END:
        raise AssertionError("copy slice did not stop before next call")
    at_d4 = bytes(uc.mem_read(CTX + 0xD4, 28))
    at_f0 = bytes(uc.mem_read(CTX + 0xF0, 28))
    if at_f0 == descriptor and at_d4 == bytes([0xD4]) * 28:
        return {"destination": "+0xf0", "other_slot_unchanged": True}
    if at_d4 == descriptor and at_f0 == bytes([0xF0]) * 28:
        return {"destination": "+0xd4", "other_slot_unchanged": True}
    raise AssertionError("unexpected descriptor copy or overlapping write")


def run_select(secondary: bytes, state: int, bit10: int, selector: int,
               validation: int, *, mode: int = 0) -> dict:
    from unicorn import UC_HOOK_CODE, UcError
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4,
        UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R8,
    )

    uc = new_uc(secondary)
    uc.mem_write(CTX + 0x5B0, bytes([state]))
    uc.mem_write(CTX + 0x5AE, bytes([0]))
    uc.mem_write(CTX + 0xB34, struct.pack("<I", bit10 << 10))
    uc.reg_write(UC_ARM_REG_R1, CTX)
    uc.reg_write(UC_ARM_REG_R4, selector)
    uc.reg_write(UC_ARM_REG_R5, WRAPPER)
    uc.reg_write(UC_ARM_REG_R6, mode)
    stop = []
    validation_sites = []
    visited = []

    def hook(engine, address, size, _):
        visited.append(address)
        if address in VALIDATION_CALLS:
            validation_sites.append(address)
            engine.reg_write(UC_ARM_REG_R0, validation)
            engine.reg_write(UC_ARM_REG_PC, address + size)
        elif address in SELECT_STOPS:
            stop.append(address)
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(SELECT_START if mode == 0 else 0x01F40C88,
                     0x01F41100, count=120)
    except UcError as exc:
        raise AssertionError(
            f"selection failed at {uc.reg_read(UC_ARM_REG_PC):#x}, "
            f"selector={selector}, state={state}, bit10={bit10}, "
            f"last={list(map(hex, visited[-12:]))}"
        ) from exc
    if len(stop) != 1 or len(validation_sites) != 1:
        raise AssertionError(f"selection did not reach one validation and stop: {stop}, {validation_sites}")
    selected = uc.reg_read(UC_ARM_REG_R8)
    if selected == 0:
        slot = None
    elif CTX <= selected < CTX + 0x1000:
        slot = f"+{selected - CTX:#x}"
    else:
        raise AssertionError(f"invalid selected descriptor: {selected:#x}")
    return {"slot": slot, "validation_site": hex(validation_sites[0]),
            "stop": hex(stop[0])}


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if sha(stock_dat) != STOCK_SHA256 or sha(candidate_dat) != CANDIDATE_DAT_SHA256:
        raise ValueError("DAT identity mismatch")
    stock = read_secondary(stock_dat)[1]
    secondary = read_secondary(candidate_dat)[1]
    if sha(stock) != SOURCES["x100v_3_01"]["secondary_sha256"] or \
            sha(secondary) != CANDIDATE_SECONDARY_SHA256:
        raise ValueError("decoded secondary identity mismatch")
    for start, end in ((COPY_START, COPY_END), (SELECT_START, 0x01F40EC0)):
        lo, hi = start - BASE7, end - BASE7
        if stock[lo:hi] != secondary[lo:hi]:
            raise AssertionError(f"candidate changed tested branch bytes at {start:#x}")

    width, height = SIZES[0]
    descriptor = bytearray(28)
    struct.pack_into("<5I", descriptor, 4, 0x40000000, height * 12544,
                     12544, width * 2, height)
    cases = []
    for state, bit10, expected_copy, expected_sel1 in (
        (25, 0, "+0xf0", "+0xf0"),
        (26, 0, "+0xf0", "+0xf0"),
        (24, 1, "+0xf0", "+0xf0"),
        (24, 0, "+0xd4", "+0xd4"),
    ):
        producer = run_copy(secondary, state, bit10, 1, bytes(descriptor))
        if producer["destination"] != expected_copy:
            raise AssertionError(f"producer slot differs for {state}/{bit10}: {producer}")
        for selector, expected in ((0, "+0xd4"), (1, expected_sel1)):
            consumer = run_select(secondary, state, bit10, selector, 1)
            if consumer["slot"] != expected:
                raise AssertionError(f"consumer slot differs for {state}/{bit10}/{selector}: {consumer}")
            cases.append({"state": state, "bit10": bit10, "selector": selector,
                          "producer": producer, "consumer": consumer,
                          "same_slot": producer["destination"] == consumer["slot"]})
    failed_validation = run_select(secondary, 25, 0, 1, 0)
    if failed_validation["slot"] is not None:
        raise AssertionError("failed validation did not null descriptor")
    command16 = run_copy(secondary, 25, 0, 0, bytes(descriptor))
    if command16["destination"] != "+0xd4":
        raise AssertionError("argument-0 control unexpectedly wrote +0xf0")
    mode2_control = run_select(secondary, 24, 0, 1, 1, mode=2)
    if mode2_control["slot"] != "+0x144":
        raise AssertionError("mode-2 selector-1 control did not read +0x144")
    return {
        "scope": "bounded original ARM branch/copy, synthetic context and validation result",
        "stock_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_secondary_sha256": CANDIDATE_SECONDARY_SHA256,
        "cases": cases,
        "failed_validation_control": failed_validation,
        "argument_zero_control": command16,
        "mode2_selector1_control": mode2_control,
        "same_shot_order_verified": False,
        "live_still_route_verified": False,
        "saved_file_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.stock.read_bytes(), args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(f"{len(result['cases'])} producer/consumer ARM pairs passed")


if __name__ == "__main__":
    main()
