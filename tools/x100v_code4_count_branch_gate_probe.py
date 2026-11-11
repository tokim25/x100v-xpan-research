"""Probe the merged image's preview descriptor and count branch gate in ARM.

This executes only the descriptor builder through its field setup, then the
count entry's branch gate. It does not execute count arithmetic or a camera.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, read_preview_key_table
from tools.x100v_code4_cache_count_input_probe import REUSED, copied_key
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256, CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_update_package import read_primary

BASE = 0x00F21000
DESCRIPTOR = 0x0115D964
DESCRIPTOR_STOPS = (0x0115DA30, 0x0115DAA8)
COUNT_GATE = 0x011685A4
COUNT_MAIN = 0x01168604
COUNT_ALT = 0x0116868C
INPUT = 0x30000000
OUTPUT = 0x30001000
STACK = 0x33000000
STATES = (
    (0, 0, 0), (0, 2, 0), (31, 1, 0),
    (31, 2, 0), (31, 2, 1), (31, 2, 2),
)


def run_case(primary: bytes, record: bytes) -> dict:
    from unicorn import (
        UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
        UC_HOOK_MEM_WRITE, UC_MODE_ARM, Uc,
    )
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_SP,
    )

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x0115D000, 0x0128F000, 0x014A6000, 0x01168000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, primary[page - BASE:page - BASE + 0x1000])
    for page in (INPUT, OUTPUT, STACK):
        uc.mem_map(page, 0x1000)
    uc.mem_write(INPUT, record)
    uc.mem_write(OUTPUT, bytes(64))

    def check_write(machine, access, address, size, value, _):
        if not (OUTPUT <= address and address + size <= OUTPUT + 64 or
                STACK <= address and address + size <= STACK + 0x1000):
            raise AssertionError(f"descriptor wrote outside synthetic RAM: {address:#x}")

    uc.hook_add(UC_HOOK_MEM_WRITE, check_write)

    def invalid_memory(machine, access, address, size, value, _):
        raise AssertionError(f"unmapped ARM access at {address:#x} from PC {machine.reg_read(UC_ARM_REG_PC):#x}")

    uc.hook_add(UC_HOOK_MEM_INVALID, invalid_memory)
    uc.reg_write(UC_ARM_REG_R0, INPUT)
    uc.reg_write(UC_ARM_REG_R1, OUTPUT)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
    uc.reg_write(UC_ARM_REG_LR, 0x34000000)
    descriptor_stop = []

    def stop_at_descriptor_fields(machine, address, size, _):
        if address in DESCRIPTOR_STOPS:
            descriptor_stop.append(address)
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop_at_descriptor_fields)
    uc.emu_start(DESCRIPTOR, 0x0115DB00, count=2000, timeout=1_000_000)
    if len(descriptor_stop) != 1:
        raise AssertionError("descriptor builder did not reach field gate")
    descriptor = bytes(uc.mem_read(OUTPUT, 64))

    selected = []

    def stop_at_gate(machine, address, size, _):
        if address in (COUNT_MAIN, COUNT_ALT):
            selected.append(address)
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop_at_gate)
    uc.reg_write(UC_ARM_REG_R4, OUTPUT)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
    uc.emu_start(COUNT_GATE, 0x01168700, count=100, timeout=1_000_000)
    if len(selected) != 1:
        raise AssertionError(f"count branch gate did not select once: {selected}")
    return {
        "descriptor_type": descriptor[0],
        "descriptor_width": int.from_bytes(descriptor[2:4], "little"),
        "descriptor_height": int.from_bytes(descriptor[4:6], "little"),
        "descriptor_state_11": descriptor[0x11],
        "descriptor_state_12": descriptor[0x12],
        "count_branch": "alternate" if selected[0] == COUNT_ALT else "main",
    }


def verify(candidate_dat: bytes) -> dict:
    if hashlib.sha256(candidate_dat).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("unrecognized merged offline package")
    primary = read_primary(candidate_dat)[1]
    if hashlib.sha256(primary).hexdigest() != CANDIDATE_PRIMARY_SHA256:
        raise ValueError("decoded primary identity changed")
    source = SOURCES["x100v_3_01"]
    rows = read_preview_key_table(primary, source["primary_load"],
                                  source["preview_key_table"], 57)
    cases = []
    for level, second, index, old_height in REUSED:
        copied = copied_key(primary, index)
        if tuple(copied[i] for i in (5, 4, 6)) != (level, second, 2):
            raise AssertionError(f"row {index} did not copy the stock key")
        for kind, record_type, state_18 in STATES:
            record = bytearray(copied)
            record[0], record[2], record[0x18] = kind, record_type, state_18
            try:
                actual = run_case(primary, bytes(record))
            except Exception as exc:
                raise AssertionError(
                    f"row {index}, kind {kind}, type {record_type}, state {state_18}: {exc}"
                ) from exc
            expected_branch = (
                "alternate" if kind == 31 and record_type == 2 and state_18 != 2
                else "main"
            )
            expected_state_12 = state_18 if state_18 in (1, 2) else 0
            # Input +2 is also the lookup bypass flag: value 1 returns
            # sentinel row zero, so its dimensions must not be reused.
            expected_width = 0 if record_type == 1 else rows[index]["width"]
            expected_height = 0 if record_type == 1 else old_height
            if actual != {
                "descriptor_type": record_type,
                "descriptor_width": expected_width,
                "descriptor_height": expected_height,
                "descriptor_state_11": int(kind == 31),
                "descriptor_state_12": expected_state_12,
                "count_branch": expected_branch,
            }:
                raise AssertionError(f"unexpected descriptor/branch at row {index}: {actual}")
            cases.append({"index": index, "row_key": [level, second, 2],
                          "input_kind": kind, "input_type": record_type,
                          "input_state_18": state_18, **actual})
    return {
        "scope": "actual merged primary; row-copy, descriptor field setup, and count branch gate only",
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "cases": cases,
        "count_arithmetic_executed": False,
        "live_descriptor_values_known": False,
        "cache_and_status_executed": False,
        "camera_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"{len(report['cases'])} descriptor/count-branch ARM cases passed")


if __name__ == "__main__":
    main()
