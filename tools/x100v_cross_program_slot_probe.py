"""Run stock ARM slot accessors used upstream of the crop and save scripts.

Synthetic slot tables only: this does not schedule either message or prove a
same-shot handoff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_capture_geometry_probe import CANDIDATE_SECONDARY_SHA256
from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_update_package import STOCK_SHA256, read_secondary

LOAD = SOURCES["x100v_3_01"]["secondary_load"]
ROOT_BASE = 0x36000000
SLOT_STRIDE = 0x5610
GLOBAL_POINTER = 0x03421480  # [0x03420cb8 + 0x7c8]
OUTPUT = 0x37000000
RETURN = 0x38000000
STACK = 0x39000000
QUEUE_TABLE = 0x022D8838
RECORD_BASE = 0x0341CCB8 + 0x47CC
ACCESSORS = {
    "root": 0x01F272B4,
    "record": 0x01F27CCC,
    "queue": 0x01F2840C,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_accessors(secondary: bytes, slot: int) -> dict:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_SP,
    )

    if not 0 <= slot < 3:
        raise ValueError("fixture slot must be 0, 1 or 2")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, length in ((0x01F27000, 0x2000), (0x022D8000, 0x1000)):
        uc.mem_map(address, length)
        uc.mem_write(address, secondary[address - LOAD:address - LOAD + length])
    uc.mem_map(0x03421000, 0x1000)
    uc.mem_map(ROOT_BASE, 0x30000)
    for address in (OUTPUT, RETURN, STACK):
        uc.mem_map(address, 0x1000)
    uc.mem_write(GLOBAL_POINTER, struct.pack("<I", ROOT_BASE))
    for index in range(3):
        root = ROOT_BASE + index * SLOT_STRIDE
        uc.mem_write(root + 0x5600, struct.pack("<I", index + 2))
        uc.mem_write(root + 0x5604, struct.pack("<I", index))

    observed = {}
    for name, entry in ACCESSORS.items():
        uc.reg_write(UC_ARM_REG_R0, slot)
        uc.reg_write(UC_ARM_REG_R1, OUTPUT)
        uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
        uc.reg_write(UC_ARM_REG_LR, RETURN)
        uc.emu_start(entry, RETURN, count=50)
        if uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise AssertionError(f"{name} accessor did not return")
        observed[name] = uc.reg_read(UC_ARM_REG_R0)
    observed["queue_bytes"] = bytes(uc.mem_read(OUTPUT, 12)).hex()
    return observed


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if sha(stock_dat) != STOCK_SHA256 or sha(candidate_dat) != CANDIDATE_DAT_SHA256:
        raise ValueError("DAT identity mismatch")
    stock = read_secondary(stock_dat)[1]
    candidate = read_secondary(candidate_dat)[1]
    if sha(stock) != SOURCES["x100v_3_01"]["secondary_sha256"] or \
            sha(candidate) != CANDIDATE_SECONDARY_SHA256:
        raise ValueError("secondary identity mismatch")
    for start, end in ((0x01F272B4, 0x01F272D0),
                       (0x01F27CCC, 0x01F27D10),
                       (0x01F2840C, 0x01F28460),
                       (QUEUE_TABLE, QUEUE_TABLE + 36)):
        if stock[start - LOAD:end - LOAD] != candidate[start - LOAD:end - LOAD]:
            raise AssertionError(f"accessor/table changed in candidate at {start:#x}")

    rows = []
    for slot in range(3):
        actual = run_accessors(candidate, slot)
        expected_queue = candidate[QUEUE_TABLE - LOAD + 12 * slot:
                                   QUEUE_TABLE - LOAD + 12 * (slot + 1)].hex()
        expected = {
            "root": ROOT_BASE + slot * SLOT_STRIDE,
            "record": RECORD_BASE + (slot + 2) * 0x50,
            "queue": 0,
            "queue_bytes": expected_queue,
        }
        if actual != expected:
            raise AssertionError(f"slot {slot}: {actual} != {expected}")
        rows.append({"slot": slot, "actual": actual, "expected": expected})
    return {
        "scope": "three original-ARM accessor cases in synthetic per-slot RAM",
        "stock_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_secondary_sha256": CANDIDATE_SECONDARY_SHA256,
        "rows": rows,
        "shared_index_domain": True,
        "root_equals_record_pointer": False,
        "same_live_slot_verified": False,
        "cross_program_order_verified": False,
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
    print(f"{len(result['rows'])} slot indices passed three ARM accessors each")


if __name__ == "__main__":
    main()
