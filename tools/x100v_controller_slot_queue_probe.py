"""Execute stock ARM controller slot-list insertion, selection and removal.

Synthetic global RAM only. This does not run camera firmware or establish the
live dispatcher schedule that invokes the key-4 save callback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES

LOAD = SOURCES["x100v_3_01"]["secondary_load"]
BASE = 0x0341CCB8
CODE = 0x01F25000
RETURN = 0x38000000
STACK = 0x39000000


def run_vectors(secondary: bytes) -> dict:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_SP,
    )

    if hashlib.sha256(secondary).hexdigest() != \
            SOURCES["x100v_3_01"]["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(CODE, 0x4000)
    uc.mem_write(CODE, secondary[CODE - LOAD:CODE - LOAD + 0x4000])
    uc.mem_map(0x0341C000, 0x2000)
    uc.mem_map(0x03420000, 0x10000)
    uc.mem_write(BASE, b"\xff" * 0x500)
    uc.mem_write(BASE + 0x4B4, struct.pack("<I", 0))
    for address in (RETURN, STACK):
        uc.mem_map(address, 0x1000)

    def call(entry: int, arg0: int, arg1: int = 0) -> int:
        uc.reg_write(UC_ARM_REG_R0, arg0)
        uc.reg_write(UC_ARM_REG_R1, arg1)
        uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
        uc.reg_write(UC_ARM_REG_LR, RETURN)
        uc.emu_start(entry, RETURN, count=2000)
        if uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise AssertionError(f"ARM {entry:#x} did not return")
        return uc.reg_read(UC_ARM_REG_R0)

    def head() -> tuple[int, int]:
        slot = struct.unpack("<I", uc.mem_read(BASE + 0xB4, 4))[0]
        kind = uc.mem_read(BASE + 0xB8, 1)[0]
        return slot, kind

    rows = []
    for action, slot, kind in (
        ("insert", 4, 1),
        ("insert", 5, 1),
        ("insert", 6, 2),
        ("remove", 5, 0),
        ("remove", 4, 0),
        ("remove", 6, 0),
    ):
        result = call(0x01F284B0 if action == "insert" else 0x01F28598,
                      slot, kind)
        rows.append({
            "action": action,
            "slot": slot,
            "kind": kind,
            "return": result,
            "head": head(),
            "select_any": call(0x01F25C74, 0),
            "select_kind_1": call(0x01F25C74, 1),
            "select_kind_2": call(0x01F25C74, 2),
        })
    return {
        "scope": "stock ARM slot-list routines with synthetic global RAM",
        "secondary_sha256": hashlib.sha256(secondary).hexdigest(),
        "rows": rows,
        "dispatcher_slot_identity_verified": False,
        "live_processing_order_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secondary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run_vectors(args.secondary.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(f"{len(result['rows'])} controller slot-list steps executed")


if __name__ == "__main__":
    main()
