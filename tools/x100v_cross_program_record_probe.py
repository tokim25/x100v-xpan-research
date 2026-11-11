"""Check stock ARM record/root handoff with synthetic slot memory.

This executes accessors, record reset/assignment, and worker payload copy.
It does not schedule messages, establish a live slot, or exercise a camera.
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
from tools.x100v_cross_program_slot_probe import (
    GLOBAL_POINTER, LOAD, RECORD_BASE, ROOT_BASE, SLOT_STRIDE,
)
from tools.x100v_update_package import STOCK_SHA256, read_secondary

MODE_RECORD = 0x37000000
PAYLOAD = 0x37100000
RETURN = 0x38000000
STACK = 0x39000000


def _word(uc, address: int) -> int:
    return struct.unpack("<I", uc.mem_read(address, 4))[0]


def run_case(secondary: bytes, slot: int) -> dict:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_SP,
    )

    if slot not in (0, 1, 2):
        raise ValueError("fixture slot must be 0, 1, or 2")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, length in ((0x01F27000, 0x2000), (0x01F3B000, 0x1000)):
        uc.mem_map(address, length)
        uc.mem_write(address, secondary[address - LOAD:address - LOAD + length])
    for address, length in ((0x03421000, 0x1000), (ROOT_BASE, 0x30000),
                            (MODE_RECORD, 0x1000), (PAYLOAD, 0x1000),
                            (RETURN, 0x1000), (STACK, 0x1000)):
        uc.mem_map(address, length)
    uc.mem_write(GLOBAL_POINTER, struct.pack("<I", ROOT_BASE))
    root = ROOT_BASE + slot * SLOT_STRIDE
    uc.mem_write(root + 0x5600, struct.pack("<I", slot + 2))

    def call(entry: int, r0: int, r1: int = 0) -> int:
        uc.reg_write(UC_ARM_REG_R0, r0)
        uc.reg_write(UC_ARM_REG_R1, r1)
        uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
        uc.reg_write(UC_ARM_REG_LR, RETURN)
        uc.emu_start(entry, RETURN, count=100)
        if uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise AssertionError(f"ARM function {entry:#x} did not return")
        return uc.reg_read(UC_ARM_REG_R0)

    actual_root = call(0x01F272B4, slot)
    record = call(0x01F27CCC, slot)
    expected_record = RECORD_BASE + (slot + 2) * 0x50
    if (actual_root, record) != (root, expected_record):
        raise AssertionError("slot accessor mismatch")

    # The ordinary per-slot record and mode-35 request object have distinct
    # addresses, but the same stock initializer can put the root in word zero.
    for target in (record, MODE_RECORD):
        uc.mem_write(target, b"\xa5" * 0x50)
        call(0x01F3B360, target)
        if _word(uc, target) != 0:
            raise AssertionError("reset did not clear record word zero")
        call(0x01F3B3B0, target, root)
        if _word(uc, target) != root:
            raise AssertionError("record setter did not store root")

    # A synthetic key-4 worker payload changes fields starting at +4 only.
    # This is the stock copy routine, not the live queue or interpreter.
    payload = bytes((i * 17 + slot) & 0xff for i in range(0x40))
    uc.mem_write(PAYLOAD, payload)
    call(0x01F3B62C, record, PAYLOAD)
    if _word(uc, record) != root:
        raise AssertionError("worker payload copy changed record root")
    if bytes(uc.mem_read(record + 4, 1)) != payload[:1]:
        raise AssertionError("worker did not copy key byte")

    return {
        "slot": slot,
        "root": actual_root,
        "record": record,
        "mode_record": MODE_RECORD,
        "record_word_zero_after_reset": 0,
        "record_word_zero_after_set_and_copy": _word(uc, record),
        "mode_record_word_zero_after_set": _word(uc, MODE_RECORD),
        "worker_key_byte": bytes(uc.mem_read(record + 4, 1)).hex(),
    }


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if hashlib.sha256(stock_dat).hexdigest() != STOCK_SHA256:
        raise ValueError("stock DAT identity mismatch")
    if hashlib.sha256(candidate_dat).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("candidate DAT identity mismatch")
    stock = read_secondary(stock_dat)[1]
    candidate = read_secondary(candidate_dat)[1]
    if hashlib.sha256(stock).hexdigest() != SOURCES["x100v_3_01"]["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    if hashlib.sha256(candidate).hexdigest() != CANDIDATE_SECONDARY_SHA256:
        raise ValueError("candidate secondary identity mismatch")
    for start, end in ((0x01F272B4, 0x01F272E8),
                       (0x01F27CCC, 0x01F27D30),
                       (0x01F3B360, 0x01F3B39C),
                       (0x01F3B3B0, 0x01F3B3C8),
                       (0x01F3B62C, 0x01F3B6A0)):
        if stock[start - LOAD:end - LOAD] != candidate[start - LOAD:end - LOAD]:
            raise AssertionError(f"candidate changed stock routine at {start:#x}")
    rows = [run_case(candidate, slot) for slot in range(3)]
    return {
        "scope": "three synthetic slot/record cases executing unchanged stock ARM",
        "stock_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_secondary_sha256": CANDIDATE_SECONDARY_SHA256,
        "rows": rows,
        "same_live_slot_verified": False,
        "cross_program_order_verified": False,
        "physical_capture_verified": False,
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
    print(f"{len(result['rows'])} record/root ARM cases passed")


if __name__ == "__main__":
    main()
