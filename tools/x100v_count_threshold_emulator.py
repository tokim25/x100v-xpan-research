"""Execute the stock selected-count threshold helper and all its callees.

Independent descriptor fixtures check return values and exact input read ranges.
No count estimator, status publisher, refresh, camera mode or saved file is tested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges
from tools.x100v_preview_cache_export_emulator import load_images

ENTRY, INPUT, STACK, STOP = 0x115C040, 0x10000000, 0x20000000, 0x30000000
RANGES = ((ENTRY, 0x115C138), (0x115BFE4, ENTRY),
          (0x115B6F8, 0x115B73C), (0x115B780, 0x115B7F4))
FILTER_START, FILTER_STOP = 0x115C718, 0x115BDD4
# selected count, minimum count, required count, resulting selected/minimum.
FILTER_VECTORS = (
    (0, 0, 1, 0, 0), (1, 1, 1, 1, 1), (2, 1, 2, 2, 0), (1, 2, 2, 0, 2),
    (7, 6, 7, 7, 0), (6, 7, 7, 0, 7), (0, 0, 0, 0, 0),
    (0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0),
    (0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF),
    (0x80000000, 0x7FFFFFFF, 0x80000000, 0x80000000, 0),
    (0x7FFFFFFF, 0x80000000, 0x80000000, 0, 0x80000000),
    (0xFFFFFFFF, 0xFFFFFFFF, 1, 0xFFFFFFFF, 0xFFFFFFFF),
)


def fixtures() -> list[dict]:
    # Expected values are fixed before execution, not derived from emulated output.
    rows = [
        ("ordinary", {}, 1, 1),
        ("paired-flags", {13: 1, 14: 1}, 1, 2),
        ("paired-flags-bypass", {2: 1, 13: 1, 14: 1}, 1, 1),
        ("type25", {0: 25, 16: 1}, 1, 2),
        ("type25-control", {0: 25}, 1, 1),
        ("type26", {0: 26, 15: 1}, 1, 2),
        ("type26-control", {0: 26}, 1, 1),
        ("type29", {0: 29, 17: 1, 18: 4}, 1, 2),
        ("type29-control", {0: 29, 17: 1, 18: 3}, 1, 1),
        ("type31", {0: 31, 2: 2}, 1, 2),
        ("type31-control", {0: 31}, 1, 1),
        ("type45-bypass", {0: 45, 2: 1}, 1, 1),
        ("normalized-bypass", {0: 31, 2: 2, 23: 2}, 1, 1),
        ("zero-mode-word", {1: 5}, 1, 1),
        ("max-mode-word", {1: 5, 28: 255, 29: 255, 30: 255, 31: 255}, 1, 0xFFFFFFFF),
    ]
    for mode, with_flag, without_flag in ((5, 7, 1), (6, 7, 7), (7, 7, 1),
                                          (8, 1, 1), (9, 7, 7), (10, 7, 7), (11, 7, 1)):
        rows += [(f"mode-{mode}-flag", {1: mode, 28: 7}, 1, with_flag),
                 (f"mode-{mode}-no-flag", {1: mode, 28: 7}, 0, without_flag)]
    result = []
    for name, fields, flag, expected in rows:
        for aspect in (2, 4):
            descriptor = bytearray(36)
            for offset, value in fields.items():
                descriptor[offset] = value
            descriptor[6] = aspect
            result.append(dict(name=name, aspect=aspect, flag=flag, expected=expected,
                               descriptor_hex=descriptor.hex()))
    return result


def execute(primary: bytes, fixture: dict) -> dict:
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(primary).hexdigest() != source["primary_sha256"]:
        raise ValueError("unrecognized primary image")
    verify_hashed_ranges(primary, source["primary_load"], source["preview_count_threshold_ranges"])
    descriptor = bytes.fromhex(fixture["descriptor_hex"])
    if len(descriptor) != 36 or fixture["flag"] not in (0, 1):
        raise ValueError("invalid fixture")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R11,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x115B000, 0x115C000):
        uc.mem_map(page, 4096)
        offset = page-source["primary_load"]
        uc.mem_write(page, primary[offset:offset+4096])
    for page in (INPUT, STACK):
        uc.mem_map(page, 4096)
    uc.mem_write(INPUT, b"\xa5"*64)
    uc.mem_write(INPUT+8, descriptor)
    sp = STACK+0xF00
    saved = ((UC_ARM_REG_R4, 0x44444444), (UC_ARM_REG_R5, 0x55555555),
             (UC_ARM_REG_R11, 0xBBBBBBBB))
    for reg, value in ((UC_ARM_REG_R0, INPUT+8), (UC_ARM_REG_R1, 0),
                       (UC_ARM_REG_R2, fixture["flag"]), (UC_ARM_REG_SP, sp),
                       (UC_ARM_REG_LR, STOP), *saved):
        uc.reg_write(reg, value)
    visited, reads = [], []

    def instruction(machine, address, size, _):
        if not any(a <= address < b for a, b in RANGES):
            raise RuntimeError(f"unexpected threshold instruction {address:#x}")
        visited.append(address)

    def read(machine, access, address, size, value, _):
        if INPUT <= address < INPUT+4096:
            if not INPUT+8 <= address or address+size > INPUT+44:
                raise AssertionError("descriptor read outside bounds")
            reads.append((address-INPUT-8, size))

    def write(machine, access, address, size, value, _):
        if not STACK <= address or address+size > STACK+4096:
            raise AssertionError(f"unexpected non-stack write {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_READ, read)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(ENTRY, STOP, count=300, timeout=1000000)
    returned = uc.reg_read(UC_ARM_REG_R0)
    if returned != fixture["expected"] or uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise AssertionError(f"threshold mismatch: {fixture['name']}/{returned}")
    if uc.reg_read(UC_ARM_REG_SP) != sp or any(uc.reg_read(r) != v for r,v in saved):
        raise AssertionError("threshold failed callee-saved/stack restoration")
    if bytes(uc.mem_read(INPUT, 64)) != b"\xa5"*8+descriptor+b"\xa5"*20:
        raise AssertionError("input or surrounding guards changed")
    if any(a <= 6 < a+n for a,n in reads):
        raise AssertionError("aspect byte unexpectedly read")
    return dict(**fixture, returned=returned, descriptor_reads=sorted(set(reads)),
                instructions=len(visited), full_return=True, aspect_byte_read=False)


def execute_filter(primary: bytes, vector: tuple[int, ...]) -> dict:
    """Isolated post-helper fragment; descriptor mode 0 excludes the mode-2 branch."""
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(primary).hexdigest() != source["primary_sha256"]:
        raise ValueError("unrecognized primary image")
    verify_hashed_ranges(primary, source["primary_load"], source["preview_count_filter_ranges"])
    selected, minimum, required, expected_selected, expected_minimum = vector
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                                   UC_ARM_REG_SP, UC_ARM_REG_PC)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x115C000, 4096)
    offset = 0x115C000-source["primary_load"]
    uc.mem_write(0x115C000, primary[offset:offset+4096])
    uc.mem_map(INPUT, 4096)
    uc.mem_map(STACK, 4096)
    for reg, value in ((UC_ARM_REG_R0, required), (UC_ARM_REG_R4, INPUT),
                       (UC_ARM_REG_R5, minimum), (UC_ARM_REG_R6, selected),
                       (UC_ARM_REG_SP, STACK+0xF00)):
        uc.reg_write(reg, value)

    def instruction(machine, address, size, _):
        if not FILTER_START <= address < 0x115C754:
            raise RuntimeError(f"unexpected filter instruction {address:#x}")

    def write(machine, access, address, size, value, _):
        raise AssertionError(f"unexpected filter write {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(FILTER_START, FILTER_STOP, count=30, timeout=1000000)
    args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
    if (uc.reg_read(UC_ARM_REG_PC) != FILTER_STOP or args != [0, expected_minimum, expected_selected]
            or uc.reg_read(UC_ARM_REG_SP) != STACK+0xF00):
        raise AssertionError(f"wrong count filter result {vector}/{args}")
    return dict(selected=selected, minimum=minimum, required=required,
                resulting_selected=args[2], resulting_minimum=args[1],
                publisher_arguments=args, publisher_executed=False, isolated_fragment=True)


def main():
    import unicorn
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    primary, _ = load_images(args.update)
    cases = [execute(primary, fixture) for fixture in fixtures()]
    filters = [execute_filter(primary, vector) for vector in FILTER_VECTORS]
    report = dict(scope=__doc__, cases=cases, primary_sha256=hashlib.sha256(primary).hexdigest(),
                  unicorn_version=unicorn.__version__,
                  count_filter_cases=filters,
                  camera_io=False, firmware_modified=False, callee_stubs=False,
                  publisher_executed=False)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(cases)} stock threshold cases and {len(filters)} unsigned count-filter cases passed")


if __name__ == "__main__":
    main()
