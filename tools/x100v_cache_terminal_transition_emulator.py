"""Execute the original 0x122a/state-5 terminal transition in synthetic RAM.

Starts at category-1 callback 0x1e6ac1c. Runs message acceptance, the full
terminal callback, post-return state transition, and readiness query. Stops
BEFORE 0x1ea84c8: no external refresh operation or constructor is executed.
Optional control-operation cases continue to the actual cache-enable caller
when no kernel call is needed, or stop before the kernel wrapper otherwise.
The caller/event scheduler and earlier asynchronous states are not modeled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges
from tools.x100v_preview_cache_export_emulator import load_images, verify_images
from tools.x100v_estimate_leaf_emulator import load_volume, verify_volume

ENTRY, BOUNDARY = 0x1E6AC1C, 0x1EA84C8
PACKET, RESULT, READY, OUTER = 0x28757A0, 0x2879510, 0x28B73C4, 0x2C9E30A
STACK = 0x30000000
CONTROL, ENABLE, KERNEL = 0xD4B108, 0x1EA3CFC, 0x113CBA4
OPERATION_MODES = ("missing", "unchanged10", "unchanged4", "changed")


def reference_payload(status: int, value: int) -> tuple[int, int]:
    if type(status) is not int or not 0 <= status <= 255:
        raise ValueError("status must be a byte")
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("value must be uint32")
    return (value if status == 0 else 0), 0


def reference_control(mode: str) -> tuple[int, list[int], int]:
    if mode not in OPERATION_MODES:
        raise ValueError("unsupported control fixture")
    slots = [4 if mode == "unchanged4" else 15, 15, 15, 15, 15]
    before = 4 if mode == "unchanged4" else (15 if mode == "changed" else 10)
    updated = list(slots)
    updated[1] = 10
    return before, slots, min(15, *updated)


def execute(secondary: bytes, status: int, value: int, *, primary: bytes | None = None,
            volume: bytes | None = None, operation_mode: str | None = None) -> dict:
    expected = reference_payload(status, value)
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("unrecognized secondary image")
    stop = BOUNDARY
    if operation_mode is not None:
        before, slots, after = reference_control(operation_mode)
        if primary is None or volume is None:
            raise ValueError("control operation requires primary and volume images")
        verify_images(primary, secondary)
        verify_volume(volume)
        stop = KERNEL if operation_mode == "changed" else ENABLE
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x1E6A000, 0x1E9B000, 0x1E9C000, 0x1EA8000, 0x22B8000):
        uc.mem_map(page, 4096)
        offset = page-source["secondary_load"]
        uc.mem_write(page, secondary[offset:offset+4096])
    for page in (0x2875000, 0x2879000, 0x287F000, 0x28B7000,
                 0x2C9E000, 0x2DA9000, 0x27B0000, STACK):
        uc.mem_map(page, 4096)
    if operation_mode is not None:
        for page in (0x113A000, 0x113C000, 0x1EA3000):
            uc.mem_map(page, 4096)
            im, base = (primary, source["primary_load"]) if page < 0x1BA0000 else (secondary, source["secondary_load"])
            uc.mem_write(page, im[page-base:page-base+4096])
        for page in (0xD20000, 0xD49000):
            uc.mem_map(page, 4096)
            start = max(page, source["volume_partition_load"])
            offset = start-source["volume_partition_load"]
            uc.mem_write(start, volume[offset:offset+page+4096-start])
        for page in (0x1850000, 0x1851000, 0xD4B000, 0xD89000):
            uc.mem_map(page, 4096)
        uc.mem_write(0x1851BB4, struct.pack("<I", 0xFFFFFFFF if operation_mode == "missing" else 0))
        uc.mem_write(0x18509B0, struct.pack("<I", source["volume_partition_load"]))
        uc.mem_write(CONTROL-4, struct.pack("<8I", 0xA5A5A5A5, before, *slots, 0xA5A5A5A5))
        uc.mem_write(0xD89A3A, bytes([45]))
    uc.mem_write(PACKET, struct.pack("<H", 0x122A))
    uc.mem_write(PACKET+12, bytes([status]))
    uc.mem_write(PACKET+16, struct.pack("<I", value))
    uc.mem_write(RESULT-4, b"\xa5"*16)
    uc.mem_write(READY-2, struct.pack("<3H", 0xA5A5, 5, 0xA5A5))
    uc.mem_write(OUTER-2, struct.pack("<3H", 0xA5A5, 1, 0xA5A5))
    sp = STACK+0xF00
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, 0x31000000)
    ranges = ((ENTRY, 0x1E6AC50), (0x1EA8428, 0x1EA8450),
              (0x1EA8484, 0x1EA8494), (0x1EA8594, 0x1EA85D4),
              (0x1E9BE64, 0x1E9C0C8), (0x1E9C0F8, 0x1E9C110),
              (0x1E9C1C0, 0x1E9C1D4), (0x1EA8A90, 0x1EA8B04),
              (0x1EA831C, 0x1EA8324), (0x1EA82A0, 0x1EA82B8),
              (0x1EA82F8, 0x1EA831C))
    if operation_mode is not None:
        ranges += ((0x1E6AC50, 0x1E6AC54), (BOUNDARY, 0x1EA84FC),
                   (0x113A6A0, 0x113A6FC), (0xD49028, 0xD490CC))
    writes, visited = [], []

    def instruction(machine, address, size, _):
        if address == stop:
            machine.emu_stop()
            return
        if not any(a <= address < b for a, b in ranges):
            raise RuntimeError(f"escaped terminal transition {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, word, _):
        if STACK <= address and address+size <= STACK+4096:
            return
        allowed = ((0x287F838, 1), (0x2DA9246, 1), (0x27B0CB0, 2),
                   (RESULT, 4), (RESULT+4, 4), (READY, 2), (OUTER, 2))
        if operation_mode is not None:
            allowed += ((CONTROL+8, 4), (CONTROL, 4))
        if (address, size) not in allowed:
            raise RuntimeError(f"unexpected transition write {address:#x}/{size}")
        writes.append((address, size, word))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(ENTRY, 0x31000000, count=500, timeout=1000000)
    stack_depth = 40 if operation_mode == "changed" else 8
    if uc.reg_read(UC_ARM_REG_PC) != stop or uc.reg_read(UC_ARM_REG_SP) != sp-stack_depth:
        raise AssertionError("did not reach selected boundary with expected stack depth")
    if bytes(uc.mem_read(RESULT-4, 16)) != struct.pack("<4I", 0xA5A5A5A5, *expected, 0xA5A5A5A5):
        raise AssertionError("terminal payload publication or guards differ")
    for address in (READY, OUTER):
        if bytes(uc.mem_read(address-2, 6)) != struct.pack("<3H", 0xA5A5, 0, 0xA5A5):
            raise AssertionError("selector not cleared or guard changed")
    expected_writes = [(0x287F838, 1, 2), (0x2DA9246, 1, 0), (0x27B0CB0, 2, 5),
                       (RESULT, 4, expected[0]), (RESULT+4, 4, 0), (READY, 2, 0),
                       (0x287F838, 1, 1), (0x2DA9246, 1, 0), (0x27B0CB0, 2, 0),
                       (OUTER, 2, 0)]
    if operation_mode is not None:
        expected_slots = list(slots)
        expected_current = before
        if operation_mode != "missing":
            expected_slots[1] = 10
            expected_writes.append((CONTROL+8, 4, 10))
            if operation_mode != "changed":
                expected_current = after
                expected_writes.append((CONTROL, 4, after))
        expected_bank = struct.pack("<8I", 0xA5A5A5A5, expected_current, *expected_slots, 0xA5A5A5A5)
        if bytes(uc.mem_read(CONTROL-4, 32)) != expected_bank:
            raise AssertionError("control bank or guards differ")
        if operation_mode == "changed" and (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)) != (45, after):
            raise AssertionError("wrong kernel-wrapper arguments")
    if writes != expected_writes:
        raise AssertionError("transition write order differs from independent sequence")
    return dict(status=status, input_word=value, published_words=expected,
                writes=writes, instructions=len(visited), stop_pc=hex(stop),
                operation_mode=operation_mode,
                control_method_entered=0xD49028 in visited,
                missing_mapping_return_executed=0x113A6F4 in visited,
                cache_enable_caller_reached=stop == ENABLE, kernel_wrapper_executed=False,
                terminal_callback_executed=True, readiness_query_executed=True,
                refresh_executed=False, hardware_io_performed=False)


def verify(primary: bytes, secondary: bytes, volume: bytes) -> dict:
    import unicorn
    verify_images(primary, secondary)
    source = SOURCES["x100v_3_01"]
    verify_hashed_ranges(secondary, source["secondary_load"], source["preview_cache_enable_dispatch_ranges"])
    verify_volume(volume)
    verify_hashed_ranges(primary, source["primary_load"], source["preview_cache_control_primary_ranges"])
    verify_hashed_ranges(volume, source["volume_partition_load"], source["preview_cache_control_volume_ranges"])
    cases = [execute(secondary, status, value) for status in (0, 1, 255)
             for value in (0, 1, 0xFFFFFFFF)]
    operation_cases = [execute(secondary, status, value, primary=primary, volume=volume, operation_mode=mode)
                       for mode in OPERATION_MODES for status in (0, 1, 255) for value in (0, 1, 0xFFFFFFFF)]
    return dict(scope=__doc__, secondary_sha256=source["secondary_sha256"],
                unicorn_version=unicorn.__version__, cases=cases, control_operation_cases=operation_cases,
                volume_sha256=source["volume_partition_sha256"],
                initial_readiness_selector=5, initial_category1_second_selector=1,
                message_id="0x122a", control_operation_executed=True, kernel_operation_executed=False,
                earlier_states_executed=False, cache_freshness_verified=False,
                firmware_modified=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_volume(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} terminal and {len(report['control_operation_cases'])} control cases passed; no kernel call or cache refresh executed")


if __name__ == "__main__":
    main()
