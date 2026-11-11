"""Bounded original-ARM dispatch and message-classification fixtures.

Stop BEFORE the final selected callback or the message-check successor. The
nested category-22 cases execute its forwarding callback and wrappers. Separate
readiness cases execute the complete local query and constant-return callbacks.
No message-advance service, refresh, diagnostic loop, scheduler or camera runs. A selected
refresh callback is NOT evidence of a completed refresh or freshness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges, verify_data_words
from tools.x100v_preview_cache_export_emulator import load_images, verify_images

STATE, FIRST, SECOND, PACKET = 0x02D56488, 0x02D5648E, 0x02C9E30A, 0x028757A0
STACK, STOP = 0x30000000, 0x31000000
CALLBACKS = (0x1E6ABB4, 0x1E6ABCC, 0x1E6ABE4, 0x1E6AC00, 0x1E6AC1C, 0x1E6AC68)
REFRESH_CALLBACK = 0x1E6AC1C
ACCEPT, DIAGNOSTIC = 0x1EA8484, 0x1EA846C


def reference_dispatch(state: int, message: int, second: int) -> tuple[int, int]:
    if (type(state) is not int or not 0 <= state <= 255
            or type(message) is not int or not 0 <= message <= 65535
            or type(second) is not int or second not in (0, 1)):
        raise ValueError("outside byte state / uint16 message / two-column fixture domain")
    # Independent explicit state matrix; not read from the binary's table.
    if state == 3:
        return 0, (0x1E6ABB4, 0x1E6ABCC)[second]
    if state in (0, 1):
        return 1, (0x1E6ABE4, 0x1E6AC00)[second]
    if state == 4:
        if message in range(0x1224, 0x122C):
            return 2, (0x1E6AC00, REFRESH_CALLBACK)[second]
        return 3, (0x1E6ABB4, 0x1E6AC68)[second]
    return 4, 0x1E6AC00


def reference_message(message: int) -> int:
    if type(message) is not int or not 0 <= message <= 65535:
        raise ValueError("expected uint16 message")
    return ACCEPT if message in (0x1224, 0x1226, 0x1228, 0x122A) else DIAGNOSTIC


def reference_nested22(message: int, outer_second: int, second: int) -> int:
    if type(outer_second) is not int or outer_second not in (0, 1, 2):
        raise ValueError("expected category-22 second selector 0, 1 or 2")
    inner = reference_dispatch(4, message, second)[1]
    if message not in range(0x1224, 0x122C):
        raise ValueError("nested fixture restricted to eight message IDs")
    return 0x1E7FDA8 if outer_second == 0 else inner


def execute(secondary: bytes, *, state: int, message: int, second: int,
            message_only: bool = False, outer_second: int | None = None) -> dict:
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("unrecognized secondary image")
    first, target = reference_dispatch(state, message, second)
    if outer_second is not None:
        if message_only or state != 4:
            raise ValueError("nested dispatch requires state 4, not message-only mode")
        target = reference_nested22(message, outer_second, second)
    if message_only:
        target = reference_message(message)
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x1E5D000, 0x1E62000, 0x1E6A000, 0x1E7F000,
                 0x1EA8000, 0x1EBB000, 0x22B2000, 0x22B7000, 0x22B8000):
        uc.mem_map(page, 4096)
        offset = page - source["secondary_load"]
        uc.mem_write(page, secondary[offset:offset + 4096])
    for page in (STATE & ~4095, SECOND & ~4095, PACKET & ~4095, STACK, 0x2CA2000):
        uc.mem_map(page, 4096)
    uc.mem_write(STATE, b"\xa5")  # entry must write the supplied state itself
    uc.mem_write(FIRST - 2, b"\xa5" * 6)
    uc.mem_write(SECOND - 2, struct.pack("<3H", 0xA5A5, second, 0xA5A5))
    uc.mem_write(PACKET, struct.pack("<H", message))
    if outer_second is not None:
        uc.mem_write(0x2CA2498, b"\x04")
        uc.mem_write(0x2C9E334, struct.pack("<H", outer_second))
    uc.reg_write(UC_ARM_REG_R0, state)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xF00)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    visited, writes = [], []
    boundaries = (ACCEPT, DIAGNOSTIC) if message_only else CALLBACKS
    if outer_second is not None:
        boundaries += (0x1E7FDA8,)
    ranges = ((0x1EA8428, 0x1EA8450),) if message_only else (
        (0x1EA82DC, 0x1EA82F8), (0x1E5DAF8, 0x1E5DBB0), (0x1E5D958, 0x1E5D9DC))
    if outer_second is not None:
        ranges += ((0x1E6243C, 0x1E62594), (0x1E7FF6C, 0x1E7FF7C),
                   (0x1EBB268, 0x1EBB278), (0x1EBB1F4, 0x1EBB208))

    def instruction(machine, address, size, _):
        if address in boundaries:
            machine.emu_stop()
            return
        if not any(a <= address < b for a, b in ranges):
            raise RuntimeError(f"escaped dispatch fragment at {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if STACK <= address and address + size <= STACK + 4096:
            return
        allowed = ((STATE, 1), (FIRST, 2))
        if outer_second is not None:
            allowed += ((0x2D564B8, 2),)
        if message_only or (address, size) not in allowed:
            raise RuntimeError(f"unexpected dispatch write {address:#x}/{size}")
        writes.append((address, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    entry = 0x1E6243C if outer_second is not None else (0x1EA8428 if message_only else 0x1EA82DC)
    uc.emu_start(entry, STOP, count=200, timeout=1000000)
    pc = uc.reg_read(UC_ARM_REG_PC)
    if pc != target:
        raise AssertionError(f"wrong dispatch boundary {pc:#x}, expected {target:#x}")
    if not message_only:
        expected_writes = [(STATE, 1, state), (FIRST, 2, first)]
        if outer_second is not None:
            expected_writes = [(0x2D564B8, 2, 21)] + (expected_writes if outer_second else [])
        if writes != expected_writes:
            raise AssertionError("state/selector writes differ from reference")
        expected_first = 0xA5A5 if outer_second == 0 else first
        if bytes(uc.mem_read(FIRST - 2, 6)) != struct.pack("<3H", 0xA5A5, expected_first, 0xA5A5):
            raise AssertionError("first selector guard changed")
    if bytes(uc.mem_read(SECOND - 2, 6)) != struct.pack("<3H", 0xA5A5, second, 0xA5A5):
        raise AssertionError("second selector or guard changed")
    if bytes(uc.mem_read(PACKET, 2)) != struct.pack("<H", message):
        raise AssertionError("packet changed")
    return dict(state=state, message=hex(message), second=second, message_only=message_only,
                outer_second=outer_second, forwarding_callback_executed=outer_second in (1, 2),
                first_selector=None if message_only or outer_second == 0 else first, stop_pc=hex(pc),
                instructions=len(visited), writes=writes,
                final_selected_callback_executed=False, refresh_executed=False)


def verify(primary: bytes, secondary: bytes) -> dict:
    import unicorn
    verify_images(primary, secondary)
    source = SOURCES["x100v_3_01"]
    verify_hashed_ranges(secondary, source["secondary_load"], source["preview_cache_enable_dispatch_ranges"])
    verify_data_words(secondary, source["secondary_load"], source["preview_cache_enable_dispatch_data_words"])
    messages = (0, 0x1223, *range(0x1224, 0x122C), 0x122C, 65535)
    cases = [execute(secondary, state=s, message=m, second=b)
             for s in (0, 1, 2, 3, 4, 5, 255) for m in messages for b in (0, 1)]
    checks = [execute(secondary, state=4, message=m, second=1, message_only=True) for m in messages]
    nested = [execute(secondary, state=4, message=m, second=b, outer_second=o)
              for m in range(0x1224, 0x122C) for o in (0, 1, 2) for b in (0, 1)]
    predicates = [execute_ready_predicate(secondary, second=s) for s in range(6)]
    return dict(scope=__doc__, secondary_sha256=source["secondary_sha256"],
                unicorn_version=unicorn.__version__, dispatch_cases=cases, message_check_cases=checks,
                nested_category22_cases=nested,
                ready_predicate_cases=predicates,
                accepted_message_ids=["0x1224", "0x1226", "0x1228", "0x122a"],
                live_second_selector_domain_verified=False, ready_predicate_executed=True,
                cache_freshness_verified=False, camera_io_performed=False, firmware_modified=False)


def execute_ready_predicate(secondary: bytes, *, second: int) -> dict:
    """Execute the complete local readiness query, not message-advance callbacks."""
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("unrecognized secondary image")
    if type(second) is not int or second not in range(6):
        raise ValueError("expected readiness selector 0..5")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x1E9B000, 0x1E9C000, 0x1EA8000, 0x22B8000):
        uc.mem_map(page, 4096)
        offset = page - source["secondary_load"]
        uc.mem_write(page, secondary[offset:offset+4096])
    for page in (0x287F000, 0x2DA9000, 0x27B0000, 0x28B7000, STACK):
        uc.mem_map(page, 4096)
    uc.mem_write(0x28B73C2, struct.pack("<3H", 0xA5A5, second, 0xA5A5))
    sp = STACK + 0xF00
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    visited, writes = [], []
    ranges = ((0x1EA82F8, 0x1EA831C), (0x1EA8594, 0x1EA85D4),
              (0x1E9BE64, 0x1E9C0C8), (0x1E9C0F8, 0x1E9C128))

    def instruction(machine, address, size, _):
        if not any(a <= address < b for a, b in ranges):
            raise RuntimeError(f"escaped readiness query {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if STACK <= address and address+size <= STACK+4096:
            return
        if (address, size) not in ((0x287F838, 1), (0x2DA9246, 1), (0x27B0CB0, 2)):
            raise RuntimeError(f"unexpected readiness write {address:#x}/{size}")
        writes.append((address, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(0x1EA82F8, STOP, count=200, timeout=1000000)
    result = uc.reg_read(UC_ARM_REG_R0)
    if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_SP) != sp:
        raise AssertionError("query did not return with stack restored")
    if result != int(second == 0):
        raise AssertionError("readiness differs from fixed zero-selector reference")
    if writes != [(0x287F838, 1, 1), (0x2DA9246, 1, 0), (0x27B0CB0, 2, 0)]:
        raise AssertionError("unexpected readiness state writes")
    if bytes(uc.mem_read(0x28B73C2, 6)) != struct.pack("<3H", 0xA5A5, second, 0xA5A5):
        raise AssertionError("query changed second selector/guards")
    return dict(second_selector=second, result=result, instructions=len(visited), writes=writes,
                complete_return=True, message_advance_executed=False, refresh_executed=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['dispatch_cases'])} dispatch, {len(report['message_check_cases'])} message-check, "
          f"{len(report['nested_category22_cases'])} nested category-22, "
          f"{len(report['ready_predicate_cases'])} readiness cases passed")


if __name__ == "__main__":
    main()
