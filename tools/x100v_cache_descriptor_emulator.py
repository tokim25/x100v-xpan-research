"""Execute the stock 36-byte preview descriptor builder on synthetic RAM.

Only helper 0x1159270's active+0x47 != 1 early-return branch is covered.
No refresh caller, constructor, camera, USB or storage operation is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges
from tools.x100v_preview_cache_export_emulator import load_images, verify_images

ENTRY, END, HELPER = 0x1EA063C, 0x1EA07E0, 0x1159270
ACTIVE, OUTPUT, STACK, STOP = 0x10000000, 0x10001000, 0x20000000, 0x30000000
SHARED = 0x28787A0
DIRECT_FIELDS = ((0, 0), (1, 4), (2, 0x71), (3, 0x72), (4, 0x6D),
                 (6, 0x70), (7, 0x78), (8, 0x79), (9, 0x524),
                 (10, 0x6E), (11, 0x6F), (12, 0x595), (14, 0x40F),
                 (15, 0x413), (16, 0x414), (17, 0x415), (18, 0x520),
                 (19, 0x521), (20, 0x534), (22, 0x530), (23, 0x572),
                 (24, 0x57B), (32, 0x57E), (33, 0x57F))


def reference_descriptor(active: bytes) -> bytes:
    if len(active) != 0x600 or active[0x47] == 1:
        raise ValueError("fixture requires 0x600 bytes and helper early return")
    output = bytearray(b"\xa5" * 36)
    for dst, src in DIRECT_FIELDS:
        output[dst] = active[src]
    output[5] = output[21] = active[0x6C if active[0] == 45 else 0x6B]
    output[13] = 0
    mode = active[4]
    value = (active[15] if mode == 5 else 3 if mode in (6, 7, 9, 10)
             else (2 if active[20] == 1 else struct.unpack_from("<I", active, 24)[0])
             if mode == 11 else 1)
    struct.pack_into("<I", output, 28, value)
    return bytes(output)


def execute(primary: bytes, secondary: bytes, active: bytes) -> dict:
    verify_images(primary, secondary)
    source = SOURCES["x100v_3_01"]
    for kind, data in (("primary", primary), ("secondary", secondary)):
        verify_hashed_ranges(data, source[f"{kind}_load"],
                             source[f"preview_cache_descriptor_{kind}_ranges"])
    expected = reference_descriptor(active)
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, data, base in ((ENTRY, secondary, source["secondary_load"]),
                                (HELPER, primary, source["primary_load"])):
        page = address & ~4095
        uc.mem_map(page, 4096)
        uc.mem_write(page, data[page-base:page-base+4096])
    for page in (ACTIVE, OUTPUT, STACK, SHARED & ~4095):
        uc.mem_map(page, 4096)
    uc.mem_write(ACTIVE, active)
    uc.mem_write(OUTPUT, b"\xa5" * 64)
    uc.mem_write(SHARED+0x73C, struct.pack("<I", ACTIVE))
    sp = STACK+0xF00
    for reg, value in ((UC_ARM_REG_R0, ACTIVE), (UC_ARM_REG_R1, OUTPUT+8),
                       (UC_ARM_REG_SP, sp), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    visited, writes = [], []

    def instruction(machine, address, size, _):
        if not (ENTRY <= address < 0x1EA0758 or 0x1EA0774 <= address < 0x1EA07DC
                or HELPER <= address < HELPER+0x20):
            raise RuntimeError(f"unexpected descriptor instruction {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if STACK <= address and address+size <= STACK+4096:
            return
        if not OUTPUT+8 <= address or address+size > OUTPUT+44:
            raise RuntimeError(f"unexpected descriptor write {address:#x}/{size}")
        writes.append((address-OUTPUT-8, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(ENTRY, STOP, count=200, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_SP) != sp:
        raise AssertionError("builder did not return and restore stack")
    actual = bytes(uc.mem_read(OUTPUT+8, 36))
    if actual != expected or bytes(uc.mem_read(ACTIVE, len(active))) != active:
        raise AssertionError("descriptor mismatch or active state changed")
    if bytes(uc.mem_read(OUTPUT, 8)) != b"\xa5"*8 or bytes(uc.mem_read(OUTPUT+44, 20)) != b"\xa5"*20:
        raise AssertionError("output guards changed")
    if HELPER not in visited or sum(size for _, size, _ in writes) != 31:
        raise AssertionError("helper or exact descriptor write coverage changed")
    return dict(type=active[0], mode=active[4], aspect=active[0x70],
                alternate_word_gate=active[20], descriptor_hex=actual.hex(),
                writes=writes, instructions=len(visited), full_return=True)


def verify(primary: bytes, secondary: bytes) -> dict:
    import unicorn
    cases = []
    for camera_type in (0, 45):
        for mode in (0, 5, 6, 7, 8, 9, 10, 11, 255):
            for aspect in (2, 4):
                for gate in ((0, 1) if mode == 11 else (0,)):
                    active = bytearray((i*13+7) & 255 for i in range(0x600))
                    active[0], active[4], active[0x70] = camera_type, mode, aspect
                    active[0x47], active[20] = 0, gate
                    cases.append(execute(primary, secondary, bytes(active)))
    return dict(scope=__doc__, unicorn_version=unicorn.__version__, cases=cases,
                primary_sha256=hashlib.sha256(primary).hexdigest(),
                secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                aspect_source_offset=0x70, aspect_descriptor_offset=6,
                untouched_descriptor_offsets=[25, 26, 27, 34, 35],
                helper_early_return_only=True, full_refresh_executed=False,
                firmware_modified=False, camera_io=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} stock descriptor builder cases passed")


if __name__ == "__main__":
    main()
