"""Execute the stock cache-update entry through preserve/clear/recompute selection.

Preserve and clear cases return through the original export code. Recompute
cases stop BEFORE the count constructor. Inputs, volume context, and fifth
argument (1, skipping selected-count processing) are synthetic. No camera I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_preview_cache_export_emulator import load_images, verify_images, BASES, CACHE, COUNT
from tools.x100v_estimate_leaf_emulator import load_volume, verify_volume

ENTRY, RECOMPUTE = 0x0115C5B8, 0x0115C758
GLOBAL = CACHE - 4
INPUT, STACK, STOP, CONTEXT = 0x10000000, 0x20000000, 0x30000000, 0x31000000


def gate_descriptor(aspect: int) -> bytes:
    """Match builder 0x1ea068c/90: active +0x70 -> descriptor +6."""
    if type(aspect) is not int or aspect not in (2, 4):
        raise ValueError("expected aspect code 2 or 4")
    descriptor = bytearray(36)
    descriptor[6] = aspect
    return bytes(descriptor)


def reference_action(flag: int, query_success: bool, bits: int) -> str:
    if flag != 1:
        return "preserve"
    return "recompute" if query_success and bits & 1 == 0 else "clear"


def execute(primary: bytes, secondary: bytes, volume: bytes, *, flag: int,
            bits: int, ready: int, missing: bool, aspect: int) -> dict:
    verify_images(primary, secondary)
    verify_volume(volume)
    if (type(flag) is not int or not 0 <= flag <= 255 or type(ready) is not int or not 0 <= ready <= 255
            or type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF or type(missing) is not bool
            or type(aspect) is not int or aspect not in (2, 4) or flag == 0 and not missing):
        raise ValueError("outside explicitly supported refresh fixture domain")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    source = SOURCES["x100v_3_01"]
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x0115B000, 0x0115C000, 0x0113A000, 0x01140000):
        uc.mem_map(page, 4096)
        offset = page-source["primary_load"]
        uc.mem_write(page, primary[offset:offset+4096])
    for page in (0x00D20000, 0x00D27000):
        uc.mem_map(page, 4096)
        start = max(page, source["volume_partition_load"])
        offset = start-source["volume_partition_load"]
        uc.mem_write(start, volume[offset:offset+page+4096-start])
    uc.mem_map(0x00D89000, 4096)
    uc.mem_map(0x0184E000, 0x4000)
    for page in (INPUT, STACK, BASES[0] & ~4095):
        uc.mem_map(page, 4096)
    uc.mem_map(CONTEXT, 0x17000)
    uc.mem_write(0x00D89A20, struct.pack("<I", CONTEXT))
    uc.mem_write(CONTEXT + 0x16B6C, struct.pack("<I", bits))
    uc.mem_write(CONTEXT + 0x16BEC, bytes([ready]))
    uc.mem_write(0x01851BB4, struct.pack("<I", 0xFFFFFFFF if missing else 0))
    uc.mem_write(0x018509B0, struct.pack("<I", source["volume_partition_load"]))
    uc.mem_write(GLOBAL, bytes([flag]))
    original = list(range(100, 157))
    uc.mem_write(CACHE, struct.pack("<57I", *original))
    uc.mem_write(BASES[0], b"\xa5" * 240)
    descriptor = gate_descriptor(aspect)
    uc.mem_write(INPUT, descriptor)
    sp = STACK + 0xF00
    uc.mem_write(sp, struct.pack("<I", 1))
    for reg, value in ((UC_ARM_REG_R0, INPUT), (UC_ARM_REG_R1, 0),
                       (UC_ARM_REG_R2, BASES[0]+8), (UC_ARM_REG_R3, 0),
                       (UC_ARM_REG_SP, sp), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    ranges = ((ENTRY, RECOMPUTE), (0x115B780, 0x115B7F4), (0x115B8C4, 0x115B97C),
              (0x113A894, 0x113A940), (0x1140808, 0x11409D4), (0xD2703C, 0xD2715C))
    visited, writes = [], []

    def instruction(machine, address, size, _):
        if address == RECOMPUTE:
            machine.emu_stop()
            return
        if not any(a <= address < b for a, b in ranges):
            raise RuntimeError(f"unexpected refresh instruction {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if STACK <= address <= STACK+4096-size:
            return
        allowed = ((CACHE, CACHE+228), (BASES[0]+8, BASES[0]+236),
                   (GLOBAL+0x229D, GLOBAL+0x229E), (GLOBAL+0x22A0, GLOBAL+0x22A1))
        if not any(a <= address and address+size <= b for a, b in allowed):
            raise RuntimeError(f"unexpected refresh write {address:#x}/{size}")
        writes.append((address, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(ENTRY, STOP, count=3000, timeout=1000000)
    pc = uc.reg_read(UC_ARM_REG_PC)
    expected = reference_action(flag, not missing and ready != 0, bits)
    if pc != (RECOMPUTE if expected == "recompute" else STOP):
        raise AssertionError(f"wrong refresh boundary: {expected}/{pc:#x}")
    actual = list(struct.unpack("<57I", uc.mem_read(CACHE, 228)))
    exported = list(struct.unpack("<57I", uc.mem_read(BASES[0]+8, 228)))
    if actual != ([0]*COUNT if expected == "clear" else original):
        raise AssertionError("unexpected primary cache contents")
    if exported != ([0xA5A5A5A5]*COUNT if expected == "recompute" else actual):
        raise AssertionError("unexpected exported cache contents")
    if bytes(uc.mem_read(BASES[0], 8)) != b"\xa5"*8 or bytes(uc.mem_read(BASES[0]+236, 4)) != b"\xa5"*4:
        raise AssertionError("output guards changed")
    if expected != "recompute" and uc.reg_read(UC_ARM_REG_SP) != sp:
        raise AssertionError("returned path did not restore stack")
    return dict(flag=flag, query_bits=bits, ready_byte=ready, missing_mapping=missing, aspect=aspect,
                input_descriptor_hex=descriptor.hex(), aspect_descriptor_offset=6,
                expected_action=expected, stop_pc=hex(pc), original_cache=original,
                resulting_cache=actual, exported_cache=exported, query1_executed=0x113A8E8 in visited,
                query1_context_reader_executed=0xD2714C in visited,
                full_return=pc == STOP, instructions=len(visited),
                cache_write_bytes=sum(s for a, s, _ in writes if CACHE <= a < CACHE+228),
                export_write_bytes=sum(s for a, s, _ in writes if BASES[0]+8 <= a < BASES[0]+236))


def verify(primary: bytes, secondary: bytes, volume: bytes) -> dict:
    import unicorn
    vectors = ((0, 0, 1, True), (2, 0, 1, True), (255, 0, 1, True),
               (1, 0, 1, True), (1, 0, 0, False), (1, 1, 1, False),
               (1, 0, 1, False), (1, 2, 1, False), (1, 0xFFFFFFFF, 1, False),
               (1, 0xFFFFFFFE, 255, False))
    cases = [execute(primary, secondary, volume, flag=f, bits=b, ready=r, missing=m, aspect=a)
             for f, b, r, m in vectors for a in (2, 4)]
    return dict(scope=__doc__, unicorn_version=unicorn.__version__, cases=cases,
                primary_sha256=hashlib.sha256(primary).hexdigest(),
                volume_sha256=hashlib.sha256(volume).hexdigest(),
                descriptor_other_bytes=0, aspect_descriptor_offset=6,
                supersedes_aspect_coverage="x100v-cache-refresh-gate-arm-fixtures.json used byte 5, not aspect byte 6",
                fifth_argument=1, callback_pointer=0,
                recomputation_executed=False, ordinary_still_timing_verified=False,
                cache_alias_safety_verified=False, firmware_modified=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_volume(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} original-entry refresh gate cases passed; recompute boundary not crossed")


if __name__ == "__main__":
    main()
