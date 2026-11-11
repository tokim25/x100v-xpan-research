"""Execute stock cache export and indexed-read fragments on synthetic RAM.

This is NOT the full constructor, receive worker, scheduler or live preview.
The harness explicitly sequences isolated reads before/after the copy. It does
not establish when a camera refreshes the array relative to a frame/capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_firmware_probe import HEADER_SIZE
from tools.fuji_xpan_validation import SOURCES, decode_partition

BASES = (0x01734A8C, 0x02EEA24C)
CACHE, SHARED, STACK = 0x0184E37C, 0x028787A0, 0x30000000
COUNT, BYTE_COUNT = 57, 228
INIT = (0x0103997C, 0x01039994)
EXPORT = (0x0115C60C, 0x0115C624)
COPY = (0x01140808, 0x011409D4)
READ = (0x01EB5848, 0x01EB585C)
GUARD = 0xA5A5A5A5


def verify_images(primary: bytes, secondary: bytes) -> None:
    source = SOURCES["x100v_3_01"]
    for name, data in (("primary", primary), ("secondary", secondary)):
        if hashlib.sha256(data).hexdigest() != source[f"{name}_sha256"]:
            raise ValueError(f"unrecognized {name} image")


def load_images(update: Path) -> tuple[bytes, bytes]:
    source = SOURCES["x100v_3_01"]
    data = update.read_bytes()
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("unrecognized X100V update")
    payload = bytes(value ^ 255 for value in data[HEADER_SIZE:])
    images = tuple(decode_partition(payload, source[f"{name}_header"])
                   for name in ("primary", "secondary"))
    verify_images(*images)
    return images


def reference_slot(base: int, index: int) -> int:
    if base not in BASES or type(index) is not int or not 0 <= index < COUNT:
        raise ValueError("outside known published arrays / 57-slot domain")
    return base + 8 + 4 * index


def execute(primary: bytes, secondary: bytes, base: int, values: list[int],
            null_output: bool = False) -> dict:
    verify_images(primary, secondary)
    reference_slot(base, 0)
    if (len(values) != COUNT or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in values)
            or type(null_output) is not bool):
        raise ValueError("expected 57 uint32 fixtures and a boolean null-output flag")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R2, UC_ARM_REG_R5, UC_ARM_REG_R7,
                                   UC_ARM_REG_R11, UC_ARM_REG_SP, UC_ARM_REG_PC,
                                   UC_ARM_REG_CPSR)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    source = SOURCES["x100v_3_01"]
    for page in (0x01039000, 0x0115C000, 0x01140000):
        uc.mem_map(page, 4096)
        uc.mem_write(page, primary[page-source["primary_load"]:page-source["primary_load"]+4096])
    page = 0x01EB5000
    uc.mem_map(page, 4096)
    uc.mem_write(page, secondary[page-source["secondary_load"]:page-source["secondary_load"]+4096])
    for page in (base & ~4095, CACHE & ~4095, SHARED & ~4095, STACK):
        uc.mem_map(page, 4096)
    initial = struct.pack("<I", GUARD) * (COUNT + 3)
    uc.mem_write(base, initial)
    fixture = struct.pack("<57I", *values)
    uc.mem_write(CACHE, fixture)
    uc.mem_write(SHARED + 0x740, struct.pack("<I", base))
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xF00)
    uc.reg_write(UC_ARM_REG_R11, STACK + 0x800)
    phase, visited, writes = "", [], []

    def instruction(machine, address, size, _):
        allowed = {"init": (INIT,), "read": (READ,), "export": (EXPORT, COPY)}[phase]
        if not any(start <= address < end for start, end in allowed):
            raise RuntimeError(f"escaped {phase}: {address:#x}")
        visited.append((phase, address))

    def write(machine, access, address, size, value, _):
        if STACK <= address <= STACK + 4096 - size:
            return
        if (phase not in ("init", "export") or not base + 8 <= address
                or address + size > base + 8 + BYTE_COUNT):
            raise RuntimeError(f"unexpected {phase} write: {address:#x}/{size}")
        writes.append((phase, address, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)

    def run(start, stop):
        uc.emu_start(start, stop, count=2000, timeout=1000000)
        if uc.reg_read(UC_ARM_REG_PC) != stop:
            raise RuntimeError("fragment did not reach its boundary")
        if uc.reg_read(UC_ARM_REG_SP) != STACK + 0xF00:
            raise RuntimeError("fragment did not preserve stack")

    # This block's r2 is established by MOVW/MOVT at 0x1039920/24.
    # Only that real base gets the original 9999 initializer fragment.
    if base == BASES[0]:
        phase = "init"
        uc.reg_write(UC_ARM_REG_R2, base)
        run(*INIT)
        if bytes(uc.mem_read(base + 8, BYTE_COUNT)) != struct.pack("<I", 9999) * COUNT:
            raise AssertionError("stock initializer does not match fixed 57 x 9999 vector")

    def read_all():
        nonlocal phase
        phase = "read"
        result = []
        for index in range(COUNT):
            # The earlier runtime gate must be not-equal for this selected path.
            uc.reg_write(UC_ARM_REG_CPSR, 0x13)
            uc.reg_write(UC_ARM_REG_R5, index)
            run(*READ)
            result.append(struct.unpack("<I", uc.mem_read(STACK + 0x800 - 0x28, 4))[0])
        return result

    before = read_all()
    phase = "export"
    # Constructor entry retains its r2 output argument in r7 at 0x115c5cc.
    uc.reg_write(UC_ARM_REG_R7, 0 if null_output else base + 8)
    run(*EXPORT)
    after = read_all()
    expected = before if null_output else values
    if after != expected or bytes(uc.mem_read(CACHE, BYTE_COUNT)) != fixture:
        raise AssertionError("cache export or slot selection mismatch")
    if bytes(uc.mem_read(base, 8)) != initial[:8] or bytes(uc.mem_read(base+236, 4)) != initial[-4:]:
        raise AssertionError("export changed surrounding words")
    copied_bytes = sum(size for p, _, size, _ in writes if p == "export")
    if copied_bytes != (0 if null_output else BYTE_COUNT):
        raise AssertionError("incorrect number of copied bytes")
    return dict(base=hex(base), null_output=null_output, selected_before=before, selected_after=after,
                copied_bytes=copied_bytes, source_unchanged=True, surrounding_words_unchanged=True,
                initializer_executed=base == BASES[0],
                copy_helper_executed=("export", COPY[0]) in visited,
                instructions=len(visited), writes=[dict(phase=p, address=hex(a), size=s, value=v)
                                                  for p, a, s, v in writes])


def verify(primary: bytes, secondary: bytes) -> dict:
    import unicorn
    vectors = {"distinct_slots": list(range(COUNT)),
               "u32_edges": [0, 1, 9999, 99999, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF] * 8 + [57]}
    cases = []
    for base in BASES:
        for name, values in vectors.items():
            cases.append(dict(vector=name, **execute(primary, secondary, base, values)))
        cases.append(dict(vector="null_destination", **execute(primary, secondary, base,
                                                                 vectors["distinct_slots"], True)))
    return dict(scope=__doc__, unicorn_version=unicorn.__version__, cases=cases,
                primary_sha256=hashlib.sha256(primary).hexdigest(),
                secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                full_constructor_executed=False, same_invocation_read_precedes_refresh_static=True,
                live_array_freshness_verified=False, cache_reuse_safe_verified=False,
                camera_or_firmware_modified=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} cache-export cases passed; all 57 slots checked before/after; no camera I/O")


if __name__ == "__main__":
    main()
