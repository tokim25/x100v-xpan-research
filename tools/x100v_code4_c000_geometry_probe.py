"""Probe two code-4-only C000 geometry hooks in pinned stock ARM, offline.

The patched image exists only in memory. A zero-filled decoded-image span is
not evidence that the camera maps it executable or that a saved RAF uses it.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_preview_alias_candidate import read_elf_text

SOURCE = SOURCES["x100v_3_01"]
LOAD = SOURCE["secondary_load"]
FIRST_HOOK = 0x01ED6C70
SECOND_HOOK = 0x01ED6CAC
CAVE = 0x01BA0040
SECOND_ENTRY = CAVE + 0x40
FIRST_END = 0x01ED6C84
SECOND_END = 0x01ED6CC0
OLD_HOOK_WORDS = (0xE1A03085, 0xE1A03080)
STUB_SHA256 = "864a0e029165a8c6cac3f7a3eca1f0567f70bda4f0bf1d44ec90e692437e3c64"
WIDTHS = (6240, 4416, 3120, 768, 6000)
ASPECTS = (0, 1, 2, 3, 4, 5, 6)
CTX = 0x33000000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def branch_word(source: int, destination: int) -> int:
    delta = destination - (source + 8)
    if delta % 4 or not -(1 << 25) <= delta < (1 << 25):
        raise ValueError("ARM branch target out of range or unaligned")
    return 0xEA000000 | ((delta >> 2) & 0xFFFFFF)


def assemble_stub() -> bytes:
    with tempfile.TemporaryDirectory(prefix="xpan-c000-code4-") as directory:
        obj = Path(directory) / "geometry.o"
        subprocess.run(
            ["clang", "--target=armv7a-none-eabi", "-c",
             "tools/x100v_code4_c000_geometry_stub.s", "-o", str(obj)],
            check=True,
        )
        stub = read_elf_text(obj)
    if len(stub) != 0x74 or sha(stub) != STUB_SHA256:
        raise ValueError("geometry stub assembly differs from reviewed bytes")
    return stub


def patch_in_memory(stock: bytes, stub: bytes) -> tuple[bytes, list[dict]]:
    if sha(stock) != SOURCE["secondary_sha256"]:
        raise ValueError("unrecognized X100V 3.01 secondary partition")
    if len(stub) != 0x74 or sha(stub) != STUB_SHA256:
        raise ValueError("unrecognized geometry stub")
    image = bytearray(stock)
    writes = []
    for address, target, old in (
        (FIRST_HOOK, CAVE, OLD_HOOK_WORDS[0]),
        (SECOND_HOOK, SECOND_ENTRY, OLD_HOOK_WORDS[1]),
    ):
        offset = address - LOAD
        before = struct.pack("<I", old)
        if image[offset:offset + 4] != before:
            raise ValueError(f"stock hook bytes differ at {address:#x}")
        after = struct.pack("<I", branch_word(address, target))
        image[offset:offset + 4] = after
        writes.append({"address": hex(address), "before_hex": before.hex(),
                       "after_hex": after.hex(), "target": hex(target)})
    offset = CAVE - LOAD
    if image[offset:offset + len(stub)] != bytes(len(stub)):
        raise ValueError("proposed decoded-image cave is not all zero")
    image[offset:offset + len(stub)] = stub
    writes.append({"address": hex(CAVE), "before_hex": bytes(len(stub)).hex(),
                   "after_hex": stub.hex(), "target": "two local stub entries"})
    allowed = set(range(CAVE - LOAD, CAVE - LOAD + len(stub)))
    allowed.update(range(FIRST_HOOK - LOAD, FIRST_HOOK - LOAD + 4))
    allowed.update(range(SECOND_HOOK - LOAD, SECOND_HOOK - LOAD + 4))
    changed = {i for i, (a, b) in enumerate(zip(stock, image)) if a != b}
    if not changed or not changed <= allowed or len(image) != len(stock):
        raise AssertionError("patch escaped three exact spans")
    return bytes(image), writes


def run_slice(image: bytes, aspect: int, width: int, which: str) -> int:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_IP, UC_ARM_REG_PC,
        UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5,
        UC_ARM_REG_R6,
    )

    if aspect not in ASPECTS or not 0 <= width <= 65535:
        raise ValueError("fixture outside bounded domain")
    if which not in ("first", "second"):
        raise ValueError("unknown geometry slice")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    for page in (0x01BA0000, 0x01ED6000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, image[page - LOAD:page - LOAD + 0x1000])
    uc.mem_map(CTX, 0x1000)
    uc.mem_write(CTX + 0x5BE, bytes([aspect]))
    uc.reg_write(UC_ARM_REG_R4, CTX)
    uc.reg_write(UC_ARM_REG_R5, width)
    uc.reg_write(UC_ARM_REG_R0, width)
    uc.reg_write(UC_ARM_REG_IP, aspect)
    if which == "first":
        start, end, result_register = 0x01ED6C5C, FIRST_END, UC_ARM_REG_R6
    else:
        start, end, result_register = 0x01ED6C98, SECOND_END, UC_ARM_REG_R2
    uc.emu_start(start, end, count=100, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != end:
        raise AssertionError(f"{which} slice did not reach expected join")
    return uc.reg_read(result_register)


def expected_height(width: int, aspect: int, patched: bool) -> int:
    if aspect == 2:
        return width * 9 // 16
    if aspect == 4 and patched and width > 0:
        return width * 24 // 65
    return width * 2 // 3


def verify(stock: bytes, stub: bytes) -> dict:
    patched, writes = patch_in_memory(stock, stub)
    rows = []
    for width in WIDTHS:
        for aspect in ASPECTS:
            for which in ("first", "second"):
                old = run_slice(stock, aspect, width, which)
                new = run_slice(patched, aspect, width, which)
                expected_old = expected_height(width, aspect, False)
                expected_new = expected_height(width, aspect, True)
                if (old, new) != (expected_old, expected_new):
                    raise AssertionError(
                        f"{width}/{aspect}/{which}: {(old, new)} != "
                        f"{(expected_old, expected_new)}"
                    )
                rows.append({"width": width, "aspect": aspect, "slice": which,
                             "stock_height": old, "patched_height": new})
    return {
        "scope": "in-memory exact-byte hook and original-ARM local slices; synthetic RAM only",
        "stock_secondary_sha256": sha(stock),
        "in_memory_secondary_sha256": sha(patched),
        "stub_sha256": sha(stub),
        "writes": writes,
        "vectors_passed": len(rows),
        "code4_example_L": [r for r in rows if r["width"] == 6240 and r["aspect"] == 4],
        "camera_safe": False,
        "cave_runtime_executable_verified": False,
        "normal_still_route_verified": False,
        "saved_raf_crop_verified": False,
    }


def main() -> None:
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    print(json.dumps(verify(stock, assemble_stub()), indent=2))


if __name__ == "__main__":
    main()
