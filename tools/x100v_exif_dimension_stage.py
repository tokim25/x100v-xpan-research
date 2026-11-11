"""Bounded stock ARM dimension staging, not EXIF serialization or a patch.

Executes only 0x1f58194..0x1f581cc in the metadata builder. The alternate
branch stops before its lookup; camera mode selection is not established.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_preview_cache_export_emulator import load_images
from tools.fuji_xpan_validation import SOURCES

ENTRY, END, ALTERNATE = 0x1F58194, 0x1F581CC, 0x1F58480
RANGE_SHA256 = "4c5d9bb961c6e460c7c27f4f0d010606ca415081d6231efd7288437cb7147f7d"
CONTEXT, DEST = 0x10000000, 0x20000000
# Explicit stock dimensions, including non-16:9 controls.
VECTORS = ((6240, 3512), (4416, 2488), (3120, 1760),
           (6240, 4160), (4416, 2944), (3120, 2080))


def verify_secondary(secondary: bytes) -> bytes:
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("unrecognized secondary image")
    code = secondary[ENTRY-source["secondary_load"]:END-source["secondary_load"]]
    if hashlib.sha256(code).hexdigest() != RANGE_SHA256:
        raise ValueError("dimension staging bytes changed")
    return code


def execute(secondary: bytes, width: int, height: int, flag: int = 0) -> dict:
    code = verify_secondary(secondary)
    if any(type(v) is not int or not 0 <= v <= 0xffffffff for v in (width, height)):
        raise ValueError("dimensions must be uint32")
    if type(flag) is not int or not 0 <= flag <= 255:
        raise ValueError("flag must be a byte")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_PC
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, code)
    uc.mem_map(CONTEXT, 0x4000)
    uc.mem_map(DEST, 4096)
    context = bytearray(b"\xa5" * 0x4000)
    context[0x3030] = flag
    struct.pack_into("<II", context, 0x30f8, height, width)
    uc.mem_write(CONTEXT, bytes(context))
    initial = b"\xcc" * 4096
    uc.mem_write(DEST, initial)
    uc.reg_write(UC_ARM_REG_R4, CONTEXT)
    uc.reg_write(UC_ARM_REG_R6, DEST)
    writes, visited = [], []

    def instruction(machine, address, size, _):
        if address == ALTERNATE:
            machine.emu_stop()
            return
        if not ENTRY <= address < END:
            raise AssertionError(f"escaped staging fragment: {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if (address, size) not in ((DEST+0x2a0, 4), (DEST+0x2a4, 4)):
            raise AssertionError(f"unexpected write: {address:#x}")
        writes.append([address-DEST, size, value])

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(ENTRY, END, count=40, timeout=1000000)
    expected = bytearray(initial)
    if flag == 0:
        struct.pack_into("<II", expected, 0x2a0, width, height)
    stop = ALTERNATE if flag else END
    if uc.reg_read(UC_ARM_REG_PC) != stop or bytes(uc.mem_read(DEST,4096)) != bytes(expected):
        raise AssertionError("wrong staging result or stop boundary")
    if bytes(uc.mem_read(CONTEXT, 0x4000)) != bytes(context):
        raise AssertionError("input context modified")
    if uc.reg_read(UC_ARM_REG_R4) != CONTEXT or uc.reg_read(UC_ARM_REG_R6) != DEST:
        raise AssertionError("base register modified")
    return dict(width=width, height=height, flag=flag, stop=hex(stop),
                writes=writes, instructions=len(visited), guards_preserved=True,
                serialization_executed=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    _, secondary = load_images(args.update)
    import unicorn
    rows = [execute(secondary, w, h) for w,h in VECTORS]
    rows += [execute(secondary, 6240, 3512, flag) for flag in (1, 2, 255)]
    report = dict(scope="Stock metadata dimension staging only; no tag serialization, patch or camera execution",
                  secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                  fragment_sha256=RANGE_SHA256, unicorn_version=unicorn.__version__,
                  entry=hex(ENTRY), cases=rows)
    with args.report.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(f"{len(rows)} bounded stock ARM cases passed")


if __name__ == "__main__":
    main()
