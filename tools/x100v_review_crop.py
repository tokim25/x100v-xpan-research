"""Offline writes that crop the post-shot review window to 65:24 for the 16:9 setting.

The three still-review routines (0x01f178e8, 0x01f18d10, 0x01f19a00, named
"...OperateDispImageProc[EyeLcdPostview]" by their debug strings) call the
window fit 0x0115f0a4(width, height, aspect, &rect). Each call is redirected
to tools/x100v_review_crop_stub.s at 0x0128fe80, which calls the original fit
and, for aspect 2 only, shrinks the window to 65:24 inside the same margins.
The ARM check runs the stub and the original fit under a Cortex-A15 model
with synthetic stack memory; it is not a camera or firmware emulator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import LOADS, stock_partitions
from tools.x100v_jpeg_crop import bl, stub_write
from tools.x100v_preview_alias_candidate import read_elf_text

STUB_ADDRESS = 0x0128FE80
FIT = 0x0115F0A4
SITES = (0x01F17978, 0x01F18DA0, 0x01F19A80)


def writes_for(partitions: dict[int, bytes], stub: bytes) -> list[dict]:
    if struct.unpack("<I", stub[-4:])[0] != FIT:
        raise ValueError("stub does not call the window fit")
    writes = [stub_write(partitions, STUB_ADDRESS, stub, "review-crop-stub")]
    for site in SITES:
        at = site - LOADS[7]
        if struct.unpack_from("<I", partitions[7], at)[0] != bl(site, FIT):
            raise ValueError(f"{site:#x} is not the stock call to the window fit")
        writes.append({"field": f"review-crop-hook-{site:08x}", "partition": 7, "address": site,
                       "partition_offset": at, "before_hex": struct.pack("<I", bl(site, FIT)).hex(),
                       "after_hex": struct.pack("<I", bl(site, STUB_ADDRESS)).hex()})
    return writes


def run(primary: bytes, entry: int, width: int, height: int, aspect: int) -> dict:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_A15)
    base = LOADS[6] & ~0xFFF
    uc.mem_map(base, (len(primary) + (LOADS[6] - base) + 0xFFF) & ~0xFFF)
    uc.mem_write(LOADS[6], primary)
    uc.mem_map(0x30000000, 0x10000)
    rect, ret = 0x30001000, 0x30000000
    uc.mem_write(rect, bytes(24))
    regs = {A.UC_ARM_REG_R0: width, A.UC_ARM_REG_R1: height, A.UC_ARM_REG_R2: aspect, A.UC_ARM_REG_R3: rect,
            A.UC_ARM_REG_SP: 0x3000F000, A.UC_ARM_REG_LR: ret}
    saved = list(range(A.UC_ARM_REG_R4, A.UC_ARM_REG_R4 + 7))
    for i, r in enumerate(saved):
        regs[r] = 0x4400 + i
    for r, v in regs.items():
        uc.reg_write(r, v)
    uc.emu_start(entry, ret, count=4000)
    return {"rect": list(struct.unpack("<6I", uc.mem_read(rect, 24))),
            "callee_saved_kept": [uc.reg_read(r) for r in saved] == [0x4400 + i for i in range(7)]
            and uc.reg_read(A.UC_ARM_REG_SP) == 0x3000F000}


def arm_check(stock: dict[int, bytes], writes: list[dict]) -> dict:
    primary = bytearray(stock[6])
    for w in writes:
        if w["partition"] == 6:
            new = bytes.fromhex(w["after_hex"])
            primary[w["partition_offset"]:w["partition_offset"] + len(new)] = new
    rows = []
    for width, height in ((640, 480), (1280, 960), (900, 600)):
        for aspect in range(0, 8):
            before = run(stock[6], FIT, width, height, aspect)
            after = run(bytes(primary), STUB_ADDRESS, width, height, aspect)
            expect = list(before["rect"])
            if aspect == 2:
                w, h = expect[0], expect[1]
                new_h = (w * 24 // 65) & ~3
                if new_h < h:
                    extra = h - new_h
                    expect[1], expect[2], expect[3] = new_h, expect[2] + extra // 2, expect[3] + extra - extra // 2
            rows.append({"base": [width, height], "aspect": aspect, "stock": before["rect"], "patched": after["rect"],
                         "as_expected": after["rect"] == expect and after["callee_saved_kept"]})
    return {"rows": rows, "all_as_expected": all(r["as_expected"] for r in rows)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--stub-object", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    stock = stock_partitions(args.stock.read_bytes())
    stub = read_elf_text(args.stub_object)
    writes = writes_for(stock, stub)
    check = arm_check(stock, writes)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "manifest.json").write_text(json.dumps({
        "kind": "post-shot review window cropped to 65:24 for aspect 2; stub + 3 BLs; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(args.stock.read_bytes()).hexdigest(),
        "stub_source": "tools/x100v_review_crop_stub.s", "stub_sha256": hashlib.sha256(stub).hexdigest(),
        "write_count": len(writes), "writes": writes}, indent=2) + "\n")
    (args.output_dir / "arm-check.json").write_text(json.dumps(check, indent=2) + "\n")
    print("all_as_expected:", check["all_as_expected"])
    for r in check["rows"]:
        if r["base"] == [640, 480] or not r["as_expected"]:
            print(r["base"], "aspect", r["aspect"], r["stock"], "->", r["patched"], "ok" if r["as_expected"] else "MISMATCH")


if __name__ == "__main__":
    main()
