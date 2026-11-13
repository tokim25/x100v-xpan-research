"""Offline probe: every caller of the window fit gets 65:24 for aspect code 2 (X100V 3.01).

The primary routine 0x0115f0a4(width, height, aspect, &rect) fits a
window to an aspect code through the ratio helper 0x0115eee0, which holds
9:16 for code 2. It has nine callers. Card 5k redirected the three
post-shot review callers to tools/x100v_review_crop_stub.s, which runs the
original fit and then, for code 2 only, shrinks the height to
width * 24 / 65 rounded down to a multiple of 4.

The OVF's solid bright frame matches this arithmetic: the 3:2 finder
window is 832x554 and its 16:9 version is 832x468, which is 832 * 9 / 16.
So this probe sends all nine callers through the same stub, placed at
0x0128ff88 after card 6a's stubs. The capture-side callers of the ratio
helper do not go through the window fit and are left alone.

Static reading plus an ARM-model run of the stub. Which caller draws what
is not established, and no display behaviour is claimed.
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
from tools.x100v_review_crop import FIT, run

STUB_ADDRESS = 0x0128FF88
STUB_BYTES = 104
SITES = (0x0115F2E4, 0x01F0EA1C, 0x01F0FA18, 0x01F17178, 0x01F17500,
         0x01F17978, 0x01F17ED4, 0x01F18DA0, 0x01F19A80)


def partition_of(address: int) -> int:
    return 7 if address >= LOADS[7] else 6


def writes_for(partitions: dict[int, bytes], stub: bytes) -> list[dict]:
    if len(stub) != STUB_BYTES or struct.unpack("<I", stub[-4:])[0] != FIT:
        raise ValueError("stub is not the window-fit wrapper")
    if STUB_ADDRESS + len(stub) > 0x01290000:
        raise ValueError("stub does not fit the zero padding")
    writes = [stub_write(partitions, STUB_ADDRESS, stub, "window-fit-6524-stub")]
    for site in SITES:
        part = partition_of(site)
        at = site - LOADS[part]
        if struct.unpack_from("<I", partitions[part], at)[0] != bl(site, FIT):
            raise ValueError(f"{site:#x} is not a stock call to the window fit")
        writes.append({"field": f"window-fit-hook-{site:08x}", "partition": part, "address": site,
                       "partition_offset": at, "before_hex": struct.pack("<I", bl(site, FIT)).hex(),
                       "after_hex": struct.pack("<I", bl(site, STUB_ADDRESS)).hex()})
    return writes


def all_callers(partitions: dict[int, bytes]) -> list[int]:
    """Every BL to the window fit in the two decoded partitions."""
    found = []
    for part in (6, 7):
        words = struct.unpack_from(f"<{len(partitions[part]) // 4}I", partitions[part])
        for i, word in enumerate(words):
            address = LOADS[part] + 4 * i
            if word >> 24 == 0xEB and abs(FIT - address) < (1 << 25) and word == bl(address, FIT):
                found.append(address)
    return found


def arm_check(stock: dict[int, bytes], stub: bytes) -> dict:
    primary = bytearray(stock[6])
    at = STUB_ADDRESS - LOADS[6]
    primary[at:at + len(stub)] = stub
    rows = []
    for width, height in ((832, 554), (1280, 852), (900, 600), (640, 480)):
        for aspect in range(8):
            before = run(stock[6], FIT, width, height, aspect)
            after = run(bytes(primary), STUB_ADDRESS, width, height, aspect)
            expect = list(before["rect"])
            if aspect == 2:
                new_h = (expect[0] * 24 // 65) & ~3
                if new_h < expect[1]:
                    extra = expect[1] - new_h
                    expect[1], expect[2], expect[3] = new_h, expect[2] + extra // 2, expect[3] + extra - extra // 2
            rows.append({"base": [width, height], "aspect": aspect, "stock": before["rect"],
                         "patched": after["rect"],
                         "as_expected": after["rect"] == expect and after["callee_saved_kept"]})
    return {"rows": rows, "all_as_expected": all(r["as_expected"] for r in rows)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--stub-object", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    stock = stock_partitions(raw)
    stub = read_elf_text(args.stub_object)
    if sorted(all_callers(stock)) != sorted(SITES):
        raise SystemExit("the window fit's callers differ from the pinned nine")
    writes = writes_for(stock, stub)
    check = arm_check(stock, stub)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "manifest.json").write_text(json.dumps({
        "kind": "all nine window-fit callers return 65:24 for aspect 2; stub + 9 BLs; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "stub_source": "tools/x100v_review_crop_stub.s", "stub_sha256": hashlib.sha256(stub).hexdigest(),
        "write_count": len(writes), "writes": writes}, indent=2) + "\n")
    (args.output_dir / "arm-check.json").write_text(json.dumps(check, indent=2) + "\n")
    print("all_as_expected:", check["all_as_expected"])
    for r in check["rows"]:
        if r["aspect"] in (1, 2):
            print(r["base"], "aspect", r["aspect"], r["stock"], "->", r["patched"])


if __name__ == "__main__":
    main()
