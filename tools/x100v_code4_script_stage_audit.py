"""Audit crop/compress/save opcode order in all X100V Recbf byte programs.

This reads stored scripts, not scheduled or executed camera commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_capture_geometry_probe import CANDIDATE_SECONDARY_SHA256
from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_update_package import STOCK_SHA256, read_secondary

TABLE = 0x022DF148
COUNT = 42
SENTINEL = 0x2A
CROP = 0x15
COMPRESS = 0x27
SAVE = (0x3C, 0x3D, 0x3E)
END = 0x9E
LOAD = SOURCES["x100v_3_01"]["secondary_load"]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rows_for(secondary: bytes) -> list[dict]:
    rows = []
    for index in range(COUNT + 1):
        at = TABLE - LOAD + 8 * index
        key, pointer = struct.unpack_from("<II", secondary, at)
        if key != index:
            raise AssertionError(f"unexpected script-table key {key:#x} at row {index}")
        if index == COUNT:
            if key != SENTINEL:
                raise AssertionError("script sentinel is not key 0x2a")
            break
        if not LOAD <= pointer < LOAD + len(secondary):
            raise AssertionError(f"script pointer out of image: {pointer:#x}")
        start = pointer - LOAD
        try:
            end = secondary.index(END, start, start + 256)
        except ValueError as exc:
            raise AssertionError(f"script {index} has no bounded terminator") from exc
        opcodes = list(secondary[start:end + 1])
        crop = [i for i, byte in enumerate(opcodes[:-1]) if byte == CROP]
        compress = [i for i, byte in enumerate(opcodes[:-1]) if byte == COMPRESS]
        save = [i for i, byte in enumerate(opcodes[:-1]) if byte in SAVE]
        rows.append({
            "key": index,
            "address": hex(pointer),
            "length": len(opcodes),
            "opcodes_hex": bytes(opcodes).hex(),
            "crop_positions": crop,
            "compress_positions": compress,
            "save_positions": save,
            "crop_before_compress": any(c < x for c in crop for x in compress),
            "compress_before_save": any(x < s for x in compress for s in save),
            "crop_compress_save_in_order": any(c < x < s for c in crop for x in compress for s in save),
        })
    return rows


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if sha(stock_dat) != STOCK_SHA256 or sha(candidate_dat) != CANDIDATE_DAT_SHA256:
        raise ValueError("DAT identity mismatch")
    stock = read_secondary(stock_dat)[1]
    candidate = read_secondary(candidate_dat)[1]
    if sha(stock) != SOURCES["x100v_3_01"]["secondary_sha256"] or \
            sha(candidate) != CANDIDATE_SECONDARY_SHA256:
        raise ValueError("secondary partition identity mismatch")
    stock_rows = rows_for(stock)
    candidate_rows = rows_for(candidate)
    if stock_rows != candidate_rows:
        raise AssertionError("merged candidate changes a stored Recbf byte program")
    if len(stock_rows) != COUNT:
        raise AssertionError("unexpected script count")
    by_key = {row["key"]: row for row in stock_rows}
    if not (by_key[0x23]["crop_before_compress"] and
            not by_key[0x23]["save_positions"] and
            by_key[4]["compress_before_save"] and
            not by_key[4]["crop_positions"]):
        raise AssertionError("pinned mode-35/mode-4 stage ordering changed")
    return {
        "scope": "all 42 selectable stored byte programs; no runtime scheduling",
        "stock_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "stock_secondary_sha256": sha(stock),
        "candidate_secondary_sha256": sha(candidate),
        "sentinel_key": SENTINEL,
        "rows": stock_rows,
        "crop_keys": [r["key"] for r in stock_rows if r["crop_positions"]],
        "crop_before_compress_keys": [r["key"] for r in stock_rows if r["crop_before_compress"]],
        "compress_before_save_keys": [r["key"] for r in stock_rows if r["compress_before_save"]],
        "crop_compress_save_keys": [r["key"] for r in stock_rows if r["crop_compress_save_in_order"]],
        "same_shot_cross_program_order_verified": False,
        "normal_still_program_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.stock.read_bytes(), args.candidate.read_bytes())
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(f"{len(result['rows'])} scripts checked; "
          f"{len(result['crop_compress_save_keys'])} contain crop→compress→save")


if __name__ == "__main__":
    main()
