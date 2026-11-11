"""Bounded original-ARM geometry coverage for the offline merged code-4 image.

Exercises the actual decoded package's primary width/height lookups and
secondary mode-0 encoder-block fill with synthetic descriptors. It does not
establish that a still shot takes any tested route or that an encoder saves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256,
    CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_jpeg_crop import run_block
from tools.x100v_update_package import STOCK_SHA256, read_primary, read_secondary

CANDIDATE_SECONDARY_SHA256 = "048db796bb472af27c8a43b1fbef5122ec46267641b5dfc18e3f43b69dd9b78a"
WIDTH_ENTRY = 0x0115F9F4
HEIGHT_ENTRY = 0x0115FABC
WIDTH_TABLE = 0x014A72DC
HEIGHT_TABLE = 0x014A75C0
SIZES = ((6240, 2304), (4416, 1632), (3120, 1152))
LEGACY_16_9 = (3512, 2488, 1760)
FULL_3_2 = (4160, 2944, 2080)
PREVIEW_HEIGHT = 2944


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lookup_arm(primary: bytes, entry: int, size_level: int, aspect: int) -> int:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
    )

    load = SOURCES["x100v_3_01"]["primary_load"]
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, length in ((0x0115F000, 0x1000), (0x014A7000, 0x1000)):
        uc.mem_map(address, length)
        uc.mem_write(address, primary[address - load:address - load + length])
    uc.mem_map(0x33000000, 0x1000)
    uc.mem_map(0x34000000, 0x1000)
    uc.reg_write(UC_ARM_REG_R0, size_level)
    uc.reg_write(UC_ARM_REG_R1, aspect)
    uc.reg_write(UC_ARM_REG_SP, 0x33000800)
    uc.reg_write(UC_ARM_REG_LR, 0x34000000)
    uc.emu_start(entry, 0x34000000, count=60)
    if uc.reg_read(UC_ARM_REG_PC) != 0x34000000:
        raise RuntimeError(f"lookup did not return: {entry:#x}")
    return uc.reg_read(UC_ARM_REG_R0)


def verify(stock_dat: bytes, candidate_dat: bytes) -> dict:
    if sha(stock_dat) != STOCK_SHA256 or sha(candidate_dat) != CANDIDATE_DAT_SHA256:
        raise ValueError("stock/candidate DAT identity mismatch")
    stock_primary = read_primary(stock_dat)[1]
    stock_secondary = read_secondary(stock_dat)[1]
    primary = read_primary(candidate_dat)[1]
    secondary = read_secondary(candidate_dat)[1]
    source = SOURCES["x100v_3_01"]
    if (sha(stock_primary) != source["primary_sha256"] or
            sha(stock_secondary) != source["secondary_sha256"] or
            sha(primary) != CANDIDATE_PRIMARY_SHA256 or
            sha(secondary) != CANDIDATE_SECONDARY_SHA256):
        raise ValueError("decoded partition identity mismatch")

    lookup_rows = []
    block_rows = []
    stock_parts = {6: stock_primary, 7: stock_secondary}
    candidate_parts = {6: primary, 7: secondary}
    for level, ((width, height), legacy_height, full_height) in enumerate(
        zip(SIZES, LEGACY_16_9, FULL_3_2)
    ):
        row = {"level": level, "expected_code4": [width, height]}
        for label, entry, table, expected in (
            ("width", WIDTH_ENTRY, WIDTH_TABLE, width),
            ("height", HEIGHT_ENTRY, HEIGHT_TABLE, height),
        ):
            cell = table + 4 * (5 * level + 4)
            at = cell - source["primary_load"]
            if struct.unpack_from("<I", primary, at)[0] != expected:
                raise AssertionError(f"candidate {label} table cell differs at {cell:#x}")
            if lookup_arm(stock_primary, entry, level, 4) != 0:
                raise AssertionError(f"stock code-4 {label} lookup not zero")
            if lookup_arm(primary, entry, level, 4) != expected:
                raise AssertionError(f"candidate code-4 {label} lookup differs")
            if lookup_arm(primary, entry, level, 2) != lookup_arm(stock_primary, entry, level, 2):
                raise AssertionError(f"code-2 {label} lookup changed")
        lookup_rows.append(row)

        for case, source_height, expected_height in (
            ("already_65_24", height, height),
            ("legacy_16_9", legacy_height, height),
            ("full_3_2", full_height, height if level == 1 else full_height),
        ):
            width_bytes = 2 * width
            stride = (width_bytes + 255) & ~255
            out = run_block(candidate_parts, width_bytes, source_height, stride,
                            0x40000000, aspect=4)
            if out["encoder_width_px"] != width or out["encoder_height"] != expected_height:
                raise AssertionError(f"mode-0 output geometry differs: {level}/{case}: {out}")
            if not out["descriptor_unchanged"] or not out["callee_saved_kept"]:
                raise AssertionError(f"unexpected descriptor/register change: {level}/{case}")
            block_rows.append({"level": level, "input": case,
                               "source_height": source_height,
                               "encoder_height": out["encoder_height"],
                               "encoder_base_advance": out["encoder_base"] - 0x40000000,
                               "stub_ran": out["stub_ran"]})

        old = run_block(stock_parts, 2 * width, legacy_height,
                        (2 * width + 255) & ~255, 0x40000000, aspect=2)
        preserved = run_block(candidate_parts, 2 * width, legacy_height,
                              (2 * width + 255) & ~255, 0x40000000, aspect=2)
        if old != {**preserved, "stub_ran": False}:
            raise AssertionError(f"code-2 compression changed for level {level}")

    preview = run_block(candidate_parts, 8832, PREVIEW_HEIGHT,
                        (8832 + 255) & ~255, 0x40000000, aspect=4)
    if preview["encoder_width_px"] != 4416 or preview["encoder_height"] != 1632:
        raise AssertionError("code-4 3:2 preview guard differs")
    return {
        "scope": "hash-pinned decoded offline package; original ARM lookups and mode-0 block; synthetic RAM",
        "source_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "candidate_secondary_sha256": CANDIDATE_SECONDARY_SHA256,
        "lookup_rows": lookup_rows,
        "block_rows": block_rows,
        "preview_3_2_input_encoder_height": preview["encoder_height"],
        "medium_full_3_2_matches_preview_guard": True,
        "normal_still_route_verified": False,
        "live_encoder_source_geometry_verified": False,
        "jpeg_or_raf_file_verified": False,
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
    print(f"{len(result['lookup_rows'])} lookup rows and "
          f"{len(result['block_rows'])} mode-0 cases passed; no live route verified")


if __name__ == "__main__":
    main()
