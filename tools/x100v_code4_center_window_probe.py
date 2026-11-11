"""Run the stock centered-descriptor ARM slice against the merged code-4 tables.

This starts after the caller's eligibility gates and stops before its return.
It is synthetic RAM execution, not a still-capture or camera test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_capture_geometry_probe import (
    CANDIDATE_SECONDARY_SHA256,
    FULL_3_2,
    LEGACY_16_9,
    SIZES,
)
from tools.x100v_code4_merged_preview_probe import (
    CANDIDATE_DAT_SHA256,
    CANDIDATE_PRIMARY_SHA256,
)
from tools.x100v_update_package import STOCK_SHA256, read_primary, read_secondary

START = 0x01EDEAA0
END = 0x01EDEAF8  # Exclusive: the following instruction branches away.
CTX = 0x33000000
DESC = 0x34000000
STACK = 0x35000000
BASE = 0x40000000

# Independent reference vectors for same-width source descriptors.  Offsets
# were calculated from the centered-window geometry, not from Unicorn output.
EXPECTED_OFFSETS = {
    "full_3_2": (11640832, 5877760, 2969600),
    "legacy_16_9": (7576576, 3834880, 1945600),
    "already_65_24": (0, 0, 0),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_slice(primary: bytes, secondary: bytes, level: int, aspect: int,
              source_width: int, source_height: int, stride: int) -> dict:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_FP, UC_ARM_REG_PC, UC_ARM_REG_R5, UC_ARM_REG_R10,
        UC_ARM_REG_SP,
    )

    load6 = SOURCES["x100v_3_01"]["primary_load"]
    load7 = SOURCES["x100v_3_01"]["secondary_load"]
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for address, length, data, base in (
        (0x0115F000, 0x1000, primary, load6),
        (0x014A7000, 0x1000, primary, load6),
        (0x01EDE000, 0x1000, secondary, load7),
    ):
        uc.mem_map(address, length)
        uc.mem_write(address, data[address - base:address - base + length])
    for address in (CTX, DESC, STACK):
        uc.mem_map(address, 0x1000)

    uc.mem_write(CTX + 0x5B0, bytes([25]))
    uc.mem_write(CTX + 0x5BE, bytes([aspect]))
    uc.mem_write(CTX + 0xA2A, bytes([level]))
    uc.mem_write(DESC + 4, struct.pack("<I", BASE))
    uc.mem_write(DESC + 8, struct.pack("<I", source_height * stride))
    uc.mem_write(DESC + 12, struct.pack("<I", stride))
    uc.mem_write(DESC + 16, struct.pack("<I", source_width * 2))
    uc.mem_write(DESC + 20, struct.pack("<I", source_height))
    uc.mem_write(STACK + 0x804, struct.pack("<I", 0))  # optional copy absent
    uc.reg_write(UC_ARM_REG_R5, CTX)
    uc.reg_write(UC_ARM_REG_R10, DESC)  # sl
    uc.reg_write(UC_ARM_REG_FP, STACK + 0x800)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x600)
    uc.emu_start(START, END, count=100)
    if uc.reg_read(UC_ARM_REG_PC) != END:
        raise AssertionError("center-window ARM slice did not reach its end")
    base, area, got_stride, width_bytes, height = struct.unpack(
        "<5I", uc.mem_read(DESC + 4, 20)
    )
    return {
        "base_advance": (base - BASE) & 0xFFFFFFFF,
        "area_bytes": area,
        "stride": got_stride,
        "width_pixels": width_bytes // 2,
        "height": height,
    }


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
    if secondary[START - source["secondary_load"]:END - source["secondary_load"]] != \
            stock_secondary[START - source["secondary_load"]:END - source["secondary_load"]]:
        raise AssertionError("center-window ARM instructions changed in candidate")

    rows = []
    for level, ((width, target_height), legacy_height, full_height) in enumerate(
        zip(SIZES, LEGACY_16_9, FULL_3_2)
    ):
        stride = (2 * width + 255) & ~255
        for label, input_height in (
            ("full_3_2", full_height),
            ("legacy_16_9", legacy_height),
            ("already_65_24", target_height),
        ):
            actual = run_slice(primary, secondary, level, 4, width, input_height, stride)
            expected = {
                "base_advance": EXPECTED_OFFSETS[label][level],
                "area_bytes": target_height * stride,
                "stride": stride,
                "width_pixels": width,
                "height": target_height,
            }
            if actual != expected:
                raise AssertionError(f"{label}/{level}: {actual} != {expected}")
            rows.append({"level": level, "input": label, "source_height": input_height,
                         "expected": expected, "actual": actual})
    return {
        "scope": "original ARM centered-window slice, synthetic context and descriptors",
        "stock_update_sha256": STOCK_SHA256,
        "candidate_update_sha256": CANDIDATE_DAT_SHA256,
        "candidate_primary_sha256": CANDIDATE_PRIMARY_SHA256,
        "candidate_secondary_sha256": CANDIDATE_SECONDARY_SHA256,
        "entry": hex(START),
        "end_exclusive": hex(END),
        "rows": rows,
        "caller_eligibility_verified": False,
        "live_still_route_verified": False,
        "saved_file_verified": False,
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
    print(f"{len(result['rows'])} centered-window ARM fixtures passed")


if __name__ == "__main__":
    main()
