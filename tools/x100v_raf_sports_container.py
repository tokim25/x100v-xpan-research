"""Offline writes that save a 65:24 RAF in the Sports Finder container (X100V 3.01).

Lightroom renders an X100V RAF only with 4182 or 3348 mosaic rows, and with
maker-note crop mode 2 it takes the picture area from the RAF's own
records (results/x100v-sports-finder-raf-form-lightroom-20261111.md). These
writes make a full-sensor 65:24 shot leave the camera in that form.

Three writes on top of a card that already tags the RAF 24:65:

- tools/x100v_raf_sports_container_stub.s in primary zero padding at
  0x0128fe80 (two stubs);
- a BL replacing `sub sp, fp, #0x18` at 0x01ed85c8, after the RAF-info
  builder returns, to the container stub;
- a BL replacing `mov r3, #0` at 0x01f54130, the default maker-note crop
  mode, to the crop-mode stub.

The container stub acts only when the RAF record is the full-sensor
layout with aspect 24:65 and the mosaic is the uncompressed full size. It
then advances the mosaic pointer 420 rows, sets the 3348-row length in the
object and the sensor-data directory, and writes 3348 rows and a
6240x2304 visible area at (519, 6) into the record.

The ARM check runs both stubs under a Cortex-A15 model on synthetic
memory. It is not a camera or firmware emulator, and the live buffer
layout, call order and camera behaviour are unobserved. The stub address
is also used by tools/x100v_review_crop.py, so the two cannot share a card.
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
CROP_MODE_OFFSET = 0xF4            # second stub inside the assembled text
CONTAINER_HOOK = 0x01ED85C8        # sub sp, fp, #0x18
CROP_MODE_HOOK = 0x01F54130        # mov r3, #0
STOCK = {CONTAINER_HOOK: 0xE24BD018, CROP_MODE_HOOK: 0xE3A03000}

ROW_BYTES = 6384 * 2
FULL_ROWS, CONTAINER_ROWS, START_ROW = 4182, 3348, 420
FULL_LENGTH = ROW_BYTES * FULL_ROWS
RECORD, DIRECTORY = 0x228, 0xAE98   # offsets in the per-shot object
STOCK_RECORD = struct.pack("<10H", 4182, 6384, 13, 6, 4160, 6240, 6240, 4160, 4160, 6240)
NEW_RECORD = struct.pack("<10H", 3348, 6384, 519, 6, 2304, 6240, 6240, 2304, 2304, 6240)


def writes_for(partitions: dict[int, bytes], stub: bytes) -> list[dict]:
    if len(stub) != CROP_MODE_OFFSET + 16:
        raise ValueError("unexpected stub length")
    writes = [stub_write(partitions, STUB_ADDRESS, stub, "raf-sports-container-stubs")]
    for site, target, field in ((CONTAINER_HOOK, STUB_ADDRESS, "raf-sports-container-hook"),
                                (CROP_MODE_HOOK, STUB_ADDRESS + CROP_MODE_OFFSET, "raf-crop-mode-hook")):
        at = site - LOADS[7]
        if struct.unpack_from("<I", partitions[7], at)[0] != STOCK[site]:
            raise ValueError(f"{site:#x} is not the stock instruction")
        writes.append({"field": field, "partition": 7, "address": site, "partition_offset": at,
                       "before_hex": struct.pack("<I", STOCK[site]).hex(),
                       "after_hex": struct.pack("<I", bl(site, target)).hex()})
    return writes


def _machine(stub: bytes):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_A15)
    uc.mem_map(STUB_ADDRESS & ~0xFFF, 0x2000)
    uc.mem_write(STUB_ADDRESS, stub)
    uc.mem_map(0x30000000, 0x20000)
    return uc, A


def stock_object(aspect=(24, 65), length=FULL_LENGTH, record=STOCK_RECORD, rows=FULL_ROWS) -> bytes:
    """A synthetic per-shot object holding only the fields the stub reads."""
    obj = bytearray(0xB000)
    struct.pack_into("<II", obj, 0x8C, 0x50000000, length)
    struct.pack_into("<I", obj, 0x1D4, length + 0x800)
    obj[RECORD:RECORD + 20] = record
    struct.pack_into("<2H", obj, RECORD + 0x14, *aspect)
    struct.pack_into("<2H", obj, RECORD + 0x20, 4160, 6240)
    struct.pack_into("<I", obj, DIRECTORY + 0x28, 6384)
    struct.pack_into("<I", obj, DIRECTORY + 0x34, rows)
    struct.pack_into("<I", obj, DIRECTORY + 0x7C, length)
    return bytes(obj)


def run_container(stub: bytes, obj: bytes) -> dict:
    uc, A = _machine(stub)
    base, ret, frame = 0x30004000, 0x30000000, 0x30003000
    uc.mem_write(base, obj)
    regs = {A.UC_ARM_REG_R0: 0x1234, A.UC_ARM_REG_R4: base, A.UC_ARM_REG_FP: frame,
            A.UC_ARM_REG_SP: frame - 0x40, A.UC_ARM_REG_LR: ret}
    for r, v in regs.items():
        uc.reg_write(r, v)
    uc.emu_start(STUB_ADDRESS, ret, count=200)
    return {"object": bytes(uc.mem_read(base, len(obj))),
            "r0_kept": uc.reg_read(A.UC_ARM_REG_R0) == 0x1234,
            "sp_is_fp_minus_0x18": uc.reg_read(A.UC_ARM_REG_SP) == frame - 0x18,
            "r4_kept": uc.reg_read(A.UC_ARM_REG_R4) == base}


def run_crop_mode(stub: bytes, aspect: int) -> int:
    uc, A = _machine(stub)
    ctx, ret = 0x30004000, 0x30000000
    uc.mem_write(ctx + 0x5BE, bytes([aspect]))
    uc.reg_write(A.UC_ARM_REG_SL, ctx)
    uc.reg_write(A.UC_ARM_REG_R3, 0xDEAD)
    uc.reg_write(A.UC_ARM_REG_LR, ret)
    uc.emu_start(STUB_ADDRESS + CROP_MODE_OFFSET, ret, count=20)
    return uc.reg_read(A.UC_ARM_REG_R3)


def expected_object(obj: bytes) -> bytes:
    """The reshaped object, written independently of the stub."""
    out = bytearray(obj)
    new_length = ROW_BYTES * CONTAINER_ROWS
    struct.pack_into("<II", out, 0x8C, 0x50000000 + ROW_BYTES * START_ROW, new_length)
    struct.pack_into("<I", out, 0x1D4, new_length + 0x800)
    out[RECORD:RECORD + 20] = NEW_RECORD
    struct.pack_into("<2H", out, RECORD + 0x20, 2304, 6240)
    struct.pack_into("<I", out, DIRECTORY + 0x34, CONTAINER_ROWS)
    struct.pack_into("<I", out, DIRECTORY + 0x7C, new_length)
    return bytes(out)


def arm_check(stub: bytes) -> dict:
    good = stock_object()
    hit = run_container(stub, good)
    untouched = {
        "aspect 9:16": stock_object(aspect=(9, 16)),
        "aspect 2:3": stock_object(aspect=(2, 3)),
        "compressed length": stock_object(length=FULL_LENGTH - 4096),
        "sports finder rows": stock_object(rows=3348),
        "origin differs": stock_object(record=STOCK_RECORD[:4] + struct.pack("<2H", 9, 630) + STOCK_RECORD[8:]),
        "visible differs": stock_object(record=STOCK_RECORD[:8] + struct.pack("<2H", 3328, 4992) + STOCK_RECORD[12:]),
        "mosaic differs": stock_object(record=struct.pack("<2H", 3348, 6384) + STOCK_RECORD[4:]),
    }
    skipped = {}
    for name, obj in untouched.items():
        r = run_container(stub, obj)
        skipped[name] = r["object"] == obj and r["r0_kept"] and r["sp_is_fp_minus_0x18"]
    modes = {aspect: run_crop_mode(stub, aspect) for aspect in range(8)}
    return {
        "reshaped_as_expected": hit["object"] == expected_object(good),
        "registers_kept": hit["r0_kept"] and hit["sp_is_fp_minus_0x18"] and hit["r4_kept"],
        "left_alone": skipped,
        "crop_mode_by_aspect": modes,
        "all_as_expected": hit["object"] == expected_object(good) and hit["r0_kept"]
        and hit["sp_is_fp_minus_0x18"] and hit["r4_kept"] and all(skipped.values())
        and modes == {a: (2 if a == 2 else 0) for a in range(8)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--stub-object", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    stub = read_elf_text(args.stub_object)
    writes = writes_for(stock_partitions(raw), stub)
    check = arm_check(stub)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "manifest.json").write_text(json.dumps({
        "kind": "65:24 RAF in the Sports Finder container; stubs + 2 BLs; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(raw).hexdigest(),
        "stub_source": "tools/x100v_raf_sports_container_stub.s",
        "stub_sha256": hashlib.sha256(stub).hexdigest(),
        "needs": "a base card that writes RAF aspect 24:65 for aspect code 2 (card 5i or later)",
        "write_count": len(writes), "writes": writes}, indent=2) + "\n")
    (args.output_dir / "arm-check.json").write_text(json.dumps(check, indent=2) + "\n")
    print(json.dumps(check, indent=2))


if __name__ == "__main__":
    main()
