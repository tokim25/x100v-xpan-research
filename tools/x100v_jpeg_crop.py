"""Build and check the encode-time 65:24 crop for 16:9 still JPEGs (X100V 3.01).

Two writes: the assembled stub (tools/x100v_jpeg_crop_stub.s) into primary
zero padding at 0x0128fc80, and a BL replacing `str r1, [r3, #0x14]` at
secondary 0x01edc4f0 in the compression setup. Every 16:9 size table stays
stock; only the main image's encoder height and base address change.

The encoder setup in the overlay (0x03db088c) looks the image size up in a
table at 0x03db1498 and spins forever on a size it does not know, which card
5a hit. With --encoder-table the three 16:9 entries there take the 65:24
heights, so the cropped image finds the configurations 16:9 always used.
With --block-only the stub (tools/x100v_jpeg_crop_block_stub.s) crops only
the encoder block and leaves the setup call at the stock height, so the
lookup succeeds without touching the overlay.

With --raf-aspect the 16:9 branch of the RAF info builder 0x01f689b0 writes
24, 65 instead of 9, 16 at record +0x14/+0x16, which the RAF directory
template at 0x013ec880 serializes as tag 0x115. The RAF keeps the stock
full-sensor crop, as stock 16:9 RAFs do.

With --raf-crop the same 16:9 branch instead branches to a second stub
(tools/x100v_raf_crop_stub.s) at 0x0128fd40. It writes the 24:65 aspect and,
when the record holds the stock 4160-row area, moves the area's top 930 rows
down (record +0x04, tag 0x110) and sets its height to 2304 (record +0x08,
tag 0x111), in the record and in its mirror. The raw pixels stay complete.

The ARM check runs the original patched instructions from 0x01edc4c0 to
0x01edc508 plus the stub under a Cortex-A15 ISA model with synthetic
registers and memory. The RAF check runs the builder's aspect switch
0x01f6928c..0x01f6939c the same way. It is not a camera or firmware emulator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import CODE_SITES, LOADS as PARTITION_LOADS, stock_partitions
from tools.x100v_exif_buffer_emulator import load_overlay
from tools.x100v_preview_alias_candidate import read_elf_text

LOADS = {**PARTITION_LOADS, 9: 0x03720000}  # 9: raw overlay
STUB_ADDRESS = 0x0128FC80
ENCODER_TABLE = 0x03DB1498  # 6-byte entries: width, height (u16), mode, config index
ENCODER_LOOKUP = 0x03DB049C
ENCODER_16_9 = {"L": 4, "M": 5, "S": 6}  # entry numbers
RAF_TEMPLATE = 0x013EC880  # 12-byte entries: tag, size, element size, count, source offset
RAF_ASPECT_SITES = ("ratio-pair-code2-first", "ratio-pair-code2-second")
RAF_STUB_ADDRESS = 0x0128FD40  # same primary zero padding, after the JPEG stub
RAF_SWITCH = 0x01F6928C  # ldrb r3, [r6, #0x5be]: aspect code 0..6, jump table at +0x10
RAF_HOOK = 0x01F69464  # aspect-code-2 case
RAF_CASE_STOCK = (0xE3A03009, 0xE1C431B4, 0xE3A03010, 0xE1C431B6, 0xEAFFFFC8)  # 9, 16 -> +0x14/+0x16; b rejoin
RAF_REJOIN = 0x01F6939C
RAF_AREA = (4160, 930, 2304)  # stock height -> rows moved down, 65:24 height (both multiples of 6)
RAF_FIELDS = {0x110: 0x04, 0x111: 0x08, 0x115: 0x14}  # tag -> record offset, two u16 each
HOOK = 0x01EDC4F0
HOOK_STOCK = 0xE5831014  # str r1, [r3, #0x14]
BLOCK = (0x01EDC4C0, 0x01EDC508)  # main-image encoder block fill
CROPS = {  # width bytes, stock height -> 65:24 height, rows skipped
    "L": (12480, 3512, 2304, 604),
    "M": (8832, 2488, 1632, 428),
    "S": (6240, 1760, 1152, 304),
}


def bl(source: int, target: int) -> int:
    offset = (target - source - 8) >> 2
    if not -(1 << 23) <= offset < (1 << 23):
        raise ValueError("BL target out of range")
    return 0xEB000000 | (offset & 0xFFFFFF)


def b(source: int, target: int) -> int:
    return bl(source, target) & ~0x01000000


def stub_write(partitions: dict[int, bytes], address: int, stub: bytes, field: str) -> dict:
    at = address - LOADS[6]
    if partitions[6][at:at + len(stub)] != bytes(len(stub)):
        raise ValueError(f"{field} area is not zero padding in the stock primary")
    for part in (6, 7):
        words = struct.unpack_from(f"<{len(partitions[part]) // 4}I", partitions[part])
        if any(address <= w < address + len(stub) for w in words):
            raise ValueError(f"stock partition {part} holds a pointer into the {field} area")
    return {"field": field, "partition": 6, "address": address, "partition_offset": at,
            "before_hex": bytes(len(stub)).hex(), "after_hex": stub.hex()}


def encoder_table_writes(overlay: bytes) -> list[dict]:
    writes = []
    for size, entry in ENCODER_16_9.items():
        width_bytes, height, new_height, _ = CROPS[size]
        address = ENCODER_TABLE + 6 * entry
        at = address - LOADS[9]
        w, h, mode = struct.unpack_from("<HHB", overlay, at)
        if (w, h, mode) != (width_bytes // 2, height, 1):
            raise ValueError(f"encoder table entry {entry} differs from stock")
        writes.append({"field": f"encoder-size-{size}-height", "partition": 9, "address": address + 2,
                       "partition_offset": at + 2, "before_hex": struct.pack("<H", height).hex(),
                       "after_hex": struct.pack("<H", new_height).hex()})
    return writes


def raf_aspect_writes(partitions: dict[int, bytes]) -> list[dict]:
    """Code-2 aspect pair of the RAF info builder: 9, 16 -> 24, 65 (tag 0x115)."""
    primary = partitions[6]
    entry = primary[RAF_TEMPLATE + 5 * 12 - LOADS[6]:][:12]
    tag, size, element, count, offset = struct.unpack("<4HI", entry)
    if (tag, size, element, count, offset) != (0x115, 4, 2, 1, 0x14):
        raise ValueError("RAF template entry for tag 0x115 differs from stock")
    writes = []
    for field, part, address, old, new in CODE_SITES:
        if field not in RAF_ASPECT_SITES:
            continue
        at = address - LOADS[part]
        before = struct.pack(f"<{len(old)}I", *old)
        if partitions[part][at:at + len(before)] != before:
            raise ValueError(f"{field}: stock words differ")
        writes.append({"field": f"raf-aspect-{field}", "partition": part, "address": address,
                       "partition_offset": at, "before_hex": before.hex(),
                       "after_hex": struct.pack(f"<{len(new)}I", *new).hex()})
    return writes


def lookup(overlay: bytes, width: int, height: int, mode: int) -> int:
    """Run the original overlay lookup 0x03db049c; returns the config index (0 = unknown)."""
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    lo, hi = ENCODER_LOOKUP & ~0xFFF, (ENCODER_TABLE + 0x200 + 0xFFF) & ~0xFFF
    uc.mem_map(lo, hi - lo)
    uc.mem_write(lo, overlay[lo - LOADS[9]:hi - LOADS[9]])
    uc.mem_map(0x33000000, 0x2000)
    for reg, value in ((A.UC_ARM_REG_R0, width), (A.UC_ARM_REG_R1, height), (A.UC_ARM_REG_R2, mode),
                       (A.UC_ARM_REG_SP, 0x33001000), (A.UC_ARM_REG_LR, 0x33001800)):
        uc.reg_write(reg, value)
    uc.emu_start(ENCODER_LOOKUP, 0x33001800, count=2000)
    return uc.reg_read(A.UC_ARM_REG_R0)


def lookup_check(stock: bytes, patched_overlay: bytes) -> dict:
    cases = {"65:24 L": (6240, 2304), "65:24 M": (4416, 1632), "65:24 S": (3120, 1152),
             "16:9 L": (6240, 3512), "3:2 L": (6240, 4160), "1:1 L": (4160, 4160), "640x480": (640, 480)}
    rows = [{"case": k, "size": v, "stock": lookup(stock, *v, 1), "patched": lookup(patched_overlay, *v, 1)}
            for k, v in cases.items()]
    rows += [{"case": "thumbnail 160x120 mode 0", "size": (160, 120), "stock": lookup(stock, 160, 120, 0),
              "patched": lookup(patched_overlay, 160, 120, 0)},
             {"case": "preview 640x480 mode 2", "size": (640, 480), "stock": lookup(stock, 640, 480, 2),
              "patched": lookup(patched_overlay, 640, 480, 2)}]
    by = {r["case"]: r for r in rows}
    ok = ([by[f"65:24 {s}"]["patched"] for s in "LMS"] == [by["16:9 L"]["stock"], 9, 10]
          and all(r["patched"] == r["stock"] for r in rows if not r["case"].startswith(("65:24", "16:9"))))
    return {"rows": rows, "all_as_expected": ok}


def writes_for(partitions: dict[int, bytes], stub: bytes) -> list[dict]:
    hook_at = HOOK - LOADS[7]
    if struct.unpack_from("<I", partitions[7], hook_at)[0] != HOOK_STOCK:
        raise ValueError("hook instruction differs from stock")
    return [
        stub_write(partitions, STUB_ADDRESS, stub, "jpeg-crop-stub"),
        {"field": "jpeg-crop-hook", "partition": 7, "address": HOOK, "partition_offset": hook_at,
         "before_hex": struct.pack("<I", HOOK_STOCK).hex(),
         "after_hex": struct.pack("<I", bl(HOOK, STUB_ADDRESS)).hex()},
    ]


def patched(partitions: dict[int, bytes], writes: list[dict]) -> dict[int, bytes]:
    out = {k: bytearray(v) for k, v in partitions.items()}
    for w in writes:
        new = bytes.fromhex(w["after_hex"])
        out[w["partition"]][w["partition_offset"]:w["partition_offset"] + len(new)] = new
    return {k: bytes(v) for k, v in out.items()}


def run_block(partitions: dict[int, bytes], width: int, height: int, stride: int,
              base: int, aspect: int = 0) -> dict:
    """Execute 0x01edc4c0..0x01edc508 (and any stub) on synthetic state."""
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    block = 0x0253C000  # parameter block page (0x0253cf64)
    desc, frame, ctl, stack, context = (
        0x30000000, 0x31001000, 0x32000000, 0x33000000, 0x35000000
    )
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_A15)
    code = {7: BLOCK, 6: (STUB_ADDRESS, STUB_ADDRESS + 0x100)}
    for part, (lo, hi) in code.items():
        page = lo & ~0xFFF
        uc.mem_map(page, ((hi - page + 0xFFF) & ~0xFFF))
        uc.mem_write(lo, partitions[part][lo - LOADS[part]:hi - LOADS[part]])
    for page in (block, desc, frame - 0x1000, ctl, stack, context):
        uc.mem_map(page, 0x2000)
    uc.mem_write(desc, struct.pack("<7I", 0, base, 0, stride, width, height, 0))
    uc.mem_write(frame - 0x44, struct.pack("<I", height))
    uc.mem_write(ctl, b"\x00\x00")  # control bytes [r8], [r8+1]
    if not 0 <= aspect <= 255:
        raise ValueError("aspect must fit in one byte")
    uc.mem_write(context + 0x5BE, bytes([aspect]))
    visited = []
    uc.hook_add(UC_HOOK_CODE, lambda m, a, s, u: visited.append(a))
    regs = {A.UC_ARM_REG_R6: desc, A.UC_ARM_REG_R8: ctl, A.UC_ARM_REG_FP: frame,
            A.UC_ARM_REG_SL: width // 2, A.UC_ARM_REG_SP: stack + 0x1000,
            A.UC_ARM_REG_R0: 0x1111, A.UC_ARM_REG_R4: 0x4444, A.UC_ARM_REG_R5: context}
    for r, v in regs.items():
        uc.reg_write(r, v)
    uc.emu_start(BLOCK[0], BLOCK[1], count=200)
    p = struct.unpack("<12I", uc.mem_read(0x0253CF64, 48))
    return {
        "encoder_width_px": p[2], "encoder_line_skip": p[3], "encoder_height": p[4],
        "encoder_base": p[5], "header_height": struct.unpack("<I", uc.mem_read(frame - 0x44, 4))[0],
        "descriptor_unchanged": struct.unpack("<7I", uc.mem_read(desc, 28)) == (0, base, 0, stride, width, height, 0),
        "callee_saved_kept": (uc.reg_read(A.UC_ARM_REG_R4), uc.reg_read(A.UC_ARM_REG_R5),
                              uc.reg_read(A.UC_ARM_REG_R6), uc.reg_read(A.UC_ARM_REG_SP)) == (0x4444, context, desc, stack + 0x1000),
        "stub_ran": any(STUB_ADDRESS <= a < STUB_ADDRESS + 0x100 for a in visited),
    }


def arm_check(stock: dict[int, bytes], writes: list[dict], block_only: bool = False) -> dict:
    new = patched(stock, writes)
    base, rows = 0x40000000, []
    cases = {**{k: v[:2] for k, v in CROPS.items()}, "L 3:2": (12480, 4160), "L 1:1": (8320, 4160),
             "preview 640x480": (1280, 480), "4992 crop 16:9": (9984, 2808)}
    for name, (width, height) in cases.items():
        stride = (width + 255) & ~255
        before = run_block(stock, width, height, stride, base)
        after = run_block(new, width, height, stride, base)
        crop = CROPS.get(name)
        expect = ({"encoder_height": crop[2], "header_height": height if block_only else crop[2],
                   "encoder_base": base + crop[3] * stride}
                  if crop else {k: before[k] for k in ("encoder_height", "header_height", "encoder_base")})
        rows.append({"case": name, "width_bytes": width, "height": height, "stride": stride,
                     "stock": before, "patched": after,
                     "as_expected": all(after[k] == v for k, v in expect.items())
                     and after["encoder_width_px"] == before["encoder_width_px"]
                     and after["encoder_line_skip"] == before["encoder_line_skip"]
                     and after["descriptor_unchanged"] and after["callee_saved_kept"]})
    return {"rows": rows, "all_as_expected": all(r["as_expected"] for r in rows)}


def raf_crop_writes(partitions: dict[int, bytes], stub: bytes) -> list[dict]:
    """Code-2 case of the RAF info builder -> B to the RAF stub (tags 0x110, 0x111, 0x115)."""
    for i in range(15):
        tag, size, element, count, offset = struct.unpack_from("<4HI", partitions[6], RAF_TEMPLATE + 12 * i - LOADS[6])
        if tag in RAF_FIELDS and (size, element, count, offset) != (4, 2, 1, RAF_FIELDS[tag]):
            raise ValueError(f"RAF template entry for tag {tag:#x} differs from stock")
    table = RAF_SWITCH + 0x10 + 4 * 2 - LOADS[7]
    if struct.unpack_from("<I", partitions[7], table)[0] != RAF_HOOK:
        raise ValueError("aspect code 2 does not jump to the hook site")
    at = RAF_HOOK - LOADS[7]
    if struct.unpack_from("<5I", partitions[7], at) != RAF_CASE_STOCK:
        raise ValueError("aspect-code-2 case differs from stock")
    if struct.unpack("<I", stub[-4:])[0] != RAF_REJOIN:
        raise ValueError("RAF stub does not rejoin the builder")
    return [
        stub_write(partitions, RAF_STUB_ADDRESS, stub, "raf-crop-stub"),
        {"field": "raf-crop-hook", "partition": 7, "address": RAF_HOOK, "partition_offset": at,
         "before_hex": struct.pack("<I", RAF_CASE_STOCK[0]).hex(),
         "after_hex": struct.pack("<I", b(RAF_HOOK, RAF_STUB_ADDRESS)).hex()},
    ]


def run_raf_switch(partitions: dict[int, bytes], code: int, area: tuple, mirror: bool) -> dict:
    """Execute the builder's aspect switch 0x01f6928c..0x01f6939c (and any stub) on synthetic state."""
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc, UcError
    from unicorn import arm_const as A

    state, record, mirror_at, stack = 0x30000000, 0x31000000, 0x31000100, 0x33000000
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_A15)
    for part, page in ((7, RAF_SWITCH & ~0xFFF), (6, RAF_STUB_ADDRESS & ~0xFFF)):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, partitions[part][page - LOADS[part]:page - LOADS[part] + 0x1000])
    for page in (state, record, stack):
        uc.mem_map(page, 0x1000)
    uc.mem_write(state + 0x5BE, bytes([code]))
    fields = bytearray(range(0x80, 0xE0))  # filler for the other record fields
    struct.pack_into("<4H", fields, 4, *area)
    struct.pack_into("<2H", fields, 0x14, 0, 0)
    uc.mem_write(record, bytes(fields))
    if mirror:
        uc.mem_write(mirror_at, bytes(fields))
    names = [f"r{i}" for i in range(13)] + ["sp"]
    regs = [getattr(A, f"UC_ARM_REG_{n.upper()}") for n in names]
    for i, r in enumerate(regs):
        uc.reg_write(r, 0x7000 + i)
    uc.reg_write(A.UC_ARM_REG_R4, record)
    uc.reg_write(A.UC_ARM_REG_R6, state)
    uc.reg_write(A.UC_ARM_REG_SL, mirror_at if mirror else 0)
    uc.reg_write(A.UC_ARM_REG_SP, stack + 0x800)
    visited = []
    uc.hook_add(UC_HOOK_CODE, lambda m, a, s, u: visited.append(a))
    try:
        uc.emu_start(RAF_SWITCH, RAF_REJOIN, count=100)
        fault = None
    except UcError as error:
        fault = str(error)
    return {"record": bytes(uc.mem_read(record, 0x60)), "mirror": bytes(uc.mem_read(mirror_at, 0x60)),
            "regs": {n: uc.reg_read(r) for n, r in zip(names, regs)}, "pc": uc.reg_read(A.UC_ARM_REG_PC),
            "fault": fault, "stub_ran": any(RAF_STUB_ADDRESS <= a < RAF_STUB_ADDRESS + 0x100 for a in visited)}


def raf_arm_check(stock: dict[int, bytes], writes: list[dict]) -> dict:
    new = patched(stock, writes)
    stock_height, rows_down, height = RAF_AREA
    full = (13, 6, stock_height, 6240)  # stock 16:9 RAF: tags 0x110 and 0x111
    cases = [(f"aspect code {c}", c, full, True) for c in range(7)]
    cases += [("aspect code 2, no mirror record", 2, full, False),
              ("aspect code 2, unexpected height 3512", 2, (13, 6, 3512, 6240), True)]
    rows = []
    for name, code, area, mirror in cases:
        before = run_raf_switch(stock, code, area, mirror)
        after = run_raf_switch(new, code, area, mirror)
        record, copy = bytearray(before["record"]), bytearray(before["mirror"])
        if code == 2:
            struct.pack_into("<2H", record, 0x14, 24, 65)
            if area[2] == stock_height:
                for buf in (record, copy) if mirror else (record,):
                    struct.pack_into("<H", buf, 4, area[0] + rows_down)
                    struct.pack_into("<H", buf, 8, height)
        kept = {k: v for k, v in after["regs"].items() if k != "r3"} == {k: v for k, v in before["regs"].items() if k != "r3"}
        rows.append({
            "case": name, "input_area": area,
            "stock": {"aspect": struct.unpack_from("<2H", before["record"], 0x14),
                      "area": struct.unpack_from("<4H", before["record"], 4)},
            "patched": {"aspect": struct.unpack_from("<2H", after["record"], 0x14),
                        "area": struct.unpack_from("<4H", after["record"], 4),
                        "mirror_area": struct.unpack_from("<4H", after["mirror"], 4) if mirror else None,
                        "stub_ran": after["stub_ran"], "fault": after["fault"]},
            "as_expected": (before["fault"] is None and after["fault"] is None
                            and before["pc"] == after["pc"] == RAF_REJOIN
                            and after["record"] == bytes(record) and after["mirror"] == bytes(copy)
                            and kept and after["stub_ran"] == (code == 2)),
        })
    return {"rows": rows, "all_as_expected": all(r["as_expected"] for r in rows)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--stub-object", type=Path, required=True, help="clang-assembled stub .o")
    parser.add_argument("--stub-source", type=str,
                        help="source label for this stub; defaults to the historical JPEG stub")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--block-only", action="store_true",
                        help="stub object crops only the encoder block (setup call keeps the stock height)")
    raf = parser.add_mutually_exclusive_group()
    raf.add_argument("--raf-aspect", action="store_true",
                     help="also write the 24:65 RAF aspect tag for the 16:9 settings")
    raf.add_argument("--raf-crop", type=Path, metavar="STUB_OBJECT",
                     help="clang-assembled RAF stub .o: 24:65 tag plus a 65:24 image area for the 16:9 settings")
    parser.add_argument("--encoder-table", action="store_true",
                        help="also give the encoder size table's 16:9 entries the 65:24 heights")
    args = parser.parse_args()
    stock = stock_partitions(args.stock.read_bytes())
    stub = read_elf_text(args.stub_object)
    writes = writes_for(stock, stub)
    check = arm_check(stock, writes, args.block_only)
    if args.raf_aspect:
        writes += raf_aspect_writes(stock)
    raf_stub = read_elf_text(args.raf_crop) if args.raf_crop else None
    if raf_stub is not None:
        if STUB_ADDRESS + len(stub) > RAF_STUB_ADDRESS:
            raise SystemExit("the JPEG stub overlaps the RAF stub area")
        writes += raf_crop_writes(stock, raf_stub)
        check["raf_area"] = raf_arm_check(stock, writes)
        check["all_as_expected"] = check["all_as_expected"] and check["raf_area"]["all_as_expected"]
    if args.encoder_table:
        overlay = load_overlay(args.stock)
        table = encoder_table_writes(overlay)
        writes += table
        new_overlay = bytearray(overlay)
        for w in table:
            new = bytes.fromhex(w["after_hex"])
            new_overlay[w["partition_offset"]:w["partition_offset"] + len(new)] = new
        check["encoder_lookup"] = lookup_check(overlay, bytes(new_overlay))
        check["all_as_expected"] = check["all_as_expected"] and check["encoder_lookup"]["all_as_expected"]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "kind": "encode-time 65:24 crop of 16:9 still JPEGs: stub + one BL; offline only",
        "source_update_sha256": hashlib.sha256(args.stock.read_bytes()).hexdigest(),
        "stub_source": args.stub_source or ("tools/x100v_jpeg_crop_block_stub.s" if args.block_only
                                            else "tools/x100v_jpeg_crop_stub.s"),
        "setup_call_height": "stock (lookup and output budget unchanged)" if args.block_only else "65:24",
        "raf_aspect_tag": "24:65 for the 16:9 settings (tag 0x115 from RAF info +0x14/+0x16)"
                          if args.raf_aspect or args.raf_crop else "stock",
        **({"raf_image_area": {"stub_source": "tools/x100v_raf_crop_stub.s",
                               "stub_sha256": hashlib.sha256(raf_stub).hexdigest(),
                               "when_height": RAF_AREA[0], "rows_moved_down": RAF_AREA[1], "height": RAF_AREA[2],
                               "tags": "0x110 top-left (record +0x04), 0x111 size (record +0x08); raw pixels unchanged"}}
           if raf_stub is not None else {}),
        "stub_sha256": hashlib.sha256(stub).hexdigest(),
        "crops": {k: {"width_bytes": v[0], "stock_height": v[1], "height": v[2], "rows_skipped": v[3]} for k, v in CROPS.items()},
        "unchanged": "every 16:9 size table in the partitions, the crop table, thumbnail and 640x480 preview, "
                     + ("" if args.raf_aspect or args.raf_crop else "RAF, ") + "frames, movies"
                     + ("; the overlay encoder table's 16:9 entries take the 65:24 heights" if args.encoder_table else ""),
        "write_count": len(writes),
        "writes": writes,
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output_dir / "arm-check.json").write_text(json.dumps(check, indent=2) + "\n")
    print(json.dumps({"writes": [w["field"] for w in writes], "all_as_expected": check["all_as_expected"]}))
    for r in check.get("encoder_lookup", {}).get("rows", []):
        print("lookup", r["case"], r["size"], "stock", r["stock"], "patched", r["patched"])
    for r in check.get("raf_area", {}).get("rows", []):
        print("raf", r["case"], "stock", r["stock"]["aspect"], r["stock"]["area"], "patched", r["patched"]["aspect"],
              r["patched"]["area"], "mirror", r["patched"]["mirror_area"], "stub" if r["patched"]["stub_ran"] else "",
              "ok" if r["as_expected"] else "MISMATCH")
    for r in check["rows"]:
        print(r["case"], "stock", (r["stock"]["encoder_height"], hex(r["stock"]["encoder_base"])),
              "patched", (r["patched"]["encoder_height"], hex(r["patched"]["encoder_base"]), r["patched"]["header_height"]),
              "stub" if r["patched"]["stub_ran"] else "", "ok" if r["as_expected"] else "MISMATCH")


if __name__ == "__main__":
    main()
