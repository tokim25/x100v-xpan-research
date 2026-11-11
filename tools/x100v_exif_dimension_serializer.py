"""Run stock dimension staging and TIFF entry serialization in synthetic RAM.

The harness explicitly sequences the fragments; it does not execute their
full caller or establish camera mode/timing. No firmware patch is emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges
from tools.x100v_preview_cache_export_emulator import load_images, verify_images
from tools.x100v_exif_dimension_stage import ENTRY, CONTEXT, DEST, VECTORS, verify_secondary
from tools.x100v_jpeg_crop import bl

PINS = {
    0x1065514: (0xB8, "03db048021f65926afced83ae34715df9edec5c62ed886625145c19b94275027"),
    0x106581C: (0x240, "9cab164347a7f3d98271cbb0ba70dd0c00f43ac842424994276a3ef14c8f5bff"),
    0x1058E4C: (0x20, "689d27d8bd30f670a7bad08651336ee332cf56468df69857c7e754602d25eb9a"),
    0x1140808: (0x1CC, "8caaae1bcd5fdc832695ba560427265438d5e055b523d18f52243c881c4a42d2"),
    0x13F0928: (0x40, "e8fae6533c5a41787e9bd0f2bf183c7c2c124d69ec9c1fbc5302b9a572c0e9aa"),
    0x13EC7AC: (0xC, "8db1a83b7272b8a47c25477160ea56ee9511a134f1b9b7e71410ce2fc2c3c43d"),
}
CODE_RANGES = ((0x1063F80, 0x1064F1C), (0x106648C, 0x10664C8),
               (0x1065514, 0x10655CC), (0x106581C, 0x1065A5C),
               (0x1058E4C, 0x1058E6C), (0x1140808, 0x11409D4))
OUTPUT, STACK, STOP, CURSOR = 0x21000000, 0x22000000, 0x23000000, 0x24000000
MASK_INDEX, MASK_TABLE = 0x25000000, 0x25001000
SCRATCH = 0x185080C
CROP_VECTORS = ((6240, 2304), (4416, 1632), (3120, 1152))
EXIF_HOOK, EXIF_STUB = 0x1F581CC, 0x128FE00
EXIF_HOOK_STOCK = 0xE5D43624
STAGE_END = EXIF_HOOK+4
ALTERNATE_RANGES = ((0x1F58480,0x1F584A8), (0x115F9F4,0x115FA4C),
                    (0x115FABC,0x115FB14))


def parse_entries(data: bytes) -> tuple[int, int]:
    """Independent strict little-endian TIFF LONG/count=1 pair reader."""
    if len(data) != 24:
        raise ValueError("expected two 12-byte TIFF entries")
    x, y = struct.unpack_from("<HHII", data), struct.unpack_from("<HHII", data, 12)
    if x[:3] != (0xA002, 4, 1) or y[:3] != (0xA003, 4, 1):
        raise ValueError("wrong dimension tag/type/count")
    return x[3], y[3]


def execute(primary: bytes, secondary: bytes, width: int, height: int,
            *, aspect: int = 2, flag: int = 0, stub: bytes | None = None,
            preview_metadata_case: bool = False,
            expected_stub_aspect: int = 2) -> dict:
    verify_images(primary, secondary)
    verify_secondary(secondary)
    base = SOURCES["x100v_3_01"]["primary_load"]
    verify_hashed_ranges(primary, base, PINS)
    if any(type(v) is not int or not 0 <= v <= 0xffffffff for v in (width, height)):
        raise ValueError("dimensions must be uint32")
    if type(aspect) is not int or not 0 <= aspect <= 255:
        raise ValueError("aspect must be a byte")
    if type(expected_stub_aspect) is not int or not 0 <= expected_stub_aspect <= 255:
        raise ValueError("expected stub aspect must be a byte")
    if type(flag) is not int or not 0 <= flag <= 255:
        raise ValueError("flag must be a byte")
    hook_bytes = secondary[EXIF_HOOK-SOURCES["x100v_3_01"]["secondary_load"]:
                           STAGE_END-SOURCES["x100v_3_01"]["secondary_load"]]
    if hook_bytes != struct.pack("<I", EXIF_HOOK_STOCK):
        raise ValueError("stock EXIF join instruction changed")
    if stub is not None:
        if not 0 < len(stub) <= 0x100 or len(stub) % 4:
            raise ValueError("invalid EXIF stub length")
        if primary[EXIF_STUB-base:EXIF_STUB-base+len(stub)] != bytes(len(stub)):
            raise ValueError("EXIF cave is not stock zero padding")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
        UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
        UC_ARM_REG_R11, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    pages = set()
    for address, (size, _) in PINS.items():
        for page in range(address & ~4095, (address+size+4095) & ~4095, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                uc.mem_write(page, primary[page-base:page-base+4096])
                pages.add(page)
    stage_page = ENTRY & ~4095
    uc.mem_map(stage_page, 4096)
    uc.mem_write(stage_page,secondary[stage_page-SOURCES["x100v_3_01"]["secondary_load"]:
                                      stage_page-SOURCES["x100v_3_01"]["secondary_load"]+4096])
    for page in (0x115F000,0x14A7000):
        uc.mem_map(page,4096)
        uc.mem_write(page,primary[page-base:page-base+4096])
    uc.mem_map(0x1066000,4096)
    uc.mem_write(0x1066000,primary[0x1066000-base:0x1067000-base])
    for page in (0x1063000,0x1064000):
        uc.mem_map(page,4096)
        uc.mem_write(page,primary[page-base:page-base+4096])
    if stub is not None:
        uc.mem_write(EXIF_HOOK,struct.pack("<I",bl(EXIF_HOOK,EXIF_STUB)))
        uc.mem_map(EXIF_STUB & ~4095,4096)
        uc.mem_write(EXIF_STUB,stub)
    for address,size in ((CONTEXT,0x4000),(DEST,4096),(OUTPUT,4096),
                         (STACK,4096),(CURSOR,4096),(SCRATCH & ~4095,4096),
                         (MASK_INDEX,4096),(MASK_TABLE,4096)):
        uc.mem_map(address,size)
        uc.mem_write(address,b"\xcc"*size)
    context = bytearray(b"\xa5"*0x4000)
    context[0x3030] = flag
    context[0x5be] = aspect
    struct.pack_into("<II", context,0x30f8,height,width)
    uc.mem_write(CONTEXT,bytes(context))
    phase = "stage"
    counts, writes = {}, []

    def instruction(machine,address,size,_):
        ranges = (((ENTRY,STAGE_END),)+ALTERNATE_RANGES+
                  ((EXIF_STUB,EXIF_STUB+len(stub)),)) if phase == "stage" and stub else (
            (((ENTRY,STAGE_END),)+ALTERNATE_RANGES) if phase == "stage" else CODE_RANGES)
        if not any(a <= address < b for a,b in ranges):
            raise AssertionError(f"unexpected {phase} instruction {address:#x}")
        counts[phase] = counts.get(phase,0)+1

    def write(machine,access,address,size,value,_):
        allowed = ((DEST+0x2a0,DEST+0x2a8),(STACK,STACK+4096)) if phase == "stage" else (
            (STACK,STACK+4096),(OUTPUT,OUTPUT+24),(SCRATCH+0x24,SCRATCH+0x5c))
        if not any(a <= address and address+size <= b for a,b in allowed):
            raise AssertionError(f"unexpected {phase} write {address:#x}")
        if OUTPUT <= address < OUTPUT+24:
            writes.append([address-OUTPUT,size,value])

    uc.hook_add(UC_HOOK_CODE,instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.reg_write(UC_ARM_REG_R4,CONTEXT)
    uc.reg_write(UC_ARM_REG_R6,DEST)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf00)
    uc.emu_start(ENTRY,STAGE_END,count=160,timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STAGE_END:
        raise AssertionError("staging did not reach its boundary")
    if uc.reg_read(UC_ARM_REG_R3) != context[0x624]:
        raise AssertionError("displaced join instruction did not preserve r3")
    expected_dest=bytearray(b"\xcc"*4096)
    staged_width,staged_height=(4416,2944) if flag else (width,height)
    crop_map={(6240,3512):2304,(4416,2488):1632,(3120,1760):1152}
    if preview_metadata_case:
        crop_map[(4416,2944)] = 1632
    expected_height=crop_map.get((staged_width,staged_height),staged_height) if stub and aspect==expected_stub_aspect else staged_height
    struct.pack_into("<II",expected_dest,0x2a0,staged_width,expected_height)
    if bytes(uc.mem_read(DEST,4096)) != expected_dest:
        raise AssertionError("staging differs from independent fixture")
    sp=STACK+0xf00
    saved_regs=(UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
                UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11)
    descriptor_gates = {}
    for index,record in enumerate((0x13f0928,0x13f0948)):
        raw=primary[record-base:record-base+32]
        tag,kind,count=struct.unpack_from("<H",raw)[0],struct.unpack_from("<H",raw,4)[0],struct.unpack_from("<H",raw,6)[0]
        offset=struct.unpack_from("<I",raw,28)[0]
        if (tag,kind,count,offset) != (0xa002+index,4,1,0x2a0+4*index):
            raise AssertionError("stock descriptor layout changed")
        flags=struct.unpack_from("<H",raw,2)[0]
        if flags != 1:
            raise AssertionError("stock dimension descriptor flags changed")
        # Execute the stock loop's first decision with the actual descriptor.
        # Flag 0x10 would take the predicate route; these records do not.
        phase=f"gate-{tag:04x}"
        uc.reg_write(UC_ARM_REG_R5,record)
        uc.reg_write(UC_ARM_REG_SP,sp)
        uc.emu_start(0x10664AC,0x106648C,count=16,timeout=1000000)
        if (uc.reg_read(UC_ARM_REG_PC) != 0x106648C or
            uc.reg_read(UC_ARM_REG_R7) != record or
            uc.reg_read(UC_ARM_REG_R2) != flags or
            uc.reg_read(UC_ARM_REG_SP) != sp):
            raise AssertionError("dimension descriptor did not enter the mask gate")
        # Synthetic masks exercise both outcomes. Their values are not
        # observations of the camera's mutable mask/selector state.
        uc.mem_write(MASK_INDEX,struct.pack("<H",0))
        mask_results={}
        for mask,target in ((1,0x10664C8),(3,0x10664A0)):
            phase=f"mask-{tag:04x}-{mask}"
            uc.mem_write(MASK_TABLE,struct.pack("<H",mask))
            uc.reg_write(UC_ARM_REG_R8,MASK_INDEX)
            uc.reg_write(UC_ARM_REG_R10,MASK_TABLE)
            uc.reg_write(UC_ARM_REG_R2,flags)
            uc.reg_write(UC_ARM_REG_SP,sp)
            uc.emu_start(0x106648C,target,count=10,timeout=1000000)
            if uc.reg_read(UC_ARM_REG_PC) != target or uc.reg_read(UC_ARM_REG_SP) != sp:
                raise AssertionError("stock dimension mask branch mismatch")
            mask_results[str(mask)]="predicate" if target==0x10664C8 else "skip"
        phase=f"predicate-{tag:04x}"
        for reg,value in ((UC_ARM_REG_R0,1),(UC_ARM_REG_R1,tag),
                          (UC_ARM_REG_R2,DEST),(UC_ARM_REG_SP,sp),
                          (UC_ARM_REG_LR,STOP)):
            uc.reg_write(reg,value)
        uc.emu_start(0x1063F80,STOP,count=100,timeout=1000000)
        if (uc.reg_read(UC_ARM_REG_PC) != STOP or
            uc.reg_read(UC_ARM_REG_R0) != 1 or uc.reg_read(UC_ARM_REG_SP) != sp):
            raise AssertionError("stock group-1 dimension predicate mismatch")
        descriptor_gates[f"{tag:04x}"]=dict(flags=flags,synthetic_mask_outcomes=mask_results,
                                                predicate_if_mask_passes=1)
        phase=f"count-{tag:04x}"
        for i,reg in enumerate(saved_regs):uc.reg_write(reg,0x44000000+i)
        for reg,value in ((UC_ARM_REG_R0,1),(UC_ARM_REG_R1,record),(UC_ARM_REG_R2,DEST),
                          (UC_ARM_REG_SP,sp),(UC_ARM_REG_LR,STOP)):
            uc.reg_write(reg,value)
        uc.emu_start(0x1065514,STOP,count=100,timeout=1000000)
        if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_R0) != count:
            raise AssertionError("stock group-1 count helper did not return descriptor count")
        phase=f"tag-{tag:04x}"
        uc.mem_write(CURSOR,struct.pack("<I",OUTPUT+0x100))
        uc.mem_write(sp,struct.pack("<II",OUTPUT,CURSOR))
        for reg,value in ((UC_ARM_REG_R0,record),(UC_ARM_REG_R1,DEST+offset),
                          (UC_ARM_REG_R2,OUTPUT+12*index),(UC_ARM_REG_R3,count),
                          (UC_ARM_REG_SP,sp),(UC_ARM_REG_LR,STOP)):
            uc.reg_write(reg,value)
        uc.emu_start(0x1065928,STOP,count=2000,timeout=1000000)
        if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_R0) != 12:
            raise AssertionError("serializer did not return a 12-byte entry")
        if uc.reg_read(UC_ARM_REG_SP) != sp or any(uc.reg_read(reg)!=0x44000000+i for i,reg in enumerate(saved_regs)):
            raise AssertionError("serializer failed register/stack restoration")
        if bytes(uc.mem_read(CURSOR,4)) != struct.pack("<I",OUTPUT+0x100):
            raise AssertionError("inline LONG unexpectedly advanced external data cursor")
    output=bytes(uc.mem_read(OUTPUT,24))
    expected=struct.pack("<HHIIHHII",0xa002,4,1,staged_width,0xa003,4,1,expected_height)
    if output != expected or parse_entries(output) != (staged_width,expected_height):
        raise AssertionError("serialized tags differ from independent TIFF fixture")
    if bytes(uc.mem_read(OUTPUT+24,4096-24)) != b"\xcc"*(4096-24):
        raise AssertionError("output guards changed")
    if bytes(uc.mem_read(DEST,4096)) != expected_dest or bytes(uc.mem_read(CONTEXT,0x4000)) != context:
        raise AssertionError("serializer mutated dimension inputs")
    return dict(width=width,height=height,aspect=aspect,flag=flag,
                serialized_width=staged_width,serialized_height=expected_height,
                stub_executed=stub is not None,entries_hex=output.hex(),instructions=counts,
                output_writes=writes,descriptor_gate=descriptor_gates,
                full_serializer_return=True,guards_preserved=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update",type=Path)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    primary,secondary=load_images(args.update)
    rows=[dict(input_kind="stock",**execute(primary,secondary,w,h)) for w,h in VECTORS]
    rows += [dict(input_kind="synthetic-crop-not-a-patch",**execute(primary,secondary,w,h)) for w,h in CROP_VECTORS]
    import unicorn
    report=dict(scope="Explicitly sequenced stock staging and serializer; no full caller, patch, JPEG or camera",
                primary_sha256=hashlib.sha256(primary).hexdigest(),secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                unicorn_version=unicorn.__version__,pins={hex(k):v for k,v in PINS.items()},cases=rows)
    with args.report.open("x") as f:
        json.dump(report,f,indent=2);f.write("\n")
    print(f"{len(rows)} paired dimension serializer cases passed")


if __name__ == "__main__":
    main()
