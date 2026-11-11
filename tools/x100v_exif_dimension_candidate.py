"""Build an offline EXIF dimension delta for the X100V 3.01 card 5d path.

Outputs decoded partition experiments and an exact two-write manifest only.
The output is not an update container or an SD boot card.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_jpeg_crop import bl, patched, stub_write
from tools.x100v_preview_alias_candidate import read_elf_text
from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_exif_dimension_serializer import (
    EXIF_HOOK, EXIF_HOOK_STOCK, EXIF_STUB, execute,
)

STUB_SIZE = 116
STUB_SHA256 = "f483d71d4cbedd0296ec85adaeb7487ee0aec473842619ecf81d8cd679ef9e12"
CARD5D_WRITES_SHA256 = "5f26f1dbf6657cfe3652f7b32c704a0db177888ecae7713ac3336bf8adbc0d44"
PRIMARY_LOAD, SECONDARY_LOAD = 0x00F21000, 0x01BA0000
CASES = (
    ("L 16:9 -> 65:24",6240,3512,2,0,6240,2304),
    ("M 16:9 -> 65:24",4416,2488,2,0,4416,1632),
    ("S 16:9 -> 65:24",3120,1760,2,0,3120,1152),
    ("L 3:2 control",6240,4160,2,0,6240,4160),
    ("M 3:2 control",4416,2944,2,0,4416,2944),
    ("S 3:2 control",3120,2080,2,0,3120,2080),
    ("L aspect-0 control",6240,3512,0,0,6240,3512),
    ("L aspect-4 control",6240,3512,4,0,6240,3512),
    ("small preview control",640,480,2,0,640,480),
    ("alternate lookup, aspect 2",6240,3512,2,1,4416,2944),
    ("alternate lookup, aspect 0",640,480,0,255,4416,2944),
)


def plan(primary: bytes, secondary: bytes, stub: bytes) -> list[dict]:
    if len(stub) != STUB_SIZE or hashlib.sha256(stub).hexdigest() != STUB_SHA256:
        raise ValueError("unrecognized assembled EXIF stub")
    offset = EXIF_HOOK-SECONDARY_LOAD
    before = struct.pack("<I",EXIF_HOOK_STOCK)
    if secondary[offset:offset+4] != before:
        raise ValueError("stock EXIF hook bytes differ")
    return [
        stub_write({6:primary,7:secondary},EXIF_STUB,stub,"exif-dimension-stub"),
        dict(field="exif-dimension-hook",partition=7,address=EXIF_HOOK,
             partition_offset=offset,before_hex=before.hex(),
             after_hex=struct.pack("<I",bl(EXIF_HOOK,EXIF_STUB)).hex()),
    ]


def merge_card5d(path: Path, exif_writes: list[dict], images: dict[int, bytes]) -> list[dict]:
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest() != CARD5D_WRITES_SHA256:
        raise ValueError("unrecognized card 5d write list")
    card=json.loads(data)
    expected={"jpeg-crop-stub","jpeg-crop-hook",
              "raf-aspect-ratio-pair-code2-first","raf-aspect-ratio-pair-code2-second",
              "metadata-version-minor-marker"}
    if len(card)!=5 or {w["field"] for w in card}!=expected:
        raise ValueError("card 5d write fields differ")
    combined=card+exif_writes
    regions={6:[],7:[]}
    for w in combined:
        part=w["partition"]
        base=PRIMARY_LOAD if part==6 else SECONDARY_LOAD
        if part not in regions or w.get("address",base+w["partition_offset"]) != base+w["partition_offset"]:
            raise ValueError("write partition/address mismatch")
        before=bytes.fromhex(w["before_hex"])
        after=bytes.fromhex(w["after_hex"])
        start=w["partition_offset"]
        if len(before)!=len(after) or not 0 <= start <= len(images[part])-len(before):
            raise ValueError("invalid write length/range")
        if images[part][start:start+len(before)] != before:
            raise ValueError(f"stock bytes differ for {w['field']}")
        regions[part].append((start,start+len(after)))
    for part, spans in regions.items():
        spans.sort()
        if any(a[1]>b[0] for a,b in zip(spans,spans[1:])):
            raise ValueError(f"overlapping writes in partition {part}")
    return combined


def build(update: Path, object_file: Path, output_dir: Path,
          card5d_writes: Path | None = None) -> dict:
    primary,secondary=load_images(update)
    stub=read_elf_text(object_file)
    exif_writes=plan(primary,secondary,stub)
    writes=(merge_card5d(card5d_writes,exif_writes,{6:primary,7:secondary})
            if card5d_writes else exif_writes)
    images=patched({6:primary,7:secondary},writes)
    for part,old in ((6,primary),(7,secondary)):
        want=bytearray(old)
        for w in writes:
            if w["partition"]==part:
                at=w["partition_offset"]
                new=bytes.fromhex(w["after_hex"])
                want[at:at+len(new)]=new
        if images[part] != bytes(want):
            raise AssertionError(f"unexpected changes in decoded partition {part}")
    rows=[]
    for name,width,height,aspect,flag,expected_width,expected_height in CASES:
        row=execute(primary,secondary,width,height,aspect=aspect,flag=flag,stub=stub)
        if (row["serialized_width"],row["serialized_height"]) != (expected_width,expected_height):
            raise AssertionError(f"wrong synthetic EXIF result: {name}")
        rows.append(dict(case=name,**row))
    manifest=dict(scope="Experimental decoded-partition delta; no SD boot, package or camera acceptance",
                  update_sha256=hashlib.sha256(update.read_bytes()).hexdigest(),
                  stock_primary_sha256=hashlib.sha256(primary).hexdigest(),
                  stock_secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                  stub_sha256=STUB_SHA256,writes=writes,arm_cases=rows,
                  card5d_write_list_sha256=CARD5D_WRITES_SHA256 if card5d_writes else None,
                  primary_sha256=hashlib.sha256(images[6]).hexdigest(),
                  secondary_sha256=hashlib.sha256(images[7]).hexdigest())
    output_dir.mkdir(parents=True,exist_ok=False)
    (output_dir/"primary-exif-dimension-experimental.bin").write_bytes(images[6])
    (output_dir/"secondary-exif-dimension-experimental.bin").write_bytes(images[7])
    with (output_dir/"manifest.json").open("x") as f:
        json.dump(manifest,f,indent=2)
        f.write("\n")
    if card5d_writes:
        keys=("field","partition","partition_offset","before_hex","after_hex")
        with (output_dir/"card-5d-plus-exif-writes.json").open("x") as f:
            json.dump([{key:w[key] for key in keys} for w in writes],f,indent=2)
            f.write("\n")
    return manifest


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock",type=Path,required=True)
    parser.add_argument("--stub-object",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--card5d-writes",type=Path)
    args=parser.parse_args()
    result=build(args.stock,args.stub_object,args.output_dir,args.card5d_writes)
    print(f"{len(result['writes'])} exact writes; {len(result['arm_cases'])} paired ARM cases passed")


if __name__=="__main__":
    main()
