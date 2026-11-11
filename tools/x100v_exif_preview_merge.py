"""Emit an offline-only card-5h EXIF-preview delta; never write an SD card.

Only the EXIF stub is lengthened. The hook and every other card-5h write are
preserved. This is a hypothesis about the preview metadata context, not a
demonstrated camera path or a flashable release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_preview_alias_candidate import read_elf_text
from tools.x100v_exif_dimension_serializer import EXIF_STUB

BASELINE_SHA256 = "6a8aa97ea6fe02ffee9c3e7293cf7063e051472ae413ba29e351fccd6d638736"
ORIGINAL_STUB_SHA256 = "f483d71d4cbedd0296ec85adaeb7487ee0aec473842619ecf81d8cd679ef9e12"
NEW_STUB_SHA256 = "b91e179d74fbe1641c582612146df4c358b732b1e47d3bcba41dd08733a3c2ac"
FIELDS = {
    "jpeg-crop-stub", "jpeg-crop-hook", "raf-aspect-ratio-pair-code2-first",
    "raf-aspect-ratio-pair-code2-second", "metadata-version-minor-marker",
    "exif-dimension-stub", "exif-dimension-hook",
}
LOADS = {6: SOURCES["x100v_3_01"]["primary_load"],
         7: SOURCES["x100v_3_01"]["secondary_load"]}


def merge(primary: bytes, secondary: bytes, baseline_data: bytes, stub: bytes) -> list[dict]:
    if hashlib.sha256(primary).hexdigest() != SOURCES["x100v_3_01"]["primary_sha256"]:
        raise ValueError("unrecognized stock primary")
    if hashlib.sha256(secondary).hexdigest() != SOURCES["x100v_3_01"]["secondary_sha256"]:
        raise ValueError("unrecognized stock secondary")
    if hashlib.sha256(baseline_data).hexdigest() != BASELINE_SHA256:
        raise ValueError("unrecognized card-5h write list")
    if len(stub) != 128 or hashlib.sha256(stub).hexdigest() != NEW_STUB_SHA256:
        raise ValueError("unrecognized assembled EXIF-preview stub")
    writes = json.loads(baseline_data)
    if len(writes) != len(FIELDS) or {w["field"] for w in writes} != FIELDS:
        raise ValueError("unexpected card-5h fields")
    old = next(w for w in writes if w["field"] == "exif-dimension-stub")
    if (old["partition"] != 6 or old["partition_offset"] != EXIF_STUB - LOADS[6]
            or hashlib.sha256(bytes.fromhex(old["after_hex"])).hexdigest()
            != ORIGINAL_STUB_SHA256):
        raise ValueError("card-5h EXIF stub identity changed")
    changed = [{**w} for w in writes]
    replacement = next(w for w in changed if w["field"] == "exif-dimension-stub")
    replacement["before_hex"] = bytes(len(stub)).hex()
    replacement["after_hex"] = stub.hex()
    images = {6: primary, 7: secondary}
    for part in images:
        spans = []
        for write in changed:
            if write["partition"] != part:
                continue
            pos = write["partition_offset"]
            before = bytes.fromhex(write["before_hex"])
            after = bytes.fromhex(write["after_hex"])
            if (len(before) != len(after) or not 0 <= pos <= len(images[part])-len(before)
                    or images[part][pos:pos+len(before)] != before):
                raise ValueError(f"stock bytes/range differ: {write['field']}")
            if "address" in write and write["address"] != LOADS[part] + pos:
                raise ValueError(f"address differs: {write['field']}")
            spans.append((pos, pos+len(before)))
        spans.sort()
        if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
            raise ValueError("overlapping writes")
    if any(a != b for a, b in zip(writes, changed)
           if a["field"] != "exif-dimension-stub"):
        raise AssertionError("unrelated write changed")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--secondary", type=Path, required=True)
    parser.add_argument("--card5h-writes", type=Path, required=True)
    parser.add_argument("--stub-object", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    writes = merge(args.primary.read_bytes(), args.secondary.read_bytes(),
                   args.card5h_writes.read_bytes(), read_elf_text(args.stub_object))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(writes, handle, indent=2)
        handle.write("\n")
    print(f"offline-only {len(writes)} exact writes; EXIF stub 128 bytes")


if __name__ == "__main__":
    main()
