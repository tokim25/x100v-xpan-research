"""Merge a tested preview-guard stub into card 5f's exact offline write list.

This emits a local experiment write list only. It does not write an SD card or
produce a flashable update. Source identities and all unchanged writes are
checked before emitting output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_16x9_to_65x24 import stock_partitions
from tools.x100v_jpeg_crop import LOADS, STUB_ADDRESS

DAT_SHA256 = "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591"
CARD5F_SHA256 = "7bcf4a377e9fed55982b0a491a2a9cc96e6808fe7b335b73d358623532b82b1b"
BASE_FIELDS = {
    "jpeg-crop-stub", "jpeg-crop-hook", "raf-aspect-ratio-pair-code2-first",
    "raf-aspect-ratio-pair-code2-second", "metadata-version-minor-marker",
    "exif-dimension-stub", "exif-dimension-hook",
}


def merge(update: Path, baseline: Path, preview_manifest: Path) -> list[dict]:
    update_data = update.read_bytes()
    if hashlib.sha256(update_data).hexdigest() != DAT_SHA256:
        raise ValueError("unrecognized official X100V DAT")
    baseline_data = baseline.read_bytes()
    if hashlib.sha256(baseline_data).hexdigest() != CARD5F_SHA256:
        raise ValueError("unrecognized card-5f write list")
    before = json.loads(baseline_data)
    preview = json.loads(preview_manifest.read_text())["writes"]
    base_by_name = {w["field"]: w for w in before}
    preview_by_name = {w["field"]: w for w in preview}
    if len(before) != 7 or set(base_by_name) != BASE_FIELDS:
        raise ValueError("card-5f write fields changed")
    if set(preview_by_name) != {
        "jpeg-crop-stub", "jpeg-crop-hook", "raf-aspect-ratio-pair-code2-first",
        "raf-aspect-ratio-pair-code2-second",
    }:
        raise ValueError("unexpected preview-manifest write fields")
    if any(
        base_by_name[name]["after_hex"] != preview_by_name[name]["after_hex"]
        for name in preview_by_name if name != "jpeg-crop-stub"
    ):
        raise ValueError("preview manifest changes a non-stub card-5f write")

    old_stub = base_by_name["jpeg-crop-stub"]
    new_stub = preview_by_name["jpeg-crop-stub"]
    if old_stub["partition"] != 6 or new_stub["partition"] != 6:
        raise ValueError("JPEG stub must be in primary partition")
    if old_stub["partition_offset"] != new_stub["partition_offset"]:
        raise ValueError("JPEG stub address changed")
    if new_stub["address"] != STUB_ADDRESS:
        raise ValueError("unexpected JPEG stub address")
    if len(bytes.fromhex(new_stub["after_hex"])) > 0x0128FE00 - STUB_ADDRESS:
        raise ValueError("preview stub overlaps EXIF stub")

    merged = [dict(w) for w in before]
    merged[before.index(old_stub)] = {
        **old_stub,
        "before_hex": new_stub["before_hex"],
        "after_hex": new_stub["after_hex"],
    }
    images = stock_partitions(update_data)
    regions: dict[int, list[tuple[int, int]]] = {6: [], 7: []}
    for write in merged:
        part = write["partition"]
        if part not in regions:
            raise ValueError("unsupported write partition")
        start = write["partition_offset"]
        old = bytes.fromhex(write["before_hex"])
        new = bytes.fromhex(write["after_hex"])
        if len(old) != len(new) or not 0 <= start <= len(images[part]) - len(old):
            raise ValueError(f"invalid write range: {write['field']}")
        if images[part][start:start + len(old)] != old:
            raise ValueError(f"source bytes changed: {write['field']}")
        if "address" in write and write["address"] != LOADS[part] + start:
            raise ValueError(f"write address changed: {write['field']}")
        regions[part].append((start, start + len(new)))
    for spans in regions.values():
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise ValueError("overlapping writes")
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--card5f-writes", type=Path, required=True)
    parser.add_argument("--preview-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    writes = merge(args.stock, args.card5f_writes, args.preview_manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(writes, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"writes": len(writes), "fields": [w["field"] for w in writes]}))


if __name__ == "__main__":
    main()
