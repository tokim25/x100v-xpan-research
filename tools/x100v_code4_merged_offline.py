"""Compose a selectable code-4 X100V container for offline analysis only.

This deliberately preserves the stock code-2 ratio and JPEG behavior. It
does not establish preview-cache safety, code-4 encoder input geometry,
RAW-editor crop, finder framing, updater acceptance, or rollback. Never put
this output on an SD card or camera without a separate approved test plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from tools.x100v_preview_alias_candidate import read_elf_text
from tools.x100v_update_package import (
    STOCK_SHA256, apply_writes, audit_container, build_container,
    read_primary, read_secondary,
)

INTEGRATED_SHA256 = "1dcdfeebc5330721846b11ec1afa676a8d36e49c45f2ecf058c5a7e998d13d81"
CARD5I_SHA256 = "6a57f43b388b3c3bd5d5ae4f6198754a690fd74ec0394d0ef87347f27b104841"
CODE4_JPEG_SHA256 = "2655ae0650f1e298204d0dec93115b0b9e2c9feb876e75809fad2439a9ec1b5f"
CODE2_EXIF_SHA256 = "b91e179d74fbe1641c582612146df4c358b732b1e47d3bcba41dd08733a3c2ac"
OLD_GUARD = struct.pack("<I", 0xE3500002)
NEW_GUARD = struct.pack("<I", 0xE3500004)
CODE2_RATIO_FIELDS = {"raf-aspect-ratio-pair-code2-first", "raf-aspect-ratio-pair-code2-second"}
HOOK_FIELDS = {"jpeg-crop-hook", "exif-dimension-hook"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assemble(source: Path, object_path: Path) -> bytes:
    subprocess.run(
        ["clang", "--target=armv7a-none-eabi", "-c", str(source), "-o", str(object_path)],
        check=True,
    )
    return read_elf_text(object_path)


def compose(integrated_data: bytes, card5i_data: bytes,
            jpeg_stub: bytes, exif_code2_stub: bytes) -> list[dict]:
    if sha(integrated_data) != INTEGRATED_SHA256 or sha(card5i_data) != CARD5I_SHA256:
        raise ValueError("unrecognized integrated/card-5i manifest")
    integrated = json.loads(integrated_data)
    card5i = json.loads(card5i_data)
    if (integrated["source_update_sha256"] != STOCK_SHA256
            or integrated["write_count"] != 36 or len(integrated["writes"]) != 36):
        raise ValueError("integrated source or write inventory changed")
    if (len(card5i) != 7 or {w["field"] for w in card5i} !=
            HOOK_FIELDS | CODE2_RATIO_FIELDS |
            {"jpeg-crop-stub", "exif-dimension-stub", "metadata-version-minor-marker"}):
        raise ValueError("card-5i write inventory changed")
    if len(jpeg_stub) != 196 or sha(jpeg_stub) != CODE4_JPEG_SHA256:
        raise ValueError("code-4-only JPEG stub identity changed")
    if len(exif_code2_stub) != 128 or sha(exif_code2_stub) != CODE2_EXIF_SHA256:
        raise ValueError("card-5i EXIF stub identity changed")
    old_exif = next(w for w in card5i if w["field"] == "exif-dimension-stub")
    if bytes.fromhex(old_exif["after_hex"]) != exif_code2_stub or exif_code2_stub.count(OLD_GUARD) != 1:
        raise ValueError("EXIF stub is not the expected aspect-2 source")
    exif_code4_stub = exif_code2_stub.replace(OLD_GUARD, NEW_GUARD)
    old_jpeg = next(w for w in card5i if w["field"] == "jpeg-crop-stub")
    if len(bytes.fromhex(old_jpeg["after_hex"])) != 200 or bytes.fromhex(old_jpeg["before_hex"]) != bytes(200):
        raise ValueError("card-5i JPEG cave differs")

    writes = [{**w, "partition": 6} for w in integrated["writes"]]
    if {w["field"] for w in writes} & (HOOK_FIELDS | CODE2_RATIO_FIELDS):
        raise ValueError("integrated writes unexpectedly overlap capture hooks")
    for w in card5i:
        if w["field"] in HOOK_FIELDS:
            writes.append(dict(w))
        elif w["field"] == "jpeg-crop-stub":
            writes.append({**w, "before_hex": bytes(len(jpeg_stub)).hex(),
                           "after_hex": jpeg_stub.hex()})
        elif w["field"] == "exif-dimension-stub":
            writes.append({**w, "after_hex": exif_code4_stub.hex()})
    if len(writes) != 40 or any(w["field"] in CODE2_RATIO_FIELDS for w in writes):
        raise ValueError("merged write inventory differs")
    return writes


def build(stock: bytes, writes: list[dict]) -> tuple[bytes, dict]:
    if sha(stock) != STOCK_SHA256:
        raise ValueError("stock DAT identity differs")
    _, primary = read_primary(stock)
    _, secondary = read_secondary(stock)
    # This also rejects overlap, length mismatch, changed old bytes and
    # any out-of-bounds slice before the container encoder is invoked.
    for number, part in ((6, primary), (7, secondary)):
        apply_writes(part, [w for w in writes if w["partition"] == number])
    candidate, stats = build_container(stock, writes)
    audit = audit_container(stock, candidate, writes)
    if not all(v is True for k, v in audit.items() if isinstance(v, bool)):
        raise ValueError("container audit did not pass")
    return candidate, {"build": stats, "audit": audit}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--integrated-manifest", type=Path, required=True)
    parser.add_argument("--card5i-writes", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(args.output_dir)
    with tempfile.TemporaryDirectory(prefix="xpan-code4-merge-") as folder:
        temp = Path(folder)
        jpeg = assemble(Path("tools/x100v_jpeg_crop_block_code4_only_stub.s"), temp / "jpeg.o")
        exif = assemble(Path("tools/x100v_exif_dimension_stub_preview.s"), temp / "exif.o")
        writes = compose(args.integrated_manifest.read_bytes(), args.card5i_writes.read_bytes(), jpeg, exif)
    candidate, report = build(args.stock.read_bytes(), writes)
    manifest = {
        "kind": "selectable code-4 offline integration; NOT FOR CARD OR CAMERA",
        "source_update_sha256": STOCK_SHA256,
        "input_manifest_sha256": [INTEGRATED_SHA256, CARD5I_SHA256],
        "code4_jpeg_stub_sha256": CODE4_JPEG_SHA256,
        "code4_exif_stub_sha256": sha(exif.replace(OLD_GUARD, NEW_GUARD)),
        "write_count": len(writes),
        "code2_ratio_edits_excluded": True,
        "code2_jpeg_crop_guarded_off": True,
        "camera_safe": False,
        "updater_acceptance_verified": False,
        "rollback_verified": False,
        "code4_capture_geometry_verified": False,
        "preview_cache_count_and_status_safe": False,
        "raw_default_crop_verified": False,
        "finder_frame_verified": False,
        **report,
    }
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "writes.json").write_text(json.dumps(writes, indent=2) + "\n")
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output_dir / "candidate-update-NOT-FOR-CARD.DAT").write_bytes(candidate)
    print(json.dumps({"write_count": len(writes), "audit": report["audit"]}, indent=2))


if __name__ == "__main__":
    main()
