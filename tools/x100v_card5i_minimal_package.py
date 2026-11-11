"""Build an offline six-write card-5i update without its diagnostic version marker.

This is NOT FOR CARD or flash: RAW default crop, finder framing, updater
acceptance, and flash rollback are unresolved. The original DAT is read-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_sd_boot_candidate import STOCK_BUILDS, validate_writes
from tools.x100v_update_package import (
    PRIMARY_LOAD, SECONDARY_OUTPUT_SIZE, STOCK_SHA256, audit_container,
    build_container, read_primary, read_secondary,
)


MANIFEST_SHA256 = "6a57f43b388b3c3bd5d5ae4f6198754a690fd74ec0394d0ef87347f27b104841"
CARD_BOOT_SHA256 = "c728c05b0ae53f57282b9e0a4180d352232cdf048346c39632c89925e58b67de"
MARKER = {
    "field": "metadata-version-minor-marker",
    "partition": 6,
    "partition_offset": 2125816,
    "before_hex": "0130a0e3",
    "after_hex": "9930a0e3",
}
FEATURE_FIELDS = {
    "jpeg-crop-stub", "jpeg-crop-hook", "raf-aspect-ratio-pair-code2-first",
    "raf-aspect-ratio-pair-code2-second", "exif-dimension-stub",
    "exif-dimension-hook",
}
LOADS = {6: PRIMARY_LOAD, 7: 0x01BA0000}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def select_feature_writes(manifest_data: bytes) -> list[dict]:
    if sha(manifest_data) != MANIFEST_SHA256:
        raise ValueError("card-5i manifest is not the pinned physical-test manifest")
    writes = json.loads(manifest_data)
    if (len(writes) != 7 or len({w["field"] for w in writes}) != 7
            or {w["field"] for w in writes} != FEATURE_FIELDS | {MARKER["field"]}):
        raise ValueError("unexpected card-5i write inventory")
    if next(w for w in writes if w["field"] == MARKER["field"]) != MARKER:
        raise ValueError("diagnostic marker bytes differ")
    return [w for w in writes if w["field"] != MARKER["field"]]


def build(stock_raw: bytes, manifest_data: bytes, card_boot: bytes) -> tuple[bytes, dict, list[dict]]:
    if sha(stock_raw) != STOCK_SHA256:
        raise ValueError("official update is not pinned X100V 3.01")
    if sha(card_boot) != CARD_BOOT_SHA256:
        raise ValueError("card-5i boot image differs from physical-test readback")
    writes = select_feature_writes(manifest_data)
    validate_writes(writes, len(card_boot), STOCK_BUILDS["full-image-b13b12c"])
    candidate, build_stats = build_container(stock_raw, writes)
    audit = audit_container(stock_raw, candidate, writes)
    primary = read_primary(candidate)[1]
    secondary = read_secondary(candidate)[1]
    card_primary = card_boot[LOADS[6]:LOADS[6] + len(primary)]
    card_secondary = card_boot[LOADS[7]:LOADS[7] + SECONDARY_OUTPUT_SIZE]
    if secondary != card_secondary:
        raise ValueError("candidate secondary differs from camera-tested card-5i image")
    marker_offset = MARKER["partition_offset"]
    before = bytes.fromhex(MARKER["before_hex"])
    after = bytes.fromhex(MARKER["after_hex"])
    expected_diff = {marker_offset + i for i, (a, b) in enumerate(zip(before, after)) if a != b}
    actual_diff = {i for i, (a, b) in enumerate(zip(primary, card_primary)) if a != b}
    if (actual_diff != expected_diff or primary[marker_offset:marker_offset + len(before)] != before
            or card_primary[marker_offset:marker_offset + len(after)] != after):
        raise ValueError("candidate primary differs beyond the removed diagnostic marker")
    report = {
        "status": "OFFLINE ONLY — NOT FOR CARD OR FLASH",
        "source_sha256": STOCK_SHA256,
        "card5i_boot_sha256": CARD_BOOT_SHA256,
        "removed_diagnostic_field": MARKER["field"],
        "feature_write_count": len(writes),
        "candidate_size": len(candidate),
        "candidate_sha256": sha(candidate),
        "card5i_primary_difference_offsets": sorted(actual_diff),
        "card5i_secondary_identical": True,
        "build": build_stats,
        "audit": audit,
    }
    return candidate, report, writes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--card5i-boot", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    candidate, report, writes = build(
        args.stock.read_bytes(), args.manifest.read_bytes(), args.card5i_boot.read_bytes()
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    with (args.output_dir / "candidate-update-NOT-FOR-CARD.DAT").open("xb") as target:
        target.write(candidate)
    with (args.output_dir / "feature-writes.json").open("x", encoding="utf-8") as target:
        json.dump(writes, target, indent=2)
        target.write("\n")
    with (args.output_dir / "audit.json").open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
