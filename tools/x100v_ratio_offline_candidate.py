"""Build an EXPERIMENTAL decoded X100V primary-partition ratio candidate.

This is not an update DAT or SD-boot image. It cannot be flashed. It only
materializes the code-4 ratio-stub manifest for independent byte inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_firmware_probe import HEADER_SIZE
from tools.fuji_xpan_validation import (
    SOURCES,
    decode_partition,
    plan_x100v_code4_ratio_stub,
    read_crop_ratio_jump_target,
)


def apply_exact_partition_writes(original: bytes, writes: list[dict]) -> bytes:
    """Apply a nonoverlapping manifest to a copy, checking every old byte."""
    occupied: set[int] = set()
    for write in writes:
        offset = write["partition_offset"]
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        extent = set(range(offset, offset + len(before)))
        if (offset < 0 or not before or len(before) != len(after)
                or offset + len(before) > len(original) or occupied & extent):
            raise ValueError("invalid or overlapping exact-byte write")
        if original[offset:offset + len(before)] != before or before == after:
            raise ValueError("original partition does not match write precondition")
        occupied.update(extent)
    candidate = bytearray(original)
    expected_changed = set()
    for write in writes:
        offset = write["partition_offset"]
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        candidate[offset:offset + len(after)] = after
        expected_changed.update(offset + index for index, (old, new) in enumerate(zip(before, after)) if old != new)
    observed_changed = {index for index, (old, new) in enumerate(zip(original, candidate)) if old != new}
    if observed_changed != expected_changed:
        raise ValueError("candidate diff differs from exact-byte manifest")
    return bytes(candidate)


def build_offline_ratio_candidate(update: Path, output_dir: Path) -> dict:
    """Emit only a decoded-partition copy plus manifest into a new directory."""
    if output_dir.exists():
        raise FileExistsError(f"refusing existing output directory: {output_dir}")
    source = SOURCES["x100v_3_01"]
    original_update = update.read_bytes()
    update_digest = hashlib.sha256(original_update).hexdigest()
    if update_digest != source["sha256"]:
        raise ValueError("X100V update hash mismatch; refusing pinned offsets")
    if struct.unpack_from("<I", original_update)[0] != 6 or struct.unpack_from("<II", original_update, 516) != source["version"]:
        raise ValueError("X100V update header or version mismatch")
    payload = bytes(value ^ 0xFF for value in original_update[HEADER_SIZE:])
    primary = decode_partition(payload, source["primary_header"])
    original_primary_digest = hashlib.sha256(primary).hexdigest()
    if original_primary_digest != source["primary_sha256"]:
        raise ValueError("X100V decoded primary hash mismatch")
    plan = plan_x100v_code4_ratio_stub(primary, source)
    candidate = apply_exact_partition_writes(primary, plan["writes"])
    helper = source["crop_ratio_helper"]
    load = source["primary_load"]
    before_targets = [read_crop_ratio_jump_target(primary, load, helper, code) for code in range(1, 8)]
    after_targets = [read_crop_ratio_jump_target(candidate, load, helper, code) for code in range(1, 8)]
    if after_targets != [*before_targets[:3], source["crop_ratio_code4_stub_candidate"], *before_targets[4:]]:
        raise ValueError("candidate changed another aspect-code jump target")
    manifest = {
        "kind": "experimental decoded-primary ratio-only candidate",
        "flashable": False,
        "update_package_built": False,
        "executable_mapping_verified": False,
        "camera_verified": False,
        "source_update_sha256": update_digest,
        "source_primary_sha256": original_primary_digest,
        "candidate_primary_sha256": hashlib.sha256(candidate).hexdigest(),
        "primary_load_address": f"{load:#010x}",
        "writes": plan["writes"],
        "stub_words": plan["stub_words"],
        "code4_jump_target_before": f"{before_targets[3]:#010x}",
        "code4_jump_target_after": f"{after_targets[3]:#010x}",
        "other_jump_targets_preserved": all(before_targets[i] == after_targets[i] for i in (0, 1, 2, 4, 5, 6)),
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "primary-ratio-code4-experimental.bin").write_bytes(candidate)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x100v", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_offline_ratio_candidate(args.x100v, args.output_dir)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
