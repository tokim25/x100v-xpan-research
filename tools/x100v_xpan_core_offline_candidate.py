"""Build an EXPERIMENTAL decoded-primary X100V 65:24 core candidate.

Only static size, crop-lookup, ratio, and preview-key slices are included.
The result is NOT a DAT, SD-boot image, or camera-validated firmware.
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
    parse_primary_records,
    plan_x100v_code4_ratio_stub,
    plan_x100v_preview_code4_zero_placeholder_reuse,
    plan_x100v_size_and_raw_crop_lookup_data,
    preview_key_lookup_index,
    read_aspect_dimension_grid,
    read_crop_ratio_jump_target,
    read_preview_key_table,
)
from tools.x100v_ratio_offline_candidate import apply_exact_partition_writes


EXPECTED_SIZES = ((6240, 2304), (4416, 1632), (3120, 1152))


def build_offline_core_candidate(update: Path, output_dir: Path) -> dict:
    """Write one exact-byte decoded image and manifest to a new directory."""
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
    primary_digest = hashlib.sha256(primary).hexdigest()
    if primary_digest != source["primary_sha256"]:
        raise ValueError("X100V decoded primary hash mismatch")

    ratio = plan_x100v_code4_ratio_stub(primary, source)
    size_writes = plan_x100v_size_and_raw_crop_lookup_data(primary, source)
    preview_rows = plan_x100v_preview_code4_zero_placeholder_reuse(primary, source)
    if [row["index"] for row in preview_rows] != [1, 2, 9, 10, 17, 18]:
        raise ValueError("X100V preview placeholder row indices differ")
    load = source["primary_load"]
    preview_writes = [{
        "field": f"preview-code4-row-{row['index']}",
        "partition_offset": source["preview_key_table"] - load + 8 * row["index"],
        "address": source["preview_key_table"] + 8 * row["index"],
        "before_hex": row["source_hex"],
        "after_hex": row["candidate_hex"],
    } for row in preview_rows]
    writes = [*ratio["writes"], *size_writes, *preview_writes]
    candidate = apply_exact_partition_writes(primary, writes)

    before_targets = [read_crop_ratio_jump_target(primary, load, source["crop_ratio_helper"], code)
                      for code in range(1, 8)]
    after_targets = [read_crop_ratio_jump_target(candidate, load, source["crop_ratio_helper"], code)
                     for code in range(1, 8)]
    if after_targets != [*before_targets[:3], source["crop_ratio_code4_stub_candidate"], *before_targets[4:]]:
        raise ValueError("candidate changed another ratio-dispatch target")
    before_preview = read_preview_key_table(primary, load, source["preview_key_table"], 57)
    after_preview = read_preview_key_table(candidate, load, source["preview_key_table"], 57)
    if [row for row in before_preview if row["key"][2] == 2] != [
        row for row in after_preview if row["key"][2] == 2
    ]:
        raise ValueError("candidate changed active 16:9 preview rows")
    if [row["index"] for row in after_preview if row["key"][2] == 4] != [1, 2, 9, 10, 17, 18]:
        raise ValueError("candidate code-4 preview coverage differs")
    removed_code0_keys = []
    for row in preview_rows:
        old_key = tuple(row["key_before"])
        if preview_key_lookup_index(before_preview, old_key) != row["index"]:
            raise ValueError("original code-0 lookup differs")
        if preview_key_lookup_index(after_preview, old_key) != 57:
            raise ValueError("candidate unexpectedly retains code-0 lookup")
        if preview_key_lookup_index(after_preview, tuple(row["key_after"])) != row["index"]:
            raise ValueError("candidate code-4 lookup differs")
        removed_code0_keys.append(row["key_before"])
    records = {row["id"]: row for row in parse_primary_records(candidate, source["primary_table"])}
    for level, size_id in enumerate((4, 11, 18)):
        row = records[size_id]
        if (row["width"], row["height"], row["enabled_byte"]) != (*EXPECTED_SIZES[level], 1):
            raise ValueError("candidate selectable code-4 size row differs")
    widths = read_aspect_dimension_grid(candidate, load, source["dimension_lookup_width"], 3, 5)
    heights = read_aspect_dimension_grid(candidate, load, source["dimension_lookup_height"], 3, 5)
    if [(widths[level][4], heights[level][4]) for level in range(3)] != list(EXPECTED_SIZES):
        raise ValueError("candidate RAW-crop code-4 lookup differs")
    changed_bytes = sum(old != new for old, new in zip(primary, candidate))
    if changed_bytes != 66:
        raise ValueError("candidate diff does not match independent 66-byte expectation")

    manifest = {
        "kind": "experimental decoded-primary X100V 65:24 core candidate",
        "flashable": False,
        "update_package_built": False,
        "code0_preview_runtime_use_verified": False,
        "stub_executable_mapping_verified": False,
        "lcd_evf_ovf_verified": False,
        "jpeg_raf_verified": False,
        "cross_path_geometry_verified": False,
        "medium_geometry_discrepancy": {
            "table_candidate": [4416, 1632],
            "patched_arm_helper_on_stock_medium": [4416, 1628],
            "evidence": "results/x100v-gfx-ratio-arm-comparison.json",
            "stock_gfx_has_same_kind_of_difference": True,
            "equality_is_established_invariant": False,
            "resolved": False,
        },
        "camera_verified": False,
        "source_update_sha256": update_digest,
        "source_primary_sha256": primary_digest,
        "candidate_primary_sha256": hashlib.sha256(candidate).hexdigest(),
        "primary_load_address": f"{load:#010x}",
        "write_span_count": len(writes),
        "changed_byte_count": changed_bytes,
        "other_ratio_codes_preserved": True,
        "active_16_9_preview_rows_preserved": True,
        "removed_code0_nonbypass_preview_keys": removed_code0_keys,
        "removed_code0_nonbypass_lookup_returns_miss_57": True,
        "primary_lookup_wrapper_spins_on_miss_57_if_runtime_requests_old_code0_key": True,
        "secondary_lookup_caller_falls_back_to_row0_on_miss_57": True,
        "preview_table_row_count_unchanged": 57,
        "writes": writes,
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "primary-xpan-core-experimental.bin").write_bytes(candidate)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x100v", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_offline_core_candidate(args.x100v, args.output_dir), indent=2))


if __name__ == "__main__":
    main()
