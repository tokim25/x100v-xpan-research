"""Isolated X100V path gates and 65:24 geometry model. Does not execute firmware.

This deliberately writes no update file and makes no claim about camera behavior.
It gives us independently testable branch outcomes and rectangles for later
firmware/emulator or physical-camera comparisons.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


X100V_UPDATE_SHA256 = "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591"
X100V_FULL_WIDTH = 6240
X100V_FULL_HEIGHT = 4160
UPDATE_HEADER_SIZE = 532


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True)
class RecbfBufferDescriptor:
    """Only the four fields read/written by the bounded crop-helper trace."""

    base_address: int
    byte_count: int
    stride_bytes: int
    width_units: int
    height: int


def isolated_recbf_1218_script_mode(
    submode_9d9: int, state_5b0: int, flag_9da: int, subtype_5bd: int,
) -> int:
    """Model only the 0x01f3a818..918 selector for modes 35–38.

    A returned mode does not imply queue delivery or normal-still execution.
    """
    if any(not 0 <= value <= 255 for value in (
        submode_9d9, state_5b0, flag_9da, subtype_5bd,
    )):
        raise ValueError("script selector fields must be bytes")
    crop_mode = (37 if submode_9d9 in (4, 5) else 35)
    helper_nonzero = state_5b0 == 45 and subtype_5bd in (7, 8)
    return crop_mode if state_5b0 != 44 and (helper_nonzero or flag_9da == 0) else crop_mode + 1


def isolated_recbf_centered_rewrite_allowed(
    state: int, subtype_5bd: int, subtype_5cd: int, caller_flag: int,
) -> bool:
    """Model the observed guard at 0x01ede9e8 and later state-32 gate.

    This says nothing about whether the helper is invoked in a normal shot.
    """
    if any(not 0 <= value <= 255 for value in (state, subtype_5bd, subtype_5cd, caller_flag)):
        raise ValueError("guard fields must be bytes")
    if caller_flag or (state == 45 and subtype_5bd in (7, 8)):
        return False
    if state == 32 and subtype_5cd in (3, 4, 5, 13):
        return False
    return True


def isolated_recbf_post_helper_slot(state: int, b34_bit10: int, command: int) -> int:
    """Model only the destination branch at 0x01f3f034..078.

    This does not claim that the command, helper, or later compression runs.
    """
    if not 0 <= state <= 255 or b34_bit10 not in (0, 1) or command not in (0x15, 0x16):
        raise ValueError("unsupported state, flag, or command")
    if command == 0x15 and (state in (25, 26) or b34_bit10):
        return 0xF0
    return 0xD4


def isolated_recbf_b34_flags(input_halfword: int) -> int:
    """Map only the three input bits in primary helper 0x01164268."""
    if not 0 <= input_halfword <= 0xFFFF:
        raise ValueError("input must be a 16-bit unsigned value")
    return (
        ((input_halfword & 1) << 13)
        | (((input_halfword >> 1) & 1) << 10)
        | (((input_halfword >> 2) & 1) << 14)
    )


def isolated_recbf_bit10_source_address(signed_selector: int) -> int:
    """Address of the +0x222 input bit for one synthetic selector value.

    The caller obtains this selector from per-slot state; this function does
    not know its runtime value or whether the selected region is initialized.
    """
    if not -0x8000 <= signed_selector <= 0x7FFF:
        raise ValueError("selector must fit a signed 16-bit value")
    return (0x0341CCB8 + 0x9960 + 288 * signed_selector + 0x222) & 0xFFFFFFFF


def isolated_recbf_selector_from_lookup(lookup_result: int) -> int:
    """Model the 16-bit store of lookup result minus one at 0x01f12750..58.

    A lookup miss returns zero, hence a signed selector of -1. This is not a
    range check or proof that any selected address is initialized in a shot.
    """
    if not -0x8000 <= lookup_result <= 0x7FFF:
        raise ValueError("lookup result must fit a signed 16-bit value")
    low_half = (lookup_result - 1) & 0xFFFF
    return low_half - 0x10000 if low_half & 0x8000 else low_half


def isolated_recbf_centered_rewrite(
    original: RecbfBufferDescriptor, target_width_pixels: int, target_height: int,
) -> RecbfBufferDescriptor:
    """Model 0x01edeabc..af4 on synthetic inputs, including 32-bit wrap.

    Target width is doubled into descriptor units. A zero target is accepted
    because the traced ARM block has no dimension check between lookup and
    stores; this is not evidence that real still capture reaches the block.
    """
    fields = (
        original.base_address, original.byte_count, original.stride_bytes,
        original.width_units, original.height, target_width_pixels, target_height,
    )
    if any(not 0 <= value <= 0xFFFFFFFF for value in fields):
        raise ValueError("descriptor fields must be unsigned 32-bit words")
    target_width_units = (target_width_pixels << 1) & 0xFFFFFFFF
    vertical = ((original.height - target_height) & 0xFFFFFFFF) >> 1
    horizontal = ((original.width_units - target_width_units) & 0xFFFFFFFF) >> 1
    base = (original.base_address + original.stride_bytes * vertical + horizontal) & 0xFFFFFFFF
    byte_count = (target_height * original.stride_bytes) & 0xFFFFFFFF
    return RecbfBufferDescriptor(base, byte_count, original.stride_bytes, target_width_units, target_height)


def centered_crop(width: int, height: int, ratio_width: int, ratio_height: int) -> Rect:
    """Largest centered integer-pixel rectangle at an exact rational ratio."""
    if min(width, height, ratio_width, ratio_height) <= 0:
        raise ValueError("dimensions and ratio must be positive")
    if width * ratio_height >= height * ratio_width:
        crop_height = height
        crop_width = height * ratio_width // ratio_height
    else:
        crop_width = width
        crop_height = width * ratio_height // ratio_width
    return Rect((width - crop_width) // 2, (height - crop_height) // 2, crop_width, crop_height)


def counterfactual_code4_height(width: int, model: str) -> int:
    """Model only the observed positive-width code-4 geometry branch.

    X100V's unmodified converter does not emit code 4. This asks what its
    downstream ratio routine would calculate *if* code 4 reached it; it is
    neither execution of firmware nor a claim about actual captured pixels.
    """
    if width <= 0:
        raise ValueError("width must be positive")
    if model == "x100v_3_01":
        return width * 2 // 3  # bounded routine's default branch
    if model == "gfx100_5_18":
        return width * 24 // 65  # bounded routine's explicit code-4 branch
    raise ValueError(f"unknown firmware model: {model}")


def isolated_recbf_event_code4_rect(width: int, height: int, model: str) -> Rect:
    """Model the isolated, observed record-buffer event ratio helper.

    Inputs are helper dimensions, not sensor dimensions. The actual event
    receiver first computes a native-aspect base rectangle, and normal
    still-capture reachability has not been established.
    """
    if width <= 0 or height <= 0:
        raise ValueError("helper dimensions must be positive")
    if model == "x100v_3_01":
        numerator, denominator = 4, 3  # unmodified code-4 default
    elif model == "gfx100_5_18":
        numerator, denominator = 65, 24  # explicit code-4 branch
    else:
        raise ValueError(f"unknown firmware model: {model}")
    comparison = height * numerator - width * denominator
    if comparison > 0:
        selected_height = (width * denominator // numerator) & ~3
        return Rect(0, (height - selected_height) // 2, width, selected_height)
    if comparison < 0:
        selected_width = (height * numerator // denominator) & ~3
        return Rect((width - selected_width) // 2, 0, selected_width, height)
    return Rect(0, 0, width, height)


def simulate_x100v(ratio_width: int = 65, ratio_height: int = 24) -> dict:
    full = Rect(0, 0, X100V_FULL_WIDTH, X100V_FULL_HEIGHT)
    crop = centered_crop(full.width, full.height, ratio_width, ratio_height)
    result = {
        "kind": "geometry_reference_only_not_firmware_emulation",
        "source_sensor_area": asdict(full),
        "selected_aspect": f"{ratio_width}:{ratio_height}",
        "rendered_jpeg_candidate": asdict(crop),
        "evf_lcd_framing_candidate": asdict(crop),
        "ovf": {
            "action": "draw_bright_frame_guide",
            "nominal_sensor_rectangle": asdict(crop),
            "parallax_compensation": "unknown; cannot simulate without lens/focus data",
        },
        "raf_candidate": {
            "retained_raw_area": asdict(full),
            "reversible_user_aspect": f"{ratio_width}:{ratio_height}",
            "metadata_field_to_verify": "RAF RawImageAspectRatio (0x115)",
            "not_a_physical_raw_crop": True,
        },
        "unknowns": [
            "X100V menu eligibility and enum wiring",
            "live-view rendering/AF overlays",
            "JPEG encoder size tables and pixel alignment",
            "OVF parallax correction and bright-frame mapping",
            "RAF metadata and preview writer behavior",
            "update validation and recovery",
        ],
    }
    if (ratio_width, ratio_height) == (65, 24):
        result["counterfactual_code4_at_6240_width"] = {
            "x100v_unmodified_downstream_height": counterfactual_code4_height(6240, "x100v_3_01"),
            "gfx100_explicit_branch_height": counterfactual_code4_height(6240, "gfx100_5_18"),
            "scope": "bounded positive-width arithmetic only; X100V converter never emits code 4",
        }
        result["isolated_recbf_event_helper_code4_at_6240x4160"] = {
            "x100v_unmodified": asdict(isolated_recbf_event_code4_rect(6240, 4160, "x100v_3_01")),
            "gfx100_homolog": asdict(isolated_recbf_event_code4_rect(6240, 4160, "gfx100_5_18")),
            "scope": "synthetic helper inputs only; receiver's native-base step and still-capture reachability excluded",
        }
        synthetic_descriptor = RecbfBufferDescriptor(0x10000000, 51_916_800, 12_480, 12_480, 4160)
        result["isolated_recbf_descriptor_code4_first_three_rows"] = {
            "input": asdict(synthetic_descriptor),
            "current_zero_table_output_if_guard_passes": asdict(
                isolated_recbf_centered_rewrite(synthetic_descriptor, 0, 0)
            ),
            "nonzero_6240x2304_control": asdict(
                isolated_recbf_centered_rewrite(synthetic_descriptor, 6240, 2304)
            ),
            "scope": "synthetic 2-byte/pixel descriptor and conditional guard; not firmware execution or saved-image evidence",
        }
    return result


def inspect_update(path: Path) -> dict:
    """Read-only identity check; no update construction or signature claims."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        header = handle.read(UPDATE_HEADER_SIZE)
        digest.update(header)
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if len(header) != UPDATE_HEADER_SIZE:
        raise ValueError("update is smaller than the known 532-byte header")
    version_major = int.from_bytes(header[516:520], "little")
    version_minor = int.from_bytes(header[520:524], "little")
    return {
        "path": str(path.resolve()),
        "sha256": digest.hexdigest(),
        "matches_supplied_x100v_3_01": digest.hexdigest() == X100V_UPDATE_SHA256,
        "header_size": UPDATE_HEADER_SIZE,
        "header_format_word": int.from_bytes(header[:4], "little"),
        "version_words": [version_major, version_minor],
        "interpretation_limit": "identity only; not an update signature or bootability check",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect-update", type=Path, help="read-only identity of a local update DAT")
    parser.add_argument("--ratio", default="65:24", help="virtual aspect ratio, default 65:24")
    args = parser.parse_args()
    parts = args.ratio.split(":")
    if len(parts) != 2:
        parser.error("--ratio must be WIDTH:HEIGHT")
    try:
        ratio_width, ratio_height = (int(part) for part in parts)
        result = simulate_x100v(ratio_width, ratio_height)
        if args.inspect_update:
            result["update_identity"] = inspect_update(args.inspect_update)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
