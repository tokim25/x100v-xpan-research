"""Independent reference vectors for the geometry-only XPan model."""

from tools.x100v_xpan_simulator import (
    Rect, RecbfBufferDescriptor, centered_crop, counterfactual_code4_height,
    isolated_recbf_centered_rewrite, isolated_recbf_centered_rewrite_allowed,
    isolated_recbf_b34_flags, isolated_recbf_bit10_source_address,
    isolated_recbf_selector_from_lookup,
    isolated_recbf_1218_script_mode,
    isolated_recbf_event_code4_rect,
    isolated_recbf_post_helper_slot, simulate_x100v,
)


def test_x100v_65_24_reference_vector() -> None:
    # 6240 * 24 / 65 = 2304; (4160 - 2304) / 2 = 928.
    expected = Rect(0, 928, 6240, 2304)
    assert centered_crop(6240, 4160, 65, 24) == expected
    model = simulate_x100v()
    assert model["rendered_jpeg_candidate"] == {"x": 0, "y": 928, "width": 6240, "height": 2304}
    assert model["raf_candidate"]["retained_raw_area"]["height"] == 4160
    assert model["raf_candidate"]["not_a_physical_raw_crop"] is True


def test_existing_1_1_reference_vector() -> None:
    assert centered_crop(6240, 4160, 1, 1) == Rect(1040, 0, 4160, 4160)


def test_existing_16_9_integer_vector() -> None:
    # Exact mathematical crop is 3510 high. Official X100V JPEG is 3512 high,
    # so firmware alignment/rounding differs from this geometry-only oracle.
    assert centered_crop(6240, 4160, 16, 9) == Rect(0, 325, 6240, 3510)


def test_input_validation() -> None:
    try:
        centered_crop(6240, 4160, 65, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero ratio must be rejected")


def test_code4_counterfactual_independent_vectors() -> None:
    # 6240 × 24/65 is exactly 2304; 6240 × 2/3 is exactly 4160.
    assert counterfactual_code4_height(6240, "gfx100_5_18") == 2304
    assert counterfactual_code4_height(6240, "x100v_3_01") == 4160
    # A non-multiple checks truncation separately: 6501 × 24/65 = 2400.369...
    assert counterfactual_code4_height(6501, "gfx100_5_18") == 2400
    assert counterfactual_code4_height(6501, "x100v_3_01") == 4334
    model = simulate_x100v()
    assert model["counterfactual_code4_at_6240_width"]["x100v_unmodified_downstream_height"] == 4160


def test_isolated_recbf_event_helper_independent_vectors() -> None:
    # Synthetic helper input: X code 4 defaults to 4:3. Height 4160 gives
    # 4160*4/3 = 5546.66..., rounded down to a multiple of four: 5544.
    assert isolated_recbf_event_code4_rect(6240, 4160, "x100v_3_01") == Rect(348, 0, 5544, 4160)
    # GFX code 4 is explicit 65:24: 6240*24/65 = 2304 exactly.
    assert isolated_recbf_event_code4_rect(6240, 4160, "gfx100_5_18") == Rect(0, 928, 6240, 2304)
    # Non-divisible vertical case checks the helper's four-pixel alignment.
    assert isolated_recbf_event_code4_rect(4000, 3000, "gfx100_5_18") == Rect(0, 762, 4000, 1476)
    assert isolated_recbf_event_code4_rect(3000, 2250, "x100v_3_01") == Rect(0, 0, 3000, 2250)
    result = simulate_x100v()["isolated_recbf_event_helper_code4_at_6240x4160"]
    assert result["x100v_unmodified"] == {"x": 348, "y": 0, "width": 5544, "height": 4160}
    try:
        isolated_recbf_event_code4_rect(0, 4160, "gfx100_5_18")
    except ValueError:
        pass
    else:
        raise AssertionError("zero helper width must be rejected")


def test_isolated_recbf_centered_rewrite_guard_matrix() -> None:
    # Independent truth table from the disassembled comparisons and branch destinations.
    assert isolated_recbf_centered_rewrite_allowed(29, 0, 0, 2) is False
    assert isolated_recbf_centered_rewrite_allowed(29, 0, 0, 0) is True
    assert isolated_recbf_centered_rewrite_allowed(45, 7, 0, 0) is False
    assert isolated_recbf_centered_rewrite_allowed(45, 8, 0, 0) is False
    assert isolated_recbf_centered_rewrite_allowed(45, 6, 0, 0) is True
    for subtype in (3, 4, 5, 13):
        assert isolated_recbf_centered_rewrite_allowed(32, 0, subtype, 0) is False
    assert isolated_recbf_centered_rewrite_allowed(32, 0, 6, 0) is True


def test_isolated_1218_script_mode_independent_truth_table() -> None:
    # Hand-enumerated ARM branch destinations; these are synthetic states.
    for inputs, expected in (
        ((0, 25, 0, 0), 35),
        ((4, 25, 0, 0), 37),
        ((5, 26, 0, 0), 37),
        ((0, 25, 1, 0), 36),
        ((4, 25, 1, 0), 38),
        ((0, 44, 0, 0), 36),
        ((4, 44, 0, 0), 38),
        ((0, 45, 1, 7), 35),
        ((4, 45, 1, 8), 37),
        ((0, 45, 1, 6), 36),
    ):
        assert isolated_recbf_1218_script_mode(*inputs) == expected
    assert not isolated_recbf_centered_rewrite_allowed(45, 7, 0, 0)
    try:
        isolated_recbf_1218_script_mode(256, 25, 0, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-range script selector field must fail closed")


def test_isolated_recbf_descriptor_rewrite_independent_vectors() -> None:
    # Synthetic 6240x4160 2-byte/pixel descriptor; no claim of actual camera address/stride.
    original = RecbfBufferDescriptor(0x10000000, 51_916_800, 12_480, 12_480, 4160)
    cropped = isolated_recbf_centered_rewrite(original, 6240, 2304)
    assert cropped == RecbfBufferDescriptor(
        0x10000000 + 11_581_440, 28_753_920, 12_480, 12_480, 2304,
    )
    # Current code-4 table gives 0x0 for the three known size rows. If reached,
    # the helper centers an empty descriptor rather than preserving full size.
    empty = isolated_recbf_centered_rewrite(original, 0, 0)
    assert empty == RecbfBufferDescriptor(
        0x10000000 + 25_964_640, 0, 12_480, 0, 0,
    )


def test_recbf_post_helper_slot_independent_truth_table() -> None:
    # ARM branch priority: state 25, state 26, or bit 10 routes command 0x15
    # to +0xf0. The unrelated 0x16 command still routes to +0xd4.
    assert isolated_recbf_post_helper_slot(25, 0, 0x15) == 0xF0
    assert isolated_recbf_post_helper_slot(26, 0, 0x15) == 0xF0
    assert isolated_recbf_post_helper_slot(29, 1, 0x15) == 0xF0
    assert isolated_recbf_post_helper_slot(29, 0, 0x15) == 0xD4
    assert isolated_recbf_post_helper_slot(32, 0, 0x15) == 0xD4
    assert isolated_recbf_post_helper_slot(25, 1, 0x16) == 0xD4


def test_recbf_b34_flag_mapping_independent_vectors() -> None:
    # Independently enumerated bit positions from the three ARM TST/ORR steps.
    assert isolated_recbf_b34_flags(0) == 0
    assert isolated_recbf_b34_flags(1) == 0x2000
    assert isolated_recbf_b34_flags(2) == 0x0400
    assert isolated_recbf_b34_flags(4) == 0x4000
    assert isolated_recbf_b34_flags(7) == 0x6400
    assert isolated_recbf_b34_flags(0x8002) == 0x0400


def test_recbf_indexed_bit_source_address_independent_vectors() -> None:
    # 0x0341ccb8 + 0x9960 + 0x222 = 0x0342683a; each index changes
    # the selected input by 288 bytes, including signed negative indices.
    assert isolated_recbf_bit10_source_address(0) == 0x0342683A
    assert isolated_recbf_bit10_source_address(1) == 0x0342695A
    assert isolated_recbf_bit10_source_address(-1) == 0x0342671A


def test_recbf_lookup_result_to_signed_selector_independent_vectors() -> None:
    # The ARM path subtracts one, stores a halfword, then later sign-extends it.
    assert isolated_recbf_selector_from_lookup(0) == -1
    assert isolated_recbf_selector_from_lookup(1) == 0
    assert isolated_recbf_selector_from_lookup(2) == 1
    assert isolated_recbf_selector_from_lookup(-0x8000) == 0x7FFF
    assert isolated_recbf_bit10_source_address(isolated_recbf_selector_from_lookup(0)) == 0x0342671A
    for bad in (-0x8001, 0x8000):
        try:
            isolated_recbf_selector_from_lookup(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("out-of-range lookup result must be rejected")
