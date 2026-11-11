"""Independent vectors and fail-closed checks for the offline C000 hook probe."""

from pathlib import Path

import pytest

from tools.x100v_code4_c000_geometry_probe import (
    CAVE,
    FIRST_HOOK,
    LOAD,
    SECOND_HOOK,
    assemble_stub,
    patch_in_memory,
    run_slice,
    sha,
    verify,
)


def stock_secondary() -> bytes:
    data = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert sha(data) == "b116e52462f245b7bfa341ebf75a644baa32590d3957518dbea436456169cb35"
    return data


def test_code4_only_hooks_match_independent_height_vectors():
    stock = stock_secondary()
    stub = assemble_stub()
    patched, writes = patch_in_memory(stock, stub)
    assert [(w["address"], w["after_hex"][:8]) for w in writes] == [
        (hex(FIRST_HOOK), "f224f3ea"),
        (hex(SECOND_HOOK), "f324f3ea"),
        (hex(CAVE), "040053e3"),
    ]
    # Values are calculated independently from the 65:24 and native-ratio
    # formulas, not copied from the probe's expected_height helper.
    for width, code4_height, code2_height, default_height in (
        (6240, 2304, 3510, 4160),
        (4416, 1630, 2484, 2944),
        (3120, 1152, 1755, 2080),
        (768, 283, 432, 512),
    ):
        for which in ("first", "second"):
            assert run_slice(stock, 4, width, which) == default_height
            assert run_slice(patched, 4, width, which) == code4_height
            assert run_slice(patched, 2, width, which) == code2_height
            for unchanged_code in (0, 1, 3, 5, 6):
                assert run_slice(patched, unchanged_code, width, which) == default_height
    for which in ("first", "second"):
        assert run_slice(stock, 4, 0, which) == 0
        assert run_slice(patched, 4, 0, which) == 0
    report = verify(stock, stub)
    assert report["vectors_passed"] == 70
    assert report["camera_safe"] is False
    assert report["saved_raf_crop_verified"] is False


def test_hook_probe_rejects_wrong_source_stub_and_cave():
    stock = stock_secondary()
    stub = assemble_stub()
    wrong_source = bytearray(stock)
    wrong_source[FIRST_HOOK - LOAD] ^= 1
    with pytest.raises(ValueError, match="unrecognized"):
        patch_in_memory(bytes(wrong_source), stub)
    with pytest.raises(ValueError, match="unrecognized geometry stub"):
        patch_in_memory(stock, stub[:-1] + bytes([stub[-1] ^ 1]))
    wrong_cave = bytearray(stock)
    wrong_cave[CAVE - LOAD] = 1
    with pytest.raises(ValueError, match="unrecognized"):
        patch_in_memory(bytes(wrong_cave), stub)
