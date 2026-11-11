import struct

import pytest

from tools.x100v_preview_frame_6524 import TABLE, TARGETS, is_16x9_window, record_address, window_6524

# Expected 65:24 windows worked out by hand: height = width * 24 / 65 rounded
# down, centred in the outer frame; x and width unchanged.
EXPECTED = {
    (0, 0, 900, 600): (0, 134, 900, 332),     # 900*24/65 = 332.3; (600-332)/2 = 134
    (0, 54, 1280, 852): (0, 244, 1280, 472),  # 1280*24/65 = 472.6; 54 + (852-472)/2 = 244
    (904, 710, 375, 250): (904, 766, 375, 138),  # 375*24/65 = 138.5; 710 + (250-138)/2 = 766
}
STOCK_16X9 = {(0, 0, 900, 600): (0, 47, 900, 506), (0, 54, 1280, 852): (0, 120, 1280, 720),
              (904, 710, 375, 250): (904, 729, 375, 211)}


@pytest.mark.parametrize("outer", list(EXPECTED))
def test_window_is_centred_65x24_of_the_same_width(outer):
    new = window_6524(outer, STOCK_16X9[outer])
    assert new == EXPECTED[outer]
    x, y, w, h = new
    assert abs(w / h - 65 / 24) < 0.01
    assert (y - outer[1]) * 2 in (outer[3] - h, outer[3] - h - 1)


def test_stock_16x9_windows_are_recognised_and_others_are_not():
    for outer, inner in STOCK_16X9.items():
        assert is_16x9_window(outer, inner)
    assert not is_16x9_window((0, 0, 900, 600), (0, 0, 900, 600))  # full 3:2
    assert not is_16x9_window((0, 0, 1024, 768), (0, 195, 1024, 378))  # dormant 65:24 row 4


def test_targets_are_the_16x9_rows():
    assert TARGETS == ((0, 2), (0, 9), (0, 15), (1, 15), (2, 15))
    assert record_address(0, 2) == TABLE + 2 * 32
    assert record_address(1, 15) == TABLE + (17 + 15) * 32
