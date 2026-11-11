from tools.x100v_ovf_window_6524 import (TABLE, is_16x9, is_consistent, record_6524,
                                         record_address)

# Stock records copied from the decoded primary partition (variant 1, slots 1 and 2).
STOCK_L6_3X2 = (1280, 960, 1280, 852, 4, 54, 148, 150, 72, 376, 832, 554, 76, 202)
STOCK_L6_16X9 = (1280, 960, 1280, 852, 4, 54, 192, 192, 72, 376, 832, 468, 76, 246)
STOCK_L7_16X9 = (1280, 960, 1280, 852, 0, 54, 336, 336, 920, 40, 320, 180, 920, 390)

# Worked by hand: 832*24/65 = 307.2 -> 307; top 192 + (468-307)//2 = 272;
# bottom 852-272-307 = 273; y 54+272 = 326. 320*24/65 = 118.2 -> 118;
# top 336 + 31 = 367; bottom 852-367-118 = 367; y 54+367 = 421.
EXPECTED_L6 = (1280, 960, 1280, 852, 4, 54, 272, 273, 72, 376, 832, 307, 76, 326)
EXPECTED_L7 = (1280, 960, 1280, 852, 0, 54, 367, 367, 920, 40, 320, 118, 920, 421)


def test_record_addresses():
    assert record_address(0, 0, 0) == TABLE
    assert record_address(1, 6, 2) == 0x014B9998
    assert record_address(1, 7, 2) == 0x014B9B20


def test_stock_records_are_recognised():
    assert is_16x9(STOCK_L6_16X9) and is_16x9(STOCK_L7_16X9)
    assert is_consistent(STOCK_L6_3X2) and not is_16x9(STOCK_L6_3X2)


def test_new_records_are_centred_65x24():
    for stock, expected in ((STOCK_L6_16X9, EXPECTED_L6), (STOCK_L7_16X9, EXPECTED_L7)):
        new = record_6524(stock)
        assert new == expected
        assert is_consistent(new)
        w, h = new[10], new[11]
        assert abs(w / h - 65 / 24) < 0.02
        # vertical centre moves by at most half a row
        assert abs((new[13] + h / 2) - (stock[13] + stock[11] / 2)) <= 0.5


# Card 5m: variant 0, layouts 0 to 3 (LCD and finder-panel live view), stock slot 2.
STOCK_LIVE_VIEW = {
    0: (900, 600, 900, 600, 0, 0, 47, 47, 0, 0, 900, 506, 0, 47),
    1: (1280, 960, 1280, 852, 0, 54, 66, 66, 0, 0, 1280, 720, 0, 120),
    2: (1280, 960, 1088, 720, 96, 120, 56, 56, 4, 4, 1080, 608, 100, 176),
    3: (1280, 960, 376, 250, 903, 710, 19, 20, 0, 1, 375, 211, 903, 729),
}
# Worked by hand: heights 900*24/65 = 332, 1280 -> 472, 1080 -> 398, 375 -> 138.
# LCD: top 47 + (506-332)//2 = 134, bottom 600-134-332 = 134, y 134.
# L1: top 66 + 124 = 190, bottom 852-190-472 = 190, y 54+190 = 244.
# L2: top 56 + 105 = 161, bottom 720-161-398 = 161, y 120+161 = 281.
# L3: top 19 + 36 = 55, bottom 250-55-138 = 57, y 710+55 = 765.
EXPECTED_LIVE_VIEW = {
    0: (900, 600, 900, 600, 0, 0, 134, 134, 0, 0, 900, 332, 0, 134),
    1: (1280, 960, 1280, 852, 0, 54, 190, 190, 0, 0, 1280, 472, 0, 244),
    2: (1280, 960, 1088, 720, 96, 120, 161, 161, 4, 4, 1080, 398, 100, 281),
    3: (1280, 960, 376, 250, 903, 710, 55, 57, 0, 1, 375, 138, 903, 765),
}


def test_live_view_records_are_centred_65x24():
    for layout, stock in STOCK_LIVE_VIEW.items():
        assert is_16x9(stock)
        new = record_6524(stock)
        assert new == EXPECTED_LIVE_VIEW[layout]
        assert is_consistent(new)
        assert abs(new[10] / new[11] - 65 / 24) < 0.02
        assert abs((new[13] + new[11] / 2) - (stock[13] + stock[11] / 2)) <= 0.5


# Card 6b: variant 1, layouts 4 and 5 on the 720x480 plane, stock slot 2.
STOCK_OVF_FRAME = {
    4: (720, 480, 720, 480, 0, 0, 108, 108, 40, 208, 472, 264, 40, 108),
    5: (720, 480, 720, 480, 0, 0, 189, 189, 520, 16, 184, 102, 520, 189),
}
# Worked by hand: 472*24/65 = 174.3 -> 174; top 108 + (264-174)//2 = 153;
# bottom 480-153-174 = 153. 184*24/65 = 67.9 -> 67; top 189 + (102-67)//2 = 206;
# bottom 480-206-67 = 207.
EXPECTED_OVF_FRAME = {
    4: (720, 480, 720, 480, 0, 0, 153, 153, 40, 208, 472, 174, 40, 153),
    5: (720, 480, 720, 480, 0, 0, 206, 207, 520, 16, 184, 67, 520, 206),
}


def test_ovf_frame_records_are_centred_65x24():
    for layout, stock in STOCK_OVF_FRAME.items():
        assert is_16x9(stock)
        new = record_6524(stock)
        assert new == EXPECTED_OVF_FRAME[layout]
        assert is_consistent(new)
        assert abs((new[13] + new[11] / 2) - (stock[13] + stock[11] / 2)) <= 0.5


def test_3x2_records_are_not_taken_for_16x9():
    assert not is_16x9((720, 480, 720, 480, 0, 0, 83, 83, 40, 208, 472, 314, 40, 83))
    assert not is_16x9(STOCK_L6_3X2)
