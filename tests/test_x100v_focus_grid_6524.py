import struct
from pathlib import Path

import pytest

from tools.x100v_focus_grid_6524 import (NEW_ROWS, ROW_24X65, STOCK_ROW, TABLE, fits,
                                         grid_y_offset, writes_for)

# Window heights in tenths of a pixel, as the routine uses them: the LCD's
# stock 16:9 window (506 rows) and card 5m's 65:24 window (332 rows).
STOCK_16X9, CARD_5M = 5060, 3320


def test_seven_rows_underflow_in_the_short_window():
    # Worked by hand for cell 600: 3320 - 4200 = -880 -> 0xFFFFFC90 >> 1 = 0x7FFFFE48.
    assert grid_y_offset(CARD_5M, 600, 7) == 0x7FFFFE48
    assert not fits(CARD_5M, 600, 7)
    # Stock: 5060 - 4200 = 860 -> 430.
    assert grid_y_offset(STOCK_16X9, 600, 7) == 430


def test_five_rows_fit_wherever_the_stock_grids_fit():
    # Nine rows fit the 600-row 3:2 window only for cells up to 666; five rows
    # then fit the 332-row window for every cell up to 664.
    assert 6000 // 9 == 666 and CARD_5M // NEW_ROWS == 664
    for cell in range(300, 665):
        assert fits(6000, cell, 9) and fits(STOCK_16X9, cell, 7) and fits(CARD_5M, cell, NEW_ROWS)
    # 3320 - 3000 = 320 -> 160, plus the window's own offset.
    assert grid_y_offset(CARD_5M, 600, NEW_ROWS, 1340) == 1500


def test_write_targets_the_row_count_only():
    path = Path("out/fw-cache/x100v-301-part6.bin")
    if not path.exists():
        pytest.skip("decoded stock primary not cached")
    primary = path.read_bytes()
    (write,) = writes_for(primary)
    assert write["address"] == "0x012911d4" and TABLE + 2 * 16 + 8 == 0x012911D4
    assert write["before_hex"] == struct.pack("<I", STOCK_ROW[2]).hex() == "07000000"
    assert write["after_hex"] == struct.pack("<I", ROW_24X65[2]).hex() == "05000000"
