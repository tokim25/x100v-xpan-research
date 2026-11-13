import struct
from pathlib import Path

import pytest

from tools.x100v_vg_aspect_rect_probe import ROWS, STOCK_6524_640, rect_6524, writes_for

LOAD = 0x01BA0000


def _synthetic() -> bytes:
    data = bytearray(0x730000)
    for address, rect in list(ROWS.items()) + [STOCK_6524_640]:
        struct.pack_into("<4I", data, address - LOAD, *rect)
    return bytes(data)


def test_rectangles_are_centred_65x24():
    # Worked by hand: 640*24/65 = 236.3 -> 236, y 60 + (360-236)//2 = 122. That equals
    # the firmware's own 65:24 row. 900 -> 332, y 47 + 87 = 134. 1280 -> 472, y 120 + 124 = 244.
    assert rect_6524((0, 60, 640, 360)) == (0, 122, 640, 236) == STOCK_6524_640[1]
    assert rect_6524((0, 47, 900, 506)) == (0, 134, 900, 332)
    assert rect_6524((0, 120, 1280, 720)) == (0, 244, 1280, 472)


def test_writes_cover_y_width_height_of_the_three_rows():
    writes = writes_for(_synthetic())
    assert [w["address"] for w in writes] == ["0x022bf04c", "0x022bf0cc", "0x022bf14c"]
    assert writes[0]["before_hex"] == struct.pack("<3I", 60, 640, 360).hex()
    assert writes[0]["after_hex"] == struct.pack("<3I", 122, 640, 236).hex()
    assert all(w["partition"] == 7 for w in writes)


def test_changed_stock_is_rejected():
    data = bytearray(_synthetic())
    struct.pack_into("<I", data, 0x022BF0C8 + 12 - LOAD, 500)
    with pytest.raises(ValueError):
        writes_for(bytes(data))


def test_pinned_secondary_matches_when_cached():
    path = Path("out/fw-cache/x100v-301-part7.bin")
    if not path.exists():
        pytest.skip("decoded secondary not cached")
    assert len(writes_for(path.read_bytes())) == 3
