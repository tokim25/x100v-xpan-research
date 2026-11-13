import struct

import pytest

from tools.x100v_ovf_frame_6524 import SCALE, new_frame_y, parse, reshape


def _path(commands: bytes, points) -> bytes:
    header = struct.pack("<5I2f", 1, 0x29A, 0x1901, 0x1801, 0x1701, 0.75, 10.0) + bytes(16)
    body = struct.pack("<II", len(commands), 8 * len(points))
    body += commands + bytes((len(commands) // 4 + 1) * 4 - len(commands))
    for x, y in points:
        body += struct.pack("<2f", x, y)
    return header + body


def _outline(x0, x1, top, bottom):
    """A two-unit outline with a gap in its top edge, in the stock point order."""
    return [(x0, bottom), (x0, top), (305, top), (305, top + 2), (x0 + 2, top + 2), (x0 + 2, bottom - 2),
            (x1 - 2, bottom - 2), (x1 - 2, top + 2), (335, top + 2), (335, top), (x1, top), (x1, bottom)]


def _drawing() -> bytes:
    blob = b"GVFF" + bytes(0x34)
    blob += _path(b"\x02\x04\x04\x04\x00", [(0, 0), (640, 0), (640, -480), (0, -480)])
    tops = (-390, -360, -340, -320, -300, -290, -280)
    for i, top in enumerate(tops):
        blob += _path(b"\x02" + b"\x04" * 11 + b"\x00", _outline(10 + 20 * i, 630 - 20 * i, top, -480 - top))
    for i in range(14):
        top = tops[i // 2]
        blob += _path(b"\x02\x04\x04\x04", [(313, top - 5), (319, top - 5), (319, top + 5), (313, top + 5)])
    return blob


def test_scale_is_6524_over_169():
    assert SCALE == pytest.approx(128 / 195)
    # A 620-wide 16:9 frame is 348.75 tall; scaled it is 228.92, and 620 / 228.92 = 65 / 24.
    assert 620 / (348.75 * SCALE) == pytest.approx(65 / 24)


def test_frame_edges_scale_about_the_centre_and_keep_thickness():
    # Worked by hand: top -390, bottom -90, centre -240. Half height 150 * 128/195 = 98.4615.
    assert new_frame_y(-390, -390, -90) == pytest.approx(-338.4615, abs=1e-3)
    assert new_frame_y(-388, -390, -90) == pytest.approx(-336.4615, abs=1e-3)
    assert new_frame_y(-90, -390, -90) == pytest.approx(-141.5385, abs=1e-3)
    assert new_frame_y(-92, -390, -90) == pytest.approx(-143.5385, abs=1e-3)
    with pytest.raises(ValueError):
        new_frame_y(-240, -390, -90)


def test_reshape_moves_only_y_values_and_carries_labels_with_their_frame():
    stock = _drawing()
    new, report = reshape(stock)
    assert len(new) == len(stock) and len(report) == 7
    before, after = parse(stock), parse(new)
    assert [p["commands"] for p in before] == [p["commands"] for p in after]
    assert after[0]["points"] == before[0]["points"]
    for b, a in zip(before[1:], after[1:]):
        assert [x for x, _ in b["points"]] == [x for x, _ in a["points"]]
    # First frame: top -390 -> -338.4615, a shift of 51.5385; its two labels move with it.
    assert min(y for _, y in after[1]["points"]) == pytest.approx(-338.4615, abs=1e-3)
    for label in (8, 9):
        shift = after[label]["points"][0][1] - before[label]["points"][0][1]
        assert shift == pytest.approx(51.5385, abs=1e-3)


def test_unexpected_drawings_are_rejected():
    with pytest.raises(ValueError):
        reshape(b"XXXX" + _drawing()[4:])
    with pytest.raises(ValueError):
        reshape(_drawing()[:0x38 + 200])
