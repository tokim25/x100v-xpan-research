"""Independent header fixtures for the read-only RAF aspect control."""

import argparse
import struct

import pytest

from tools.x100v_raf_aspect_control import aspect_payload_offset, make_control, parse_aspect


def fixture(aspect=(24, 65), tag=0x0115):
    data = bytearray(0x200)
    data[:16] = b"FUJIFILMCCD-RAW "
    struct.pack_into(">II", data, 0x5C, 0x100, 12)
    struct.pack_into(">IHHHH", data, 0x100, 1, tag, 4, *aspect)
    return bytes(data)


def test_changes_only_the_four_byte_aspect_payload():
    source = fixture()
    result, offset = make_control(source)
    assert offset == 0x108
    assert result[:offset] == source[:offset]
    assert result[offset + 4:] == source[offset + 4:]
    assert result[offset:offset + 4] == bytes.fromhex("00090010")


def test_gfx_four_three_to_sixty_five_twenty_four_control():
    source = fixture((3, 4))
    result, offset = make_control(source, (3, 4), (24, 65))
    assert result[:offset] == source[:offset]
    assert result[offset + 4:] == source[offset + 4:]
    assert result[offset:offset + 4] == bytes.fromhex("00180041")
    assert parse_aspect("3:4") == (3, 4)
    assert parse_aspect("24:65") == (24, 65)


@pytest.mark.parametrize("ratio,payload", [
    ((3, 4), bytes.fromhex("00030004")),
    ((1, 1), bytes.fromhex("00010001")),
])
def test_x100v_same_file_ratio_controls(ratio, payload):
    source = fixture((24, 65))
    result, offset = make_control(source, (24, 65), ratio)
    assert result[offset:offset + 4] == payload
    assert result[:offset] == source[:offset]
    assert result[offset + 4:] == source[offset + 4:]


def test_rejects_same_or_out_of_range_aspect():
    with pytest.raises(ValueError, match="must differ"):
        make_control(fixture((3, 4)), (3, 4), (3, 4))
    with pytest.raises(ValueError, match="positive 16-bit"):
        make_control(fixture((3, 4)), (3, 4), (0, 65))
    with pytest.raises(argparse.ArgumentTypeError, match="positive 16-bit"):
        parse_aspect("24:0")


def test_rejects_wrong_source_aspect():
    with pytest.raises(ValueError, match="source aspect"):
        make_control(fixture((2, 3)))


def test_rejects_missing_tag():
    with pytest.raises(ValueError, match="expected one aspect"):
        aspect_payload_offset(fixture(tag=0x0111))


def test_rejects_non_raf():
    with pytest.raises(ValueError, match="not a RAF"):
        aspect_payload_offset(bytes(0x200))
