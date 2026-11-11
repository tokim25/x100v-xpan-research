"""Independent small RAF vectors for the synthetic C000 geometry probe."""

import hashlib
import struct

import pytest

from tools.x100v_raf_c000_probe import HEIGHT_OFFSETS, c000_payload_offset, make_probe


def fixture(height=3510):
    data = bytearray(0x300)
    data[:16] = b"FUJIFILMCCD-RAW "
    struct.pack_into(">II", data, 0x5C, 0x100, 4 + 4 + 0x80)
    struct.pack_into(">IHH", data, 0x100, 1, 0xC000, 0x80)
    for relative in HEIGHT_OFFSETS:
        struct.pack_into("<I", data, 0x108 + relative, height)
    return bytes(data)


def test_probe_changes_only_five_known_words():
    source = fixture()
    result, offsets = make_probe(source)
    assert offsets == [0x108 + offset for offset in (0x28, 0x30, 0x40, 0x48, 0x50)]
    assert len(result) == len(source)
    assert hashlib.sha256(result).digest() != hashlib.sha256(source).digest()
    expected = bytearray(source)
    for offset in offsets:
        expected[offset:offset + 4] = bytes.fromhex("00090000")
    assert result == bytes(expected)


def test_probe_refuses_unexpected_original_height():
    with pytest.raises(ValueError, match="not 3510"):
        make_probe(fixture(4160))


def test_probe_refuses_non_raf():
    with pytest.raises(ValueError, match="not a RAF"):
        c000_payload_offset(bytes(0x300))
