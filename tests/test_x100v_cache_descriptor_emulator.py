import struct

import pytest

from tools.x100v_cache_descriptor_emulator import reference_descriptor


def test_independent_marker_vector():
    active = bytearray(0x600)
    markers = {4: 5, 15: 0xAB, 0x71: 0x11, 0x72: 0x12, 0x6D: 0x13,
               0x6B: 0x14, 0x6C: 0xEE, 0x70: 4, 0x78: 0x15, 0x79: 0x16,
               0x524: 0x17, 0x6E: 0x18, 0x6F: 0x19, 0x595: 0x1A,
               0x40F: 0x1B, 0x413: 0x1C, 0x414: 0x1D, 0x415: 0x1E,
               0x520: 0x1F, 0x521: 0x20, 0x534: 0x21, 0x530: 0x22,
               0x572: 0x23, 0x57B: 0x24, 0x57E: 0x25, 0x57F: 0x26}
    for offset, value in markers.items():
        active[offset] = value
    assert reference_descriptor(bytes(active)) == bytes.fromhex(
        "00 05 11 12 13 14 04 15 16 17 18 19 1a 00 1b 1c "
        "1d 1e 1f 20 21 14 22 23 24 a5 a5 a5 ab 00 00 00 25 26 a5 a5")
    active[0] = 45
    result = reference_descriptor(bytes(active))
    assert result[5] == result[21] == 0xEE
    assert result[6] == 4


@pytest.mark.parametrize("mode,gate,expected", [
    (0, 0, 1), (5, 0, 171), (6, 0, 3), (7, 0, 3), (8, 0, 1),
    (9, 0, 3), (10, 0, 3), (11, 0, 0x87654321), (11, 1, 2), (255, 0, 1),
])
def test_independent_word_vectors(mode, gate, expected):
    active = bytearray(0x600)
    active[4], active[15], active[20] = mode, 171, gate
    struct.pack_into("<I", active, 24, 0x87654321)
    assert struct.unpack_from("<I", reference_descriptor(bytes(active)), 28)[0] == expected


def test_rejects_uncovered_helper_branch_and_wrong_length():
    active = bytearray(0x600)
    active[0x47] = 1
    with pytest.raises(ValueError):
        reference_descriptor(bytes(active))
    with pytest.raises(ValueError):
        reference_descriptor(bytes(36))
