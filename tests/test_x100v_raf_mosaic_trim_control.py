"""Independent small-vector checks for the offline CFA row-trim experiment."""

import struct

import pytest

from tools.x100v_raf_mosaic_trim_control import trim_mosaic


def sample_raf() -> tuple[bytes, dict[int, int]]:
    # Intentionally tiny: 30 rows x 12 pixels, with a 24 x 10 visible area.
    # A 6-row shift preserves the X-Trans row phase. Each row has its own value.
    cfa_off, tiff_prefix, width, height = 0x100, 256, 12, 30
    source = bytearray(cfa_off + tiff_prefix + width * height * 2)
    source[:16] = b"FUJIFILMCCD-RAW "
    struct.pack_into(">6I", source, 0x54, 0x70, 4, 0x80, 52,
                     cfa_off, tiff_prefix + width * height * 2)
    source[0x70:0x74] = b"JPEG"
    records = {
        0x100: (30, 12),
        0x110: (3, 1),
        0x111: (24, 10),
        0x112: (10, 24),
        0x113: (24, 10),
        0x119: (24, 10),
    }
    offsets = {}
    struct.pack_into(">I", source, 0x80, len(records))
    for i, (tag, pair) in enumerate(records.items()):
        pos = 0x84 + 8 * i
        offsets[tag] = pos + 4
        struct.pack_into(">HHHH", source, pos, tag, 4, *pair)
    source[cfa_off:cfa_off + 8] = b"II*\0" + struct.pack("<I", 8)
    struct.pack_into("<H", source, cfa_off + 8, 1)
    struct.pack_into("<HHII", source, cfa_off + 10, 0xF000, 13, 1, 64)
    struct.pack_into("<H", source, cfa_off + 64, 4)
    for i, (tag, value) in enumerate(((0xF001, width), (0xF002, height),
                                      (0xF007, tiff_prefix),
                                      (0xF008, width * height * 2))):
        struct.pack_into("<HHII", source, cfa_off + 66 + 12 * i,
                         tag, 4, 1, value)
    for row in range(height):
        struct.pack_into("<12H", source, cfa_off + tiff_prefix + row * 24,
                         *(row * 100 + col for col in range(width)))
    return bytes(source), offsets


def trim(source: bytes) -> tuple[bytes, dict]:
    return trim_mosaic(source, expected_full=(30, 12),
                       expected_origin=(3, 1), expected_visible=(24, 10),
                       start_rows=6, target_full_height=18)


def test_reference_vector_rows_lengths_and_geometry():
    source, offsets = sample_raf()
    result, facts = trim(source)
    assert len(result) == 0x100 + 256 + 18 * 12 * 2
    assert result[0x70:0x74] == source[0x70:0x74] == b"JPEG"
    for tag, expected in {
        0x100: (18, 12), 0x110: (3, 1), 0x111: (12, 10),
        0x112: (10, 12), 0x113: (12, 10), 0x119: (12, 10),
    }.items():
        assert struct.unpack_from(">HH", result, offsets[tag]) == expected
    assert struct.unpack_from(">I", result, 0x68)[0] == 256 + 18 * 24
    assert struct.unpack_from("<I", result, 0x100 + 66 + 12 + 8)[0] == 18
    assert struct.unpack_from("<I", result, 0x100 + 66 + 36 + 8)[0] == 18 * 24
    rows = result[0x200:]
    assert rows == source[0x200 + 6 * 24:0x200 + 24 * 24]
    assert struct.unpack_from("<12H", rows, 0) == tuple(600 + col for col in range(12))
    assert struct.unpack_from("<12H", rows, 17 * 24) == tuple(2300 + col for col in range(12))
    assert facts["target_visible"] == [12, 10]


def test_rejects_phase_shift_and_unexpected_source():
    source, offsets = sample_raf()
    with pytest.raises(ValueError, match="phase"):
        trim_mosaic(source, expected_full=(30, 12), expected_origin=(3, 1),
                    expected_visible=(24, 10), start_rows=5, target_full_height=18)
    corrupt = bytearray(source)
    struct.pack_into(">H", corrupt, offsets[0x111], 23)
    with pytest.raises(ValueError, match="differs from expected"):
        trim(bytes(corrupt))


def test_rejects_inconsistent_payload_length():
    source, _ = sample_raf()
    corrupt = bytearray(source)
    struct.pack_into("<I", corrupt, 0x100 + 66 + 36 + 8, 719)
    with pytest.raises(ValueError, match="not contiguous"):
        trim(bytes(corrupt))
