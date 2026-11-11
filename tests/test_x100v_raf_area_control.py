import struct

import pytest

from tools.x100v_raf_area_control import area_payload_offsets, make_control


def sample_raf() -> bytes:
    data = bytearray(0x100)
    data[:16] = b"FUJIFILMCCD-RAW "
    struct.pack_into(">II", data, 0x5C, 0x80, 20)
    struct.pack_into(">I", data, 0x80, 2)
    struct.pack_into(">HHHH", data, 0x84, 0x0110, 4, 13, 6)
    struct.pack_into(">HHHH", data, 0x8C, 0x0111, 4, 4160, 6240)
    return bytes(data)


def test_reference_vector_changes_only_area_payloads():
    source = sample_raf()
    result, offsets = make_control(source)
    assert offsets == {0x0110: 0x88, 0x0111: 0x90}
    assert result[0x88:0x8C] == bytes.fromhex("03af0006")
    assert result[0x90:0x94] == bytes.fromhex("09001860")
    assert {i for i, (a, b) in enumerate(zip(source, result)) if a != b} == {
        0x88, 0x89, 0x90, 0x91,
    }
    assert len(result) == len(source)


def test_rejects_unexpected_source_before_change():
    source = bytearray(sample_raf())
    source[0x88] = 1
    with pytest.raises(ValueError, match="source 0x110"):
        make_control(bytes(source))


def test_rejects_duplicate_area_record():
    source = bytearray(sample_raf())
    struct.pack_into(">H", source, 0x8C, 0x0110)
    with pytest.raises(ValueError, match="duplicate"):
        area_payload_offsets(bytes(source))


def test_small_origin_shift_reference_vector():
    source = sample_raf()
    result, offsets = make_control(
        source, target_origin=(19, 6), target_size=(4154, 6240)
    )
    assert result[offsets[0x0110]:offsets[0x0110] + 4] == bytes.fromhex("00130006")
    assert result[offsets[0x0111]:offsets[0x0111] + 4] == bytes.fromhex("103a1860")
    assert {i for i, (a, b) in enumerate(zip(source, result)) if a != b} == {
        0x89, 0x91,
    }


def test_height_only_reference_vector():
    source = sample_raf()
    result, offsets = make_control(
        source, target_origin=(13, 6), target_size=(2304, 6240)
    )
    assert result[offsets[0x0110]:offsets[0x0110] + 4] == bytes.fromhex("000d0006")
    assert result[offsets[0x0111]:offsets[0x0111] + 4] == bytes.fromhex("09001860")
    assert {i for i, (a, b) in enumerate(zip(source, result)) if a != b} == {
        0x90, 0x91,
    }
