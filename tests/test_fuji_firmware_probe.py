import struct

from tools.fuji_firmware_probe import candidate_lzss_headers, lzss_decode
from tools.fuji_xpan_validation import decode_partition


def test_lzss_literal_and_backreference_vector() -> None:
    # 0x03 'ABC', then 0x8033 => distance 3, length 3.
    assert lzss_decode(b"\x03ABC\x803", 6) == b"ABCABC"


def test_lzss_rejects_declared_size_mismatch() -> None:
    try:
        lzss_decode(b"\x03ABC", 4)
    except ValueError:
        pass
    else:
        raise AssertionError("declared output length must be exact")


def test_packed_extent_includes_header_independent_vector() -> None:
    # Six encoded bytes produce ABCABC. The 26-byte packed extent includes
    # the 20-byte header; zeros after that extent are not part of the stream.
    header = struct.pack("<5I", 6, 26, 1, 0x4000, 4)
    payload = b"PRE" + header + b"\x03ABC\x803" + b"\x00" * 20
    rows = candidate_lzss_headers(payload)
    assert rows == [{
        "payload_offset": 3,
        "output_size": 6,
        "packed_size": 26,
        "block_count": 1,
        "flags": 4,
    }]
    assert decode_partition(payload, 3) == b"ABCABC"


def test_lzss_rejects_padding_and_invalid_backreferences() -> None:
    for stream in (b"\x03ABC\x00", b"\x03ABC\x80\x00", b"\x03ABC\x80\x30"):
        try:
            lzss_decode(stream, 3)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid trailing command must be rejected")


def test_partition_rejects_padding_inside_declared_extent() -> None:
    # A falsely enlarged packed extent must not pass just because the decoded
    # byte count was already reached before the zero-filled tail.
    payload = struct.pack("<5I", 6, 46, 1, 0x4000, 4) + b"\x03ABC\x803" + b"\x00" * 20
    try:
        decode_partition(payload, 0)
    except ValueError as exc:
        assert "zero-length literal" in str(exc)
    else:
        raise AssertionError("padding inside the packed extent must fail closed")
