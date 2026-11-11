"""Create a guarded, offline RAF control with physically trimmed CFA rows.

This is a synthetic file-format experiment, not a camera firmware patch.
It never changes its input and does not claim Lightroom compatibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def _cfa_payloads(data: bytes, offset: int, length: int) -> dict[int, int]:
    if offset + length > len(data) or length < 4:
        raise ValueError("CFA directory outside file")
    count = struct.unpack_from(">I", data, offset)[0]
    pos, end = offset + 4, offset + length
    found: dict[int, int] = {}
    for _ in range(count):
        if pos + 4 > end:
            raise ValueError("truncated CFA directory")
        tag, size = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + size > end:
            raise ValueError("CFA record outside directory")
        if tag in (0x100, 0x110, 0x111, 0x112, 0x113, 0x119):
            if tag in found or size != 4:
                raise ValueError(f"duplicate or non-four-byte CFA tag {tag:#x}")
            found[tag] = pos
        pos += size
    if set(found) != {0x100, 0x110, 0x111, 0x112, 0x113, 0x119}:
        raise ValueError("required CFA geometry tags missing")
    return found


def _tiff_scalar_offsets(data: bytes, cfa_offset: int) -> dict[int, int]:
    if data[cfa_offset:cfa_offset + 4] != b"II*\0":
        raise ValueError("CFA payload is not little-endian TIFF")
    root = struct.unpack_from("<I", data, cfa_offset + 4)[0]
    root_count = struct.unpack_from("<H", data, cfa_offset + root)[0]
    subifd = None
    for i in range(root_count):
        pos = cfa_offset + root + 2 + 12 * i
        tag, typ, count, value = struct.unpack_from("<HHII", data, pos)
        if (tag, typ, count) == (0xF000, 13, 1):
            subifd = value
    if subifd is None:
        raise ValueError("missing CFA sub-IFD")
    count = struct.unpack_from("<H", data, cfa_offset + subifd)[0]
    found: dict[int, int] = {}
    for i in range(count):
        pos = cfa_offset + subifd + 2 + 12 * i
        tag, typ, n, _ = struct.unpack_from("<HHII", data, pos)
        if tag in (0xF001, 0xF002, 0xF007, 0xF008):
            if tag in found or (typ, n) != (4, 1):
                raise ValueError(f"invalid CFA TIFF scalar {tag:#x}")
            found[tag] = pos + 8
    if set(found) != {0xF001, 0xF002, 0xF007, 0xF008}:
        raise ValueError("required CFA TIFF scalars missing")
    return found


def trim_mosaic(
    data: bytes,
    *,
    expected_full: tuple[int, int],
    expected_origin: tuple[int, int],
    expected_visible: tuple[int, int],
    start_rows: int,
    target_full_height: int,
) -> tuple[bytes, dict]:
    """Copy a contiguous row window and update only its enclosing geometry.

    Widths and heights use (height, width); origin uses (top, left).
    The original visible top/bottom margins are retained inside the new mosaic.
    """
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    if start_rows < 0 or start_rows % 6 or target_full_height <= 0:
        raise ValueError("invalid X-Trans-phase-preserving row window")
    jpeg_off, jpeg_len, hdr_off, hdr_len, cfa_off, cfa_len = struct.unpack_from(">6I", data, 0x54)
    if jpeg_off + jpeg_len > hdr_off or hdr_off + hdr_len > cfa_off:
        raise ValueError("overlapping RAF sections")
    if cfa_off + cfa_len != len(data):
        raise ValueError("CFA section must end at file end")
    tags = _cfa_payloads(data, hdr_off, hdr_len)
    scalars = _tiff_scalar_offsets(data, cfa_off)
    full_height, full_width = expected_full
    top, left = expected_origin
    visible_height, visible_width = expected_visible
    if top < 0 or left < 0 or top + visible_height > full_height or left + visible_width > full_width:
        raise ValueError("invalid expected visible area")
    if start_rows + target_full_height > full_height:
        raise ValueError("target rows extend beyond source mosaic")
    bottom_margin = full_height - top - visible_height
    target_visible_height = target_full_height - top - bottom_margin
    if target_visible_height <= 0:
        raise ValueError("target leaves no visible rows")
    expected_tags = {
        0x100: expected_full,
        0x110: expected_origin,
        0x111: expected_visible,
        0x112: (visible_width, visible_height),
        0x113: expected_visible,
        0x119: expected_visible,
    }
    for tag, pair in expected_tags.items():
        if struct.unpack_from(">HH", data, tags[tag]) != pair:
            raise ValueError(f"source CFA tag {tag:#x} differs from expected")
    row_bytes = full_width * 2
    data_offset = struct.unpack_from("<I", data, scalars[0xF007])[0]
    raw_bytes = struct.unpack_from("<I", data, scalars[0xF008])[0]
    if (struct.unpack_from("<I", data, scalars[0xF001])[0],
            struct.unpack_from("<I", data, scalars[0xF002])[0]) != (full_width, full_height):
        raise ValueError("CFA TIFF dimensions differ from expected")
    if raw_bytes != row_bytes * full_height or data_offset + raw_bytes != cfa_len:
        raise ValueError("CFA data is not contiguous 16-bit full rows")
    if data_offset < 2 + 12 * 4 or cfa_off + data_offset > len(data):
        raise ValueError("invalid CFA data offset")

    target_raw_bytes = row_bytes * target_full_height
    start = cfa_off + data_offset + start_rows * row_bytes
    end = start + target_raw_bytes
    result = bytearray(data[:cfa_off + data_offset])
    result.extend(data[start:end])
    struct.pack_into(">I", result, 0x68, data_offset + target_raw_bytes)
    for tag, pair in {
        0x100: (target_full_height, full_width),
        0x111: (target_visible_height, visible_width),
        0x112: (visible_width, target_visible_height),
        0x113: (target_visible_height, visible_width),
        0x119: (target_visible_height, visible_width),
    }.items():
        struct.pack_into(">HH", result, tags[tag], *pair)
    struct.pack_into("<I", result, scalars[0xF002], target_full_height)
    struct.pack_into("<I", result, scalars[0xF008], target_raw_bytes)
    if len(result) != cfa_off + data_offset + target_raw_bytes:
        raise AssertionError("trimmed RAF length mismatch")
    if result[cfa_off + data_offset:] != data[start:end]:
        raise AssertionError("trimmed mosaic differs from source row window")
    return bytes(result), {
        "scope": "offline synthetic physical-mosaic trim; not camera output",
        "source_full": list(expected_full),
        "target_full": [target_full_height, full_width],
        "source_visible": list(expected_visible),
        "target_visible": [target_visible_height, visible_width],
        "source_row_start": start_rows,
        "raw_row_bytes": row_bytes,
        "source_cfa_bytes": cfa_len,
        "target_cfa_bytes": data_offset + target_raw_bytes,
        "cfa_unselected_records_unchanged": True,
        "embedded_jpeg_unchanged": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ")
    source = args.source.read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    if source_hash != args.expect_sha256.lower():
        parser.error(f"source hash mismatch: {source_hash}")
    result, facts = trim_mosaic(
        source,
        expected_full=(4182, 6384),
        expected_origin=(13, 6),
        expected_visible=(4160, 6240),
        start_rows=930,
        target_full_height=2326,
    )
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as target:
        target.write(result)
    if hashlib.sha256(args.destination.read_bytes()).digest() != hashlib.sha256(result).digest():
        raise OSError("synthetic RAF readback mismatch")
    print(json.dumps({**facts, "source_sha256": source_hash,
                      "destination_sha256": hashlib.sha256(result).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
