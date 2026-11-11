"""Make an offline RAF image-area control without changing its source."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def area_payload_offsets(data: bytes) -> dict[int, int]:
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    header, size = struct.unpack_from(">II", data, 0x5C)
    if size < 4 or header + size > len(data):
        raise ValueError("CFA header outside file")
    count = struct.unpack_from(">I", data, header)[0]
    pos, end = header + 4, header + size
    found: dict[int, int] = {}
    for _ in range(count):
        if pos + 4 > end:
            raise ValueError("truncated CFA record")
        tag, length = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + length > end:
            raise ValueError("CFA record outside header")
        if tag in (0x0110, 0x0111):
            if tag in found or length != 4:
                raise ValueError(f"duplicate or non-four-byte area record {tag:#x}")
            found[tag] = pos
        pos += length
    if set(found) != {0x0110, 0x0111}:
        raise ValueError("missing RAF area record")
    return found


def make_control(
    data: bytes,
    *,
    expected_origin: tuple[int, int] = (13, 6),
    expected_size: tuple[int, int] = (4160, 6240),
    target_origin: tuple[int, int] = (943, 6),
    target_size: tuple[int, int] = (2304, 6240),
) -> tuple[bytes, dict[int, int]]:
    pairs = (expected_origin, expected_size, target_origin, target_size)
    if not all(0 <= v <= 0xFFFF for pair in pairs for v in pair):
        raise ValueError("area components must be 16-bit unsigned integers")
    if expected_origin == target_origin and expected_size == target_size:
        raise ValueError("control area must differ")
    offsets = area_payload_offsets(data)
    for tag, expected in ((0x0110, expected_origin), (0x0111, expected_size)):
        if data[offsets[tag]:offsets[tag] + 4] != struct.pack(">HH", *expected):
            raise ValueError(f"source {tag:#x} does not match expected value")
    result = bytearray(data)
    struct.pack_into(">HH", result, offsets[0x0110], *target_origin)
    struct.pack_into(">HH", result, offsets[0x0111], *target_size)
    changed = {i for i, (old, new) in enumerate(zip(data, result)) if old != new}
    allowed = set(range(offsets[0x0110], offsets[0x0110] + 4))
    allowed.update(range(offsets[0x0111], offsets[0x0111] + 4))
    if len(result) != len(data) or not changed or not changed <= allowed:
        raise AssertionError("unexpected RAF control change")
    return bytes(result), offsets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--target-origin", nargs=2, type=int, metavar=("TOP", "LEFT"), default=(943, 6))
    parser.add_argument("--target-size", nargs=2, type=int, metavar=("HEIGHT", "WIDTH"), default=(2304, 6240))
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ")
    data = args.source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expect_sha256.lower():
        parser.error(f"source hash mismatch: {digest}")
    target_origin = tuple(args.target_origin)
    target_size = tuple(args.target_size)
    result, offsets = make_control(data, target_origin=target_origin, target_size=target_size)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as target:
        target.write(result)
    if args.destination.read_bytes() != result:
        raise OSError("synthetic control readback mismatch")
    print(json.dumps({
        "scope": "synthetic RAF area control; not camera evidence",
        "source_sha256": digest,
        "destination_sha256": hashlib.sha256(result).hexdigest(),
        "origin_payload_file_offset": hex(offsets[0x0110]),
        "size_payload_file_offset": hex(offsets[0x0111]),
        "source_origin": [13, 6],
        "source_size": [4160, 6240],
        "target_origin": list(target_origin),
        "target_size": list(target_size),
        "changed_bytes": sum(a != b for a, b in zip(data, result)),
    }, indent=2))


if __name__ == "__main__":
    main()
