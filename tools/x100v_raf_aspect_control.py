"""Make an offline RAF aspect-tag control; never modify its source."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def aspect_payload_offset(data: bytes) -> int:
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    header, size = struct.unpack_from(">II", data, 0x5C)
    if size < 4 or header + size > len(data):
        raise ValueError("CFA header outside file")
    count = struct.unpack_from(">I", data, header)[0]
    pos, end = header + 4, header + size
    found = []
    for _ in range(count):
        if pos + 4 > end:
            raise ValueError("truncated CFA record")
        tag, length = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + length > end:
            raise ValueError("CFA record outside header")
        if tag == 0x0115:
            if length != 4:
                raise ValueError("aspect record length is not four")
            found.append(pos)
        pos += length
    if len(found) != 1:
        raise ValueError(f"expected one aspect record, found {len(found)}")
    return found[0]


def make_control(
    data: bytes,
    source_aspect: tuple[int, int] = (24, 65),
    control_aspect: tuple[int, int] = (9, 16),
) -> tuple[bytes, int]:
    if source_aspect == control_aspect:
        raise ValueError("source and control aspect must differ")
    if not all(0 < value <= 0xFFFF for value in (*source_aspect, *control_aspect)):
        raise ValueError("aspect components must be positive 16-bit integers")
    offset = aspect_payload_offset(data)
    if data[offset:offset + 4] != struct.pack(">HH", *source_aspect):
        raise ValueError("source aspect does not match expected value")
    result = bytearray(data)
    struct.pack_into(">HH", result, offset, *control_aspect)
    original_view, result_view = memoryview(data), memoryview(result)
    if (len(result) != len(data)
            or original_view[:offset] != result_view[:offset]
            or original_view[offset + 4:] != result_view[offset + 4:]):
        raise AssertionError("unexpected control change")
    return bytes(result), offset


def parse_aspect(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2 or not all(part.isdecimal() for part in parts):
        raise argparse.ArgumentTypeError("expected H:W as positive 16-bit integers")
    aspect = tuple(int(part) for part in parts)
    if not all(0 < part <= 0xFFFF for part in aspect):
        raise argparse.ArgumentTypeError("aspect components must be positive 16-bit integers")
    return aspect


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--source-aspect", type=parse_aspect, default=(24, 65))
    parser.add_argument("--control-aspect", type=parse_aspect, default=(9, 16))
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ")
    data = args.source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expect_sha256.lower():
        parser.error(f"source hash mismatch: {digest}")
    result, offset = make_control(data, args.source_aspect, args.control_aspect)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as target:
        target.write(result)
    print(json.dumps({
        "scope": "synthetic RAF tag control; not camera evidence",
        "source_sha256": digest,
        "destination_sha256": hashlib.sha256(result).hexdigest(),
        "aspect_payload_file_offset": hex(offset),
        "source_aspect": list(args.source_aspect),
        "control_aspect": list(args.control_aspect),
        "changed_bytes": sum(a != b for a, b in zip(data, result)),
    }, indent=2))


if __name__ == "__main__":
    main()
