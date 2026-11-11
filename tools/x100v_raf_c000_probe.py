"""Make a synthetic RAF copy to test the five C000 height-word hypothesis.

This is a metadata experiment, not a firmware candidate or camera capture.
The source is never modified; destination must not exist. The caller must
provide the expected whole-file SHA-256 from a prior read-only inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


HEIGHT_OFFSETS = (0x28, 0x30, 0x40, 0x48, 0x50)
BEFORE_HEIGHT = 3510
PROBE_HEIGHT = 2304


def c000_payload_offset(data: bytes) -> tuple[int, int]:
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    hdr_offset, hdr_size = struct.unpack_from(">II", data, 0x5C)
    if hdr_offset + hdr_size > len(data) or hdr_size < 4:
        raise ValueError("CFA header outside file")
    count = struct.unpack_from(">I", data, hdr_offset)[0]
    pos = hdr_offset + 4
    end = hdr_offset + hdr_size
    for _ in range(count):
        if pos + 4 > end:
            raise ValueError("truncated CFA record")
        tag, size = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + size > end:
            raise ValueError("CFA record outside header")
        if tag == 0xC000:
            if size <= max(HEIGHT_OFFSETS) + 4:
                raise ValueError("C000 record too short")
            return pos, size
        pos += size
    raise ValueError("C000 record absent")


def make_probe(data: bytes) -> tuple[bytes, list[int]]:
    payload, _ = c000_payload_offset(data)
    changed = bytearray(data)
    file_offsets = [payload + relative for relative in HEIGHT_OFFSETS]
    for offset in file_offsets:
        actual = struct.unpack_from("<I", data, offset)[0]
        if actual != BEFORE_HEIGHT:
            raise ValueError(f"C000 height at {offset:#x} is {actual}, not {BEFORE_HEIGHT}")
        struct.pack_into("<I", changed, offset, PROBE_HEIGHT)
    result = bytes(changed)
    expected = set()
    for offset in file_offsets:
        expected.update(range(offset, offset + 4))
    actual_changes = {i for i, (a, b) in enumerate(zip(data, result)) if a != b}
    if not actual_changes or not actual_changes <= expected or len(result) != len(data):
        raise AssertionError("unexpected synthetic change set")
    return result, file_offsets


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    p.add_argument("--expect-sha256", required=True)
    args = p.parse_args()
    if args.source.resolve() == args.destination.resolve():
        p.error("source and destination must differ")
    source = args.source.read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    if source_hash != args.expect_sha256.lower():
        p.error(f"source hash mismatch: {source_hash}")
    result, offsets = make_probe(source)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as output:
        output.write(result)
    print(json.dumps({
        "scope": "synthetic RAF header test copy; not camera evidence",
        "source_sha256": source_hash,
        "destination_sha256": hashlib.sha256(result).hexdigest(),
        "c000_file_offsets": [hex(offset) for offset in offsets],
        "before_height": BEFORE_HEIGHT,
        "probe_height": PROBE_HEIGHT,
        "bytes_changed": sum(a != b for a, b in zip(source, result)),
    }, indent=2))


if __name__ == "__main__":
    main()
