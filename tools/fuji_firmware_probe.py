"""Read-only Fujifilm DAT and candidate partition reconnaissance.

Candidate LZSS headers are heuristics until linked to a validated loader table.
Never constructs an update or writes to a camera.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


HEADER_SIZE = 532
NEEDLES = (
    b"MODE_ASPECT_65_24",
    b"BKUP_ASPECT_65_24",
    b"UI_PXL_L_65_24",
    b"UI_AUTOASPECT_65_24",
    b"REC_REMAIN_COUNT_L_S_65_24",
)


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    offsets = []
    cursor = 0
    while True:
        index = haystack.find(needle, cursor)
        if index < 0:
            return offsets
        offsets.append(index)
        cursor = index + 1


def lzss_decode(stream: bytes, output_size: int) -> bytes:
    """Continuous LZSS grammar described in fujihack/fujihack issue 23."""
    output = bytearray()
    cursor = 0
    while cursor < len(stream):
        control = stream[cursor]
        cursor += 1
        if control < 0x80:
            if control == 0:
                raise ValueError("zero-length literal run")
            if cursor + control > len(stream):
                raise ValueError("truncated literal run")
            output.extend(stream[cursor : cursor + control])
            cursor += control
        else:
            if cursor >= len(stream):
                raise ValueError("truncated back-reference")
            value = ((control & 0x7F) << 8) | stream[cursor]
            cursor += 1
            length = value & 0x0F
            distance = value >> 4
            if not distance or not length:
                raise ValueError("zero-length or zero-distance back-reference")
            if distance > len(output):
                raise ValueError("back-reference before output start")
            for _ in range(length):
                output.append(output[-distance])
        if len(output) > output_size:
            raise ValueError("decoded output exceeds header declaration")
    if len(output) != output_size:
        raise ValueError(f"decoded {len(output)} bytes, expected {output_size}")
    return bytes(output)


def candidate_lzss_headers(payload: bytes) -> list[dict]:
    # Header: output length, packed extent INCLUDING this 20-byte header,
    # transfer block count, 0x4000 block size, flags.
    candidates = []
    cursor = 0
    block_marker = struct.pack("<I", 0x4000)
    while True:
        marker = payload.find(block_marker, cursor)
        if marker < 0:
            return candidates
        cursor = marker + 1
        start = marker - 12
        if start < 0 or start + 20 > len(payload):
            continue
        output_size, packed_size, block_count, block_size, flags = struct.unpack_from("<5I", payload, start)
        if not (0 < output_size <= 128 * 1024 * 1024):
            continue
        if not (20 <= packed_size <= len(payload) - start):
            continue
        if not (0 < block_count < 10000 and block_size == 0x4000):
            continue
        # Block count tracks compressed transfer chunks, not decoded chunks.
        if block_count != (packed_size + 0x3FFF) // 0x4000:
            continue
        candidates.append({
            "payload_offset": start,
            "output_size": output_size,
            "packed_size": packed_size,
            "block_count": block_count,
            "flags": flags,
        })


def candidate_loader_tables(payload: bytes) -> list[dict]:
    """Find X100V-style 0x24-byte records; ID order is only a heuristic."""
    candidates = []
    search = struct.pack("<I", 1)
    cursor = 0
    while True:
        id_one_at = payload.find(search, cursor)
        if id_one_at < 0:
            return candidates
        cursor = id_one_at + 4
        start = id_one_at - 32
        if start < 0 or start + 0x24 * 3 > len(payload):
            continue
        records = []
        for index in range(12):
            offset = start + index * 0x24
            if offset + 0x24 > len(payload):
                break
            fields = struct.unpack_from("<9I", payload, offset)
            record_id = fields[8]
            if record_id == 0xFF:
                if len(records) >= 5:
                    candidates.append({"payload_offset": start, "records": records})
                break
            if record_id > 16 or (records and record_id in {row["id"] for row in records}):
                break
            records.append({
                "id": record_id,
                "load": fields[0],
                "size": fields[1],
                "flash": fields[4],
                "flags": fields[6],
            })


def analyze(path: Path, decode_limit: int = 64 * 1024 * 1024, extract_to: Path | None = None) -> dict:
    original = path.read_bytes()
    if len(original) < HEADER_SIZE:
        raise ValueError("shorter than Fujifilm update header")
    header = original[:HEADER_SIZE]
    payload = bytes(value ^ 0xFF for value in original[HEADER_SIZE:])
    result = {
        "input_path": str(path.resolve()),
        "input_size": len(original),
        "input_sha256": hashlib.sha256(original).hexdigest(),
        "format_word": struct.unpack_from("<I", header, 0)[0],
        "version_words": list(struct.unpack_from("<II", header, 516)),
        "model_field_prefix_ascii": header[4:64].decode("ascii", "replace"),
        "decoded_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "decoded_payload_size": len(payload),
        "uncompressed_literals": {needle.decode(): find_all(payload, needle) for needle in NEEDLES},
        "loader_table_candidates": candidate_loader_tables(payload),
        "lzss_candidates": [],
    }
    if extract_to is not None:
        extract_to.mkdir(parents=False, exist_ok=False)
    for candidate in candidate_lzss_headers(payload):
        item = dict(candidate)
        if item["output_size"] > decode_limit:
            item["status"] = "over local decode limit"
        else:
            start = item["payload_offset"] + 20
            stream = payload[start : item["payload_offset"] + item["packed_size"]]
            try:
                decoded = lzss_decode(stream, item["output_size"])
            except ValueError as exc:
                item["status"] = f"rejected: {exc}"
            else:
                item["status"] = "exact decode"
                item["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
                item["literal_offsets"] = {needle.decode(): find_all(decoded, needle) for needle in NEEDLES}
                if extract_to is not None:
                    child = extract_to / f"partition-{item['payload_offset']:08x}-{item['decoded_sha256'][:12]}.bin"
                    child.write_bytes(decoded)
                    item["extracted_path"] = str(child.resolve())
        result["lzss_candidates"].append(item)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--extract-to", type=Path, help="new directory for exact-decoded partition files")
    args = parser.parse_args()
    print(json.dumps(analyze(args.update, extract_to=args.extract_to), indent=2))


if __name__ == "__main__":
    main()
