"""Add an Adobe crop to a synthetic X100V RAF copy's embedded JPEG XMP.

This is an offline metadata control, not a firmware or SD-card candidate.
The original RAF and all bytes outside the fixed-size XMP APP1 segment stay
unchanged. A positive editor response would not establish camera behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path


XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
CRS_NAMESPACE = b"http://ns.adobe.com/camera-raw-settings/1.0/"
DESCRIPTION_CLOSE = b"</rdf:Description>"
PACKET_END = b"<?xpacket end='w'?>"


def xmp_extent(data: bytes) -> tuple[int, int]:
    """Locate the one bounded XMP APP1 inside the RAF's embedded JPEG."""
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    jpeg_offset, jpeg_length, cfa_offset, cfa_length, raw_offset, raw_length = (
        struct.unpack_from(">6I", data, 0x54)
    )
    if not (0x94 <= jpeg_offset < jpeg_offset + jpeg_length <= cfa_offset
            and cfa_offset + cfa_length <= raw_offset
            and raw_offset + raw_length <= len(data)):
        raise ValueError("unexpected RAF section layout")
    jpeg_end = jpeg_offset + jpeg_length
    if data[jpeg_offset:jpeg_offset + 2] != b"\xff\xd8":
        raise ValueError("embedded JPEG has no SOI")
    matches = []
    search = jpeg_offset + 2
    while True:
        position = data.find(XMP_PREFIX, search, jpeg_end)
        if position < 0:
            break
        marker = position - 4
        if marker >= jpeg_offset and data[marker:marker + 2] == b"\xff\xe1":
            length = struct.unpack_from(">H", data, marker + 2)[0]
            end = marker + 2 + length
            if position == marker + 4 and end <= jpeg_end:
                matches.append((position + len(XMP_PREFIX), end))
        search = position + 1
    if len(matches) != 1:
        raise ValueError(f"expected one bounded XMP APP1, found {len(matches)}")
    return matches[0]


def make_control(data: bytes, top: str = "0.2230769231",
                 bottom: str = "0.7769230769") -> tuple[bytes, tuple[int, int]]:
    start, end = xmp_extent(data)
    packet = data[start:end]
    if packet.count(DESCRIPTION_CLOSE) != 1 or packet.count(PACKET_END) != 1:
        raise ValueError("unexpected XMP packet structure")
    if b"xmlns:crs=" in packet or b"crs:HasCrop" in packet:
        raise ValueError("source already has Camera Raw crop metadata")
    if not (0 <= float(top) < float(bottom) <= 1):
        raise ValueError("crop bounds outside normalized image")
    namespace = b' xmlns:crs="' + CRS_NAMESPACE + b'"'
    description_open = b"<rdf:Description "
    if packet.count(description_open) != 1:
        raise ValueError("expected one RDF description")
    # Add namespace to the existing description and crop children before its
    # closing tag; consume only the packet's original space padding.
    packet = packet.replace(description_open, description_open + namespace + b" ", 1)
    crop = (
        b"<crs:HasCrop>True</crs:HasCrop>"
        b"<crs:CropLeft>0</crs:CropLeft>"
        b"<crs:CropTop>" + top.encode("ascii") + b"</crs:CropTop>"
        b"<crs:CropRight>1</crs:CropRight>"
        b"<crs:CropBottom>" + bottom.encode("ascii") + b"</crs:CropBottom>"
        b"<crs:CropAngle>0</crs:CropAngle>"
    )
    packet = packet.replace(DESCRIPTION_CLOSE, crop + DESCRIPTION_CLOSE, 1)
    ending = packet.index(PACKET_END)
    prefix, suffix = packet[:ending], packet[ending:]
    padding = len(packet) - (end - start)
    close = b"</x:xmpmeta>"
    pad_start = prefix.index(close) + len(close)
    match = re.fullmatch(rb"\r\n( +)(?:\r\n)?", prefix[pad_start:])
    if padding <= 0 or match is None or len(match.group(1)) < padding:
        raise ValueError("XMP packet lacks enough space padding")
    spaces_start = pad_start + match.start(1)
    spaces_end = pad_start + match.end(1)
    packet = (prefix[:spaces_start] + b" " * (spaces_end - spaces_start - padding)
              + prefix[spaces_end:] + suffix)
    if len(packet) != end - start:
        raise AssertionError("XMP segment length changed")
    # The packet contains a processing instruction outside its XML document.
    document = packet[packet.index(b"<x:xmpmeta"):packet.index(b"</x:xmpmeta>") + len(b"</x:xmpmeta>")]
    root = ET.fromstring(document)
    ns = {"crs": CRS_NAMESPACE.decode("ascii")}
    if root.find(".//crs:HasCrop", ns).text != "True":
        raise AssertionError("XMP crop did not parse")
    result = bytearray(data)
    result[start:end] = packet
    if result[:start] != data[:start] or result[end:] != data[end:]:
        raise AssertionError("bytes outside XMP changed")
    return bytes(result), (start, end)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ")
    data = args.source.read_bytes()
    source_hash = hashlib.sha256(data).hexdigest()
    if source_hash != args.expect_sha256.lower():
        parser.error(f"source hash mismatch: {source_hash}")
    result, extent = make_control(data)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("xb") as target:
        target.write(result)
    readback_hash = hashlib.sha256(args.destination.read_bytes()).hexdigest()
    if readback_hash != hashlib.sha256(result).hexdigest():
        raise AssertionError("synthetic RAF readback mismatch")
    print(json.dumps({
        "scope": "synthetic embedded-XMP crop control; never camera evidence",
        "source_sha256": source_hash,
        "destination_sha256": readback_hash,
        "xmp_file_extent": [hex(value) for value in extent],
        "changed_bytes": sum(a != b for a, b in zip(data, result)),
    }, indent=2))


if __name__ == "__main__":
    main()
