"""Offline write that reshapes the 16:9 bright-frame drawing to 65:24 (X100V 3.01).

The icon table at RAM 0x001eb720 gives resource 0xFF00059B
(ICO_BR_FRAME_LX12_16_9) a 640x480 drawing of 6156 bytes at 0x002966c8.
It sits in update partition 2, which is stored uncompressed and loads at
0x001e0000. The drawing starts with "GVFF" and holds 22 paths in OpenVG
segment form (2 move, 4 line, 12 cubic, 0 close), each as a 44-byte
header, a segment count, a coordinate byte count, the segment bytes padded
to (count // 4 + 1) * 4, and float32 x, y pairs with y negative downward.

Path 0 is the full plane. Paths 1 to 7 are rectangle outlines two units
thick with a gap in the top edge. Paths 8 to 21 are label glyphs that sit
in those gaps.

This tool scales each rectangle's height by (24/65) / (9/16) = 128/195
about its own centre, keeping the line thickness and every x value, and
moves each label by the shift of the nearest rectangle's top edge.

Static reading plus arithmetic. Whether this drawing is the OVF's solid
bright frame, and which rectangle shows when, are not established here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

RESOURCE_LOAD = 0x001E0000          # update partition 2
RESOURCE_IMAGE_OFFSET = 0x1820000
IMAGE_BASE = 0x274
ICON_TABLE = 0x001EB720
ICON_INDEX = 0x59B
ICON_ADDRESS = 0x002966C8
ICON_BYTES = 6156
SCALE = (24 / 65) / (9 / 16)
COORDS = {0: 0, 2: 1, 4: 1, 12: 3}
FRAME_PATHS = range(1, 8)
LABEL_PATHS = range(8, 22)


def resource_bytes(update: bytes, address: int, size: int) -> bytes:
    """Bytes of update partition 2 at a RAM address; the update stores them inverted."""
    start = IMAGE_BASE + RESOURCE_IMAGE_OFFSET + address - RESOURCE_LOAD
    return bytes(b ^ 0xFF for b in update[start:start + size])


def parse(blob: bytes) -> list[dict]:
    """Paths as dicts with the file offset of their float pairs."""
    if blob[:4] != b"GVFF":
        raise ValueError("not a GVFF drawing")
    paths, at = [], 0x38
    while at + 8 <= len(blob):
        count, size = struct.unpack_from("<II", blob, at)
        commands = blob[at + 8:at + 8 + count]
        points_at = at + 8 + (count // 4 + 1) * 4
        if (1 <= count <= 4000 and size and size % 8 == 0 and points_at + size <= len(blob)
                and commands[:1] == b"\x02" and all(c in COORDS for c in commands)
                and sum(COORDS[c] for c in commands) * 8 == size):
            values = struct.unpack_from(f"<{size // 4}f", blob, points_at)
            paths.append({"at": at, "commands": bytes(commands), "points_at": points_at,
                          "points": [(values[i], values[i + 1]) for i in range(0, len(values), 2)]})
            at = points_at + size
        else:
            at += 4
    return paths


def frame_edges(points: list[tuple[float, float]]) -> tuple[float, float]:
    ys = [y for _, y in points]
    return min(ys), max(ys)  # top (most negative), bottom


def new_frame_y(y: float, top: float, bottom: float) -> float:
    centre = (top + bottom) / 2
    new_top = centre + (top - centre) * SCALE
    new_bottom = centre + (bottom - centre) * SCALE
    if abs(y - top) <= 2.5:
        return new_top + (y - top)
    if abs(y - bottom) <= 2.5:
        return new_bottom + (y - bottom)
    raise ValueError("frame point is on neither horizontal edge")


def reshape(blob: bytes) -> tuple[bytes, list[dict]]:
    paths = parse(blob)
    if len(paths) != 22:
        raise ValueError("expected 22 paths")
    out = bytearray(blob)
    report, shifts = [], {}
    for index in FRAME_PATHS:
        path = paths[index]
        if path["commands"] != b"\x02" + b"\x04" * 11 + b"\x00":
            raise ValueError(f"path {index} is not a 12-point outline")
        top, bottom = frame_edges(path["points"])
        xs = [x for x, _ in path["points"]]
        for k, (x, y) in enumerate(path["points"]):
            struct.pack_into("<f", out, path["points_at"] + 8 * k + 4, new_frame_y(y, top, bottom))
        new_top, new_bottom = new_frame_y(top, top, bottom), new_frame_y(bottom, top, bottom)
        shifts[top] = new_top - top
        report.append({"path": index, "x": [min(xs), max(xs)], "stock_y": [top, bottom],
                       "new_y": [new_top, new_bottom]})
    for index in LABEL_PATHS:
        path = paths[index]
        ys = [y for _, y in path["points"]]
        middle = (min(ys) + max(ys)) / 2
        nearest = min(shifts, key=lambda top: abs(top - middle))
        if abs(nearest - middle) > 8:
            raise ValueError(f"label path {index} is not on a frame's top edge")
        for k, (x, y) in enumerate(path["points"]):
            struct.pack_into("<f", out, path["points_at"] + 8 * k + 4, y + shifts[nearest])
    return bytes(out), report


def write_for(update: bytes) -> tuple[dict, list[dict]]:
    entry = resource_bytes(update, ICON_TABLE + 12 * ICON_INDEX, 12)
    if struct.unpack("<HHB3xI", entry) != (640, 480, 1, ICON_ADDRESS):
        raise ValueError("icon table entry is not the stock 16:9 bright-frame drawing")
    stock = resource_bytes(update, ICON_ADDRESS, ICON_BYTES)
    new, report = reshape(stock)
    changed = sum(a != b for a, b in zip(stock, new))
    return ({"field": "ovf-frame-drawing-16x9-to-65x24", "partition": 2,
             "partition_offset": ICON_ADDRESS - RESOURCE_LOAD, "address": f"0x{ICON_ADDRESS:08x}",
             "before_hex": stock.hex(), "after_hex": new.hex(), "changed_bytes": changed}, report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True, help="official X100V 3.01 FPUPDATE.DAT")
    parser.add_argument("--output", type=Path, required=True, help="manifest JSON to write")
    args = parser.parse_args()
    update = args.stock.read_bytes()
    write, report = write_for(update)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "kind": "16:9 bright-frame drawing reshaped to 65:24; one resource write; offline only, NOT FOR FLASH",
        "source_update_sha256": hashlib.sha256(update).hexdigest(),
        "stock_drawing_sha256": hashlib.sha256(bytes.fromhex(write["before_hex"])).hexdigest(),
        "new_drawing_sha256": hashlib.sha256(bytes.fromhex(write["after_hex"])).hexdigest(),
        "scale": "128/195", "frames": report, "writes": [write]}, indent=2) + "\n")
    print("changed bytes:", write["changed_bytes"])
    for row in report:
        print(row["path"], "x", row["x"], "y", [round(v, 2) for v in row["stock_y"]], "->",
              [round(v, 2) for v in row["new_y"]])


if __name__ == "__main__":
    main()
