"""Separate read-only inspector for an X100V 3.01 experimental container.

Deliberately imports nothing from the builder (tools.x100v_update_package) or
from tools.fuji_firmware_probe: header parsing, the integrity sums and the LZSS
decoder are rewritten here so a shared bug cannot pass both. Same author, so
this is a separate implementation, not third-party verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

IMG = 0x274  # 532-byte outer header + 0x60 inner header
PINNED_STOCK_SHA256 = "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591"


def u32(buf: bytes, at: int) -> int:
    return int.from_bytes(buf[at:at + 4], "little")


def image(raw: bytes, offset: int, length: int) -> bytes:
    return bytes(b ^ 0xFF for b in raw[IMG + offset:IMG + offset + length])


def sums_ok(raw: bytes) -> dict[str, bool]:
    def inv(x: int) -> int:
        return (x ^ 0xFFFFFFFF) & 0xFFFFFFFF

    def dsum(off: int, n: int) -> int:
        return sum(image(raw, off, n)) & 0xFFFFFFFF

    def rsum(off: int, n: int) -> int:
        return sum(raw[IMG + off:IMG + off + n]) & 0xFFFFFFFF

    w = lambda i: u32(raw, 532 + 4 * i)  # noqa: E731
    return {
        "outer_image": u32(raw, 524) == inv(dsum(0, 0x2FC0020)),
        "outer_table": u32(raw, 528) == inv(dsum(0x2FC0020, 0x4000)),
        "inner_trailer": w(2) == inv(dsum(w(3), w(4))),
        "inner_segment_a": w(20) == inv(rsum(w(18), w(19))),
        "inner_segment_b": w(23) == inv(rsum(w(21), w(22))),
    }


def unpack(raw: bytes, offset: int) -> bytes:
    head = image(raw, offset, 20)
    size, packed, blocks, bsize, flags = struct.unpack("<IIIII", head)
    assert bsize == 0x4000 and flags == 4, "partition header variant"
    assert blocks * bsize >= packed > (blocks - 1) * bsize, "block count"
    src = image(raw, offset + 20, packed - 20)
    dst = bytearray()
    pos = 0
    while pos < len(src):
        c = src[pos]
        if c >= 0x80:
            pair = ((c & 0x7F) << 8) + src[pos + 1]
            pos += 2
            start = len(dst) - (pair >> 4)
            assert start >= 0 and pair & 0xF, "bad back-reference"
            for k in range(pair & 0xF):
                dst.append(dst[start + k])
        else:
            assert c, "empty literal"
            dst += src[pos + 1:pos + 1 + c]
            pos += 1 + c
    assert len(dst) == size, "decoded size"
    return bytes(dst)


def changed_runs(a: bytes, b: bytes) -> list[tuple[int, int]]:
    runs, start = [], None
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y and start is None:
            start = i
        elif x == y and start is not None:
            runs.append((start, i))
            start = None
    if start is not None:
        runs.append((start, len(a)))
    return runs


def inspect(stock: bytes, cand: bytes, writes: list[dict]) -> dict:
    report: dict = {"candidate_sha256": hashlib.sha256(cand).hexdigest(), "same_length": len(stock) == len(cand)}
    report["stock_sha256"] = hashlib.sha256(stock).hexdigest()
    report["stock_is_pinned"] = report["stock_sha256"] == PINNED_STOCK_SHA256
    report["integrity"] = sums_ok(cand)
    valid_parts = all(w.get("partition") in (6, 7) for w in writes)
    report["write_partitions_valid"] = valid_parts
    for name, number, off in (("primary", 6, 0x280000), ("secondary", 7, 0x560000)):
        a, b = unpack(stock, off), unpack(cand, off)
        report[f"{name}_decoded_sha256"] = hashlib.sha256(b).hexdigest()
        runs = changed_runs(a, b)
        report[f"{name}_changed_runs"] = len(runs)
        part_writes = [w for w in writes if w.get("partition") == number]
        spans = [(w["partition_offset"], w["partition_offset"] + len(w["after_hex"]) // 2, w["field"])
                 for w in part_writes]
        mapped, unmapped = [], []
        for lo, hi in runs:
            covered = all(any(o <= i < e for o, e, _ in spans) for i in range(lo, hi))
            owner = [f for o, e, f in spans if o < hi and lo < e]
            (mapped if covered else unmapped).append({"range": [hex(lo), hex(hi)], "fields": owner})
        report[f"{name}_runs_mapped_to_writes"] = len(mapped)
        report[f"{name}_runs_unmapped"] = unmapped
        report[f"{name}_writes_verify"] = all(
            a[w["partition_offset"]:w["partition_offset"] + len(w["before_hex"]) // 2].hex() == w["before_hex"]
            and b[w["partition_offset"]:w["partition_offset"] + len(w["after_hex"]) // 2].hex() == w["after_hex"]
            and len(w["before_hex"]) == len(w["after_hex"])
            for w in part_writes
        )
    first_slot = IMG + 0x280000
    last_slot_end = IMG + 0xA00000
    report["bytes_outside_slots_and_sums_identical"] = (
        stock[:524] == cand[:524]
        and stock[532:first_slot] == cand[532:first_slot]
        and stock[last_slot_end:] == cand[last_slot_end:]
    )
    report["pass"] = (
        report["same_length"]
        and report["stock_is_pinned"]
        and valid_parts
        and all(report["integrity"].values())
        and not report["primary_runs_unmapped"]
        and not report["secondary_runs_unmapped"]
        and report["primary_writes_verify"]
        and report["secondary_writes_verify"]
        and report["bytes_outside_slots_and_sums_identical"]
    )
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--stock", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--writes", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(inspect(a.stock.read_bytes(), a.candidate.read_bytes(),
                             json.loads(a.writes.read_text())), indent=2))


if __name__ == "__main__":
    main()
