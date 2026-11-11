"""Source-bound X100V 3.01 update-container model, minimal re-encoder and audit.

Everything here is pinned against the stock X100V 3.01 FPUPDATE.DAT. It builds
experimental update containers for offline inspection only. A container that
passes these checks has NOT been accepted by a camera updater, booted, or
validated for rollback. Never copy one to a card as FPUPDATE.DAT without the
separately approved physical procedure.

Container model (file offsets; "decoded" means byte ^ 0xff):

* 532-byte outer header: format word 6, 512-byte model field, version 3/1,
  then two integrity words.
* Everything after offset 532 is XOR-0xff payload. Its first 0x60 bytes are an
  inner header; the flash image starts at file offset 0x274.
* Image layout: flash image [0, 0x2fc0020), segment [0x2fc0020, +0x4000),
  segment [0x2fc4020, +0x188), segment [0x2fc41a8, +0x430), trailer
  [0x2fc45d8, +0xc000).
* Every integrity word is the 32-bit complement of a plain byte sum:

  =================  ======================================  =========
  stored at          covers (image offsets)                  bytes
  =================  ======================================  =========
  outer +524         flash image [0, 0x2fc0020)              decoded
  outer +528         segment [0x2fc0020, +0x4000)            decoded
  inner word 2       trailer [word 3, +word 4)               decoded
  inner word 20      segment [word 18, +word 19)             raw
  inner word 23      segment [word 21, +word 22)             raw
  =================  ======================================  =========

Partitions 6 and 7 are 20-byte headers plus continuous LZSS streams at image
offsets 0x280000 and 0x560000. Their fixed slots end at 0x560000 and 0xa00000;
the stock unused tails are decoded zero. This is an offline container model,
not evidence that the camera updater accepts a modified image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from tools.fuji_firmware_probe import lzss_decode

STOCK_SHA256 = "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591"
STOCK_SIZE = 50_137_164
OUTER_HEADER = 532
INNER_HEADER = 0x60
IMAGE_BASE = OUTER_HEADER + INNER_HEADER
FLASH_IMAGE_SIZE = 0x2FC0020
TABLE_SEGMENT = (0x2FC0020, 0x4000)

PRIMARY_IMAGE_OFFSET = 0x280000
PRIMARY_SLOT_SIZE = 0x2E0000
PRIMARY_LOAD = 0x00F21000
PRIMARY_OUTPUT_SIZE = 0x603340
PRIMARY_DECODED_SHA256 = "3be0132c4bb17aa7504aaaf7e6d85d037368d21f49463ea0ce1ae37a764f6c87"
SECONDARY_IMAGE_OFFSET = 0x560000
SECONDARY_SLOT_SIZE = 0x4A0000
SECONDARY_OUTPUT_SIZE = 0x82C000
SECONDARY_DECODED_SHA256 = "b116e52462f245b7bfa341ebf75a644baa32590d3957518dbea436456169cb35"
BLOCK_SIZE = 0x4000
PARTITION_FLAGS = 4

# Stock values, used only to prove the model reproduces the source file.
STOCK_INTEGRITY = {
    "outer_image": 0xC41EB85B,
    "outer_table": 0xFFD557CD,
    "inner_trailer": 0xFF55DE19,
    "inner_segment_a": 0xFFFFB198,
    "inner_segment_b": 0xFFFF692B,
}


def _decoded_sum(raw: bytes) -> int:
    return 0xFF * len(raw) - sum(raw)


def _complement(value: int) -> int:
    return ~value & 0xFFFFFFFF


def _inner_word(raw: bytes, index: int) -> int:
    return struct.unpack_from("<I", raw, OUTER_HEADER + 4 * index)[0]


def _image_slice(raw: bytes, offset: int, size: int) -> bytes:
    start = IMAGE_BASE + offset
    if offset < 0 or size <= 0 or start + size > len(raw):
        raise ValueError(f"image range {offset:#x}+{size:#x} outside container")
    return raw[start:start + size]


def compute_integrity(raw: bytes) -> dict[str, int]:
    """Recompute every integrity word from the container bytes."""
    trailer = (_inner_word(raw, 3), _inner_word(raw, 4))
    seg_a = (_inner_word(raw, 18), _inner_word(raw, 19))
    seg_b = (_inner_word(raw, 21), _inner_word(raw, 22))
    return {
        "outer_image": _complement(_decoded_sum(_image_slice(raw, 0, FLASH_IMAGE_SIZE))),
        "outer_table": _complement(_decoded_sum(_image_slice(raw, *TABLE_SEGMENT))),
        "inner_trailer": _complement(_decoded_sum(_image_slice(raw, *trailer))),
        "inner_segment_a": _complement(sum(_image_slice(raw, *seg_a))),
        "inner_segment_b": _complement(sum(_image_slice(raw, *seg_b))),
    }


def stored_integrity(raw: bytes) -> dict[str, int]:
    outer_image, outer_table = struct.unpack_from("<2I", raw, 524)
    return {
        "outer_image": outer_image,
        "outer_table": outer_table,
        "inner_trailer": _inner_word(raw, 2),
        "inner_segment_a": _inner_word(raw, 20),
        "inner_segment_b": _inner_word(raw, 23),
    }


def reseal(raw: bytes) -> bytes:
    """Rewrite all five integrity words; nothing else changes."""
    out = bytearray(raw)
    sums = compute_integrity(raw)
    struct.pack_into("<2I", out, 524, sums["outer_image"], sums["outer_table"])
    for name, index in (("inner_trailer", 2), ("inner_segment_a", 20), ("inner_segment_b", 23)):
        struct.pack_into("<I", out, OUTER_HEADER + 4 * index, sums[name])
    return bytes(out)


def check_container_shape(raw: bytes) -> None:
    if len(raw) != STOCK_SIZE:
        raise ValueError(f"container size {len(raw)} differs from X100V 3.01 stock")
    if struct.unpack_from("<I", raw, 0)[0] != 6:
        raise ValueError("outer header format word is not 6")
    if struct.unpack_from("<2I", raw, 516) != (3, 1):
        raise ValueError("container version is not 3.01")
    layout = (_inner_word(raw, 3), _inner_word(raw, 4), _inner_word(raw, 18),
              _inner_word(raw, 19), _inner_word(raw, 21), _inner_word(raw, 22))
    if layout != (0x2FC45D8, 0xC000, 0x2FC4020, 0x188, 0x2FC41A8, 0x430):
        raise ValueError("inner header segment layout differs from the pinned stock layout")


def read_partition(raw: bytes, image_offset: int, slot_size: int,
                   output_size_expected: int) -> tuple[bytes, bytes]:
    """Return (decoded header + stream, decoded partition) for a pinned slot."""
    header = bytes(b ^ 0xFF for b in _image_slice(raw, image_offset, 20))
    output_size, packed, blocks, block_size, flags = struct.unpack("<5I", header)
    if (output_size, block_size, flags) != (output_size_expected, BLOCK_SIZE, PARTITION_FLAGS):
        raise ValueError("partition header differs from pinned variant")
    if not 20 <= packed <= slot_size:
        raise ValueError("partition stream does not fit its flash slot")
    if blocks != (packed + BLOCK_SIZE - 1) // BLOCK_SIZE:
        raise ValueError("partition transfer block count does not match packed size")
    packed_bytes = bytes(b ^ 0xFF for b in _image_slice(raw, image_offset, packed))
    return packed_bytes, lzss_decode(packed_bytes[20:], output_size)


def read_primary(raw: bytes) -> tuple[bytes, bytes]:
    return read_partition(raw, PRIMARY_IMAGE_OFFSET, PRIMARY_SLOT_SIZE, PRIMARY_OUTPUT_SIZE)


def read_secondary(raw: bytes) -> tuple[bytes, bytes]:
    return read_partition(raw, SECONDARY_IMAGE_OFFSET, SECONDARY_SLOT_SIZE, SECONDARY_OUTPUT_SIZE)


@dataclass(frozen=True)
class Token:
    literal: bool
    out_start: int
    length: int
    distance: int  # zero for literals
    encoded: bytes


def tokenize(stream: bytes) -> list[Token]:
    """Split the LZSS grammar used by fuji_firmware_probe.lzss_decode into tokens."""
    tokens: list[Token] = []
    cursor = 0
    out = 0
    while cursor < len(stream):
        control = stream[cursor]
        if control < 0x80:
            if control == 0:
                raise ValueError("zero-length literal run")
            tokens.append(Token(True, out, control, 0, stream[cursor:cursor + 1 + control]))
            cursor += 1 + control
            out += control
        else:
            value = ((control & 0x7F) << 8) | stream[cursor + 1]
            length, distance = value & 0x0F, value >> 4
            if not length or not distance:
                raise ValueError("zero-length or zero-distance back-reference")
            tokens.append(Token(False, out, length, distance, stream[cursor:cursor + 2]))
            cursor += 2
            out += length
    return tokens


def _literal_runs(data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 0x7F):
        chunk = data[start:start + 0x7F]
        out.append(len(chunk))
        out.extend(chunk)
    return bytes(out)


def splice_encode(stock_stream: bytes, stock: bytes, patched: bytes) -> tuple[bytes, dict]:
    """Re-encode only the tokens whose decoded output would differ.

    A literal token keeps its length and takes the patched bytes. A
    back-reference stays only if copying from the patched output reproduces
    the patched output exactly; otherwise it becomes literal bytes. Adjacent
    replaced tokens are merged into literal runs. Every untouched token keeps
    its stock encoding.
    """
    if len(stock) != len(patched):
        raise ValueError("patched partition length differs")
    tokens = tokenize(stock_stream)
    out = bytearray()
    pending = bytearray()
    rewritten_literals = 0
    replaced_refs = 0

    def flush() -> None:
        if pending:
            out.extend(_literal_runs(bytes(pending)))
            pending.clear()

    for token in tokens:
        span = slice(token.out_start, token.out_start + token.length)
        if token.literal:
            if patched[span] == stock[span]:
                flush()
                out.extend(token.encoded)
            else:
                rewritten_literals += 1
                pending.extend(patched[span])
            continue
        valid = all(
            patched[pos - token.distance] == patched[pos]
            for pos in range(token.out_start, token.out_start + token.length)
        )
        if valid:
            flush()
            out.extend(token.encoded)
        else:
            replaced_refs += 1
            pending.extend(patched[span])
    flush()
    stream = bytes(out)
    if lzss_decode(stream, len(patched)) != patched:
        raise ValueError("splice-encoded stream does not decode to the patched partition")
    return stream, {
        "token_count": len(tokens),
        "rewritten_literal_tokens": rewritten_literals,
        "replaced_back_references": replaced_refs,
        "stream_growth_bytes": len(stream) - len(stock_stream),
    }


def apply_writes(stock: bytes, writes: list[dict]) -> bytes:
    patched = bytearray(stock)
    claimed: set[int] = set()
    for write in writes:
        offset = write["partition_offset"]
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        if len(before) != len(after):
            raise ValueError(f"{write['field']}: before/after lengths differ")
        if stock[offset:offset + len(before)] != before:
            raise ValueError(f"{write['field']}: stock bytes at {offset:#x} differ from expected old bytes")
        span = set(range(offset, offset + len(before)))
        if span & claimed:
            raise ValueError(f"{write['field']}: overlaps an earlier write")
        claimed |= span
        patched[offset:offset + len(after)] = after
    return bytes(patched)


def build_container(stock_raw: bytes, writes: list[dict]) -> tuple[bytes, dict]:
    if hashlib.sha256(stock_raw).hexdigest() != STOCK_SHA256:
        raise ValueError("source is not the pinned X100V 3.01 update")
    check_container_shape(stock_raw)
    if any(w.get("partition") not in (6, 7) for w in writes):
        raise ValueError("every container write must name partition 6 or 7")
    out = bytearray(stock_raw)
    stats: dict = {}
    for number, image_offset, slot_size, output_size, expected_sha, reader in (
        (6, PRIMARY_IMAGE_OFFSET, PRIMARY_SLOT_SIZE, PRIMARY_OUTPUT_SIZE, PRIMARY_DECODED_SHA256, read_primary),
        (7, SECONDARY_IMAGE_OFFSET, SECONDARY_SLOT_SIZE, SECONDARY_OUTPUT_SIZE, SECONDARY_DECODED_SHA256, read_secondary),
    ):
        packed, stock = reader(stock_raw)
        if hashlib.sha256(stock).hexdigest() != expected_sha:
            raise ValueError(f"decoded partition {number} hash differs")
        tail = _image_slice(stock_raw, image_offset + len(packed), slot_size - len(packed))
        if any(byte != 0xFF for byte in tail):
            raise ValueError(f"partition {number} stock slot tail is not decoded zero")
        part_writes = [w for w in writes if w["partition"] == number]
        patched = apply_writes(stock, part_writes)
        if not part_writes:
            continue
        stream, part_stats = splice_encode(packed[20:], stock, patched)
        packed_size = 20 + len(stream)
        if packed_size > slot_size:
            raise ValueError(f"re-encoded partition {number} ({packed_size:#x}) exceeds slot {slot_size:#x}")
        header = struct.pack("<5I", output_size, packed_size,
                             (packed_size + BLOCK_SIZE - 1) // BLOCK_SIZE, BLOCK_SIZE, PARTITION_FLAGS)
        slot = header + stream + bytes(slot_size - packed_size)
        start = IMAGE_BASE + image_offset
        out[start:start + slot_size] = bytes(b ^ 0xFF for b in slot)
        part_stats.update({
            "stock_packed_size": len(packed),
            "candidate_packed_size": packed_size,
            "slot_headroom_after": slot_size - packed_size,
            f"patched_partition_{number}_sha256": hashlib.sha256(patched).hexdigest(),
        })
        stats[f"partition_{number}"] = part_stats
    sealed = reseal(bytes(out))
    return sealed, stats


def audit_container(stock_raw: bytes, candidate_raw: bytes, writes: list[dict]) -> dict:
    """Independently re-parse a candidate and account for every changed byte."""
    check_container_shape(candidate_raw)
    stored, computed = stored_integrity(candidate_raw), compute_integrity(candidate_raw)
    if stored != computed:
        raise ValueError(f"integrity words do not verify: {stored} vs {computed}")
    if hashlib.sha256(stock_raw).hexdigest() != STOCK_SHA256:
        raise ValueError("audit source is not the pinned X100V 3.01 update")
    if any(w.get("partition") not in (6, 7) for w in writes):
        raise ValueError("every container write must name partition 6 or 7")
    decoded: dict = {}
    for number, reader in ((6, read_primary), (7, read_secondary)):
        _, stock = reader(stock_raw)
        _, candidate = reader(candidate_raw)
        expected = apply_writes(stock, [w for w in writes if w["partition"] == number])
        if candidate != expected:
            bad = next(i for i in range(len(stock)) if candidate[i] != expected[i])
            raise ValueError(f"decoded partition {number} differs from declared writes at {bad:#x}")
        decoded[number] = (stock, candidate)
    changed_outside = _diff_outside_slots(stock_raw, candidate_raw)
    if changed_outside:
        raise ValueError(f"unaccounted container change at file offset {changed_outside[0]:#x}")
    declared = sum(len(bytes.fromhex(w["before_hex"])) for w in writes)
    actual = sum(sum(a != b for a, b in zip(*decoded[number])) for number in (6, 7))
    return {
        "integrity_words_verify": True,
        "decoded_primary_matches_declared_writes": True,
        "decoded_secondary_matches_declared_writes": True,
        "declared_write_bytes": declared,
        "decoded_bytes_actually_changed": actual,
        "changes_confined_to_integrity_words_and_partition_slots": True,
        "candidate_sha256": hashlib.sha256(candidate_raw).hexdigest(),
        "candidate_decoded_primary_sha256": hashlib.sha256(decoded[6][1]).hexdigest(),
        "candidate_decoded_secondary_sha256": hashlib.sha256(decoded[7][1]).hexdigest(),
    }


def _diff_outside_slots(a: bytes, b: bytes) -> list[int]:
    """Changed offsets outside the integrity words and both partition slots."""
    if len(a) != len(b):
        return [min(len(a), len(b))]
    out = []
    first_lo = IMAGE_BASE + PRIMARY_IMAGE_OFFSET
    last_hi = IMAGE_BASE + SECONDARY_IMAGE_OFFSET + SECONDARY_SLOT_SIZE
    for lo, hi in ((0, 524), (532, first_lo), (last_hi, len(a))):
        if a[lo:hi] != b[lo:hi]:
            out.append(lo + next(i for i in range(hi - lo) if a[lo + i] != b[lo + i]))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--writes", type=Path, help="JSON list of partition writes")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--stock-roundtrip", action="store_true")
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    report: dict = {"source_sha256": hashlib.sha256(raw).hexdigest()}
    check_container_shape(raw)
    report["stock_integrity_reproduced"] = stored_integrity(raw) == compute_integrity(raw) == STOCK_INTEGRITY
    if args.stock_roundtrip:
        rebuilt, stats = build_container(raw, [])
        report["stock_roundtrip_identical"] = rebuilt == raw
        report["stock_roundtrip_stats"] = stats
    if args.writes:
        writes = json.loads(args.writes.read_text())
        candidate, stats = build_container(raw, writes)
        report["build"] = stats
        report["audit"] = audit_container(raw, candidate, writes)
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=False)
            (args.output_dir / "candidate-update-NOT-FOR-CARD.DAT").write_bytes(candidate)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
