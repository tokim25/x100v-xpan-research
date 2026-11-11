"""Build a reversible 65:24 SD-boot card set from FujiMod's stock X100V files.

Input is a directory produced by `fujimod-recovery build x100v-301` from the
pinned stock DAT, plus this project's integrated write list. Two audited
FujiMod layouts are known: the preloaded set from 130dabad (with ffdata.bin),
which did not boot an X100V, and the full-image pair from b13b12c. The 65:24
writes are applied to ffboot.bin, the RAM image the card boots, at the
write's partition load address (primary unless it names partition 7) plus
its partition offset. ffinit.bin stores ffboot's length and CRC32
as two adjacent words; only the CRC word changes. Every other file is copied
unchanged.

Booting this card runs the mod from RAM without writing internal flash. It
has not been booted on a camera. Persisted settings still go to internal
storage, so set the aspect back to 3:2 before removing the card.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import zlib
from pathlib import Path

from tools.x100v_update_package import (
    PRIMARY_LOAD, PRIMARY_OUTPUT_SIZE, SECONDARY_OUTPUT_SIZE, STOCK_SHA256,
)

# Decoded partitions and the raw overlay sit in ffboot.bin at their load
# addresses (checked byte for byte against the full-image b13b12c ffboot).
PARTITION_LOADS = {6: PRIMARY_LOAD, 7: 0x01BA0000, 9: 0x03720000}  # 9: raw overlay
PARTITION_SIZES = {6: PRIMARY_OUTPUT_SIZE, 7: SECONDARY_OUTPUT_SIZE, 9: 0xA00000}

# fujimod-recovery build x100v-301 from the stock DAT, audited by
# tools.x100v_recovery_audit. "edits" are the RAM bytes FujiMod changes from
# stock; our writes must not touch them.
STOCK_BUILDS = {
    "preload-130dabad": {
        "files": {
            "ffinit.bin": "85cc626c265a06b4e3e6053068c6a4c8ee2562717f01d570ac76f351431f1e5d",
            "ffboot.bin": "0eeea582e5ad1778d3c107d72b838e77e1a6de07043b976778d87585118c98c8",
            "ffdata.bin": "df82cc646d6db74c2d2f7b1cc451c49664b660c6bb2fbc548b09c39d6a6c3b8e",
            "FPUPDATE.DAT": STOCK_SHA256,
        },
        "edits": [(0x5D8, 1), (0x620, 1), (0xA28, 1), (0x93E0, 1), (0xD20008, 1),
                  (0x1127C36, 2), (0x1127EE0, 2), (0x11280D4, 4), (0x1128374, 4),
                  (0x112893C, 4), (0x11295C4, 4), (0x11296DC, 4), (0x11507C4, 4),
                  (0x15190EC, 1)],
    },
    "full-image-b13b12c": {
        "files": {
            "ffinit.bin": "f85ea00d1f87051587548c65d8d70d54cc29c2ec4d9977610e6e5ae84cf59c40",
            "ffboot.bin": "21d9f68f2a74462be44e1052647d754ea82450b8f2836c4e0ce77a9e7c58c0f1",
            "FPUPDATE.DAT": STOCK_SHA256,
        },
        "edits": [(0x5D8, 1), (0x620, 1), (0xA28, 1), (0xD20008, 1)],
    },
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ram_address(write: dict) -> int:
    return PARTITION_LOADS[write.get("partition", 6)] + write["partition_offset"]


def validate_writes(writes: list[dict], boot_size: int, known: dict) -> list[tuple[int, bytes, bytes]]:
    """Reject resizing, out-of-partition, overlapping, or FujiMod-owned edits."""
    spans: list[tuple[int, int]] = []
    validated = []
    protected = [(start, start + size) for start, size in known["edits"]]
    for write in writes:
        partition = write.get("partition", 6)
        offset = write["partition_offset"]
        if partition not in PARTITION_LOADS or type(offset) is not int or offset < 0:
            raise ValueError(f"{write['field']}: invalid partition or offset")
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        if not before or len(before) != len(after):
            raise ValueError(f"{write['field']}: write must be nonempty and length-preserving")
        end_offset = offset + len(before)
        if end_offset > PARTITION_SIZES[partition]:
            raise ValueError(f"{write['field']}: write crosses decoded partition boundary")
        address = PARTITION_LOADS[partition] + offset
        end = address + len(before)
        if end > boot_size:
            raise ValueError(f"{write['field']}: write exceeds ffboot.bin")
        if any(address < hi and lo < end for lo, hi in protected):
            raise ValueError(f"{write['field']}: overlaps a FujiMod edit")
        if any(address < hi and lo < end for lo, hi in spans):
            raise ValueError(f"{write['field']}: overlaps another declared write")
        spans.append((address, end))
        validated.append((address, before, after))
    return validated


def config_offset(ffinit: bytes, boot: bytes) -> int:
    pair = struct.pack("<II", len(boot), zlib.crc32(boot))
    first = ffinit.find(pair)
    if first < 0 or ffinit.find(pair, first + 1) >= 0:
        raise ValueError("ffboot length/CRC pair is not unique in ffinit.bin")
    return first


def stock_build(stock_dir: Path) -> tuple[str, dict]:
    """Identify an audited FujiMod stock set by its ffboot.bin hash."""
    boot = sha((stock_dir / "ffboot.bin").read_bytes())
    for name, known in STOCK_BUILDS.items():
        if known["files"]["ffboot.bin"] == boot:
            return name, known
    raise ValueError("ffboot.bin is not an audited FujiMod stock output")


def build(stock_dir: Path, writes: list[dict]) -> tuple[dict[str, bytes], dict]:
    layout, known = stock_build(stock_dir)
    files = {name: (stock_dir / name).read_bytes() for name in known["files"]}
    for name, digest in known["files"].items():
        if sha(files[name]) != digest:
            raise ValueError(f"{name} is not the audited FujiMod stock output")
    boot = bytearray(files["ffboot.bin"])
    for w, (address, before, after) in zip(writes, validate_writes(writes, len(boot), known)):
        if boot[address:address + len(before)] != before:
            raise ValueError(f"{w['field']}: ffboot bytes at {address:#x} differ from expected old bytes")
        boot[address:address + len(after)] = after
    boot = bytes(boot)
    at = config_offset(files["ffinit.bin"], files["ffboot.bin"])
    init = bytearray(files["ffinit.bin"])
    struct.pack_into("<I", init, at + 4, zlib.crc32(boot))
    out = {**files, "ffinit.bin": bytes(init), "ffboot.bin": boot}
    report = {
        "stock_layout": layout,
        "ffinit_config_offset": hex(at),
        "ffboot_crc32_stock": hex(zlib.crc32(files["ffboot.bin"])),
        "ffboot_crc32_candidate": hex(zlib.crc32(boot)),
        "files": {n: {"size": len(b), "sha256": sha(b)} for n, b in out.items()},
    }
    return out, report


def audit(stock_dir: Path, card: dict[str, bytes], writes: list[dict]) -> dict:
    """Re-derive every difference from the stock files without reusing build()."""
    _, known = stock_build(stock_dir)
    stock = {n: (stock_dir / n).read_bytes() for n in known["files"]}
    a, b = stock["ffboot.bin"], card["ffboot.bin"]
    changed = {i for i in range(len(a)) if a[i] != b[i]} if len(a) == len(b) else None
    declared = set()
    for w in writes:
        address = ram_address(w)
        old, new = bytes.fromhex(w["before_hex"]), bytes.fromhex(w["after_hex"])
        declared |= {address + k for k in range(len(old)) if old[k] != new[k]}
    init_a, init_b = stock["ffinit.bin"], card["ffinit.bin"]
    init_diff = [i for i in range(len(init_a)) if init_a[i] != init_b[i]]
    at = init_a.find(struct.pack("<II", len(a), zlib.crc32(a)))
    return {
        "ffboot_same_length": len(a) == len(b),
        "ffboot_changes_equal_declared": changed == declared,
        "ffboot_changed_bytes": len(changed or ()),
        "ffinit_changes_only_in_crc_word": bool(init_diff) and all(at + 4 <= i < at + 8 for i in init_diff),
        "ffinit_crc_matches_card_ffboot": struct.unpack_from("<I", init_b, at + 4)[0] == zlib.crc32(b),
        "ffinit_length_word_unchanged": struct.unpack_from("<I", init_b, at)[0] == len(b),
        "same_file_set_as_stock": set(card) == set(stock),
        "other_files_unchanged": all(card[n] == stock[n] for n in stock if n not in ("ffinit.bin", "ffboot.bin")),
        "fpupdate_is_stock": sha(card["FPUPDATE.DAT"]) == STOCK_SHA256,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("stock_dir", type=Path, help="fujimod-recovery build output for the stock DAT")
    p.add_argument("writes", type=Path, help="integrated writes.json")
    p.add_argument("output_dir", type=Path, help="new directory for the card files")
    a = p.parse_args()
    writes = json.loads(a.writes.read_text())
    card, report = build(a.stock_dir, writes)
    report["audit"] = audit(a.stock_dir, card, writes)
    if not all(report["audit"].values()):
        raise SystemExit(json.dumps(report, indent=2))
    a.output_dir.mkdir(parents=True, exist_ok=False)
    for name, data in card.items():
        (a.output_dir / name).write_bytes(data)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
