"""Independent audit of FujiMod's X100V 3.01 XP4 recovery files.

Reads the stock update with this repository's own container model and LZSS
decoder (never FujiMod code), rebuilds the stock RAM image the recipe
describes (regions copied, BSS and gaps zero), and accounts for every byte
where FujiMod's ffboot.bin differs. It also checks that the card's
FPUPDATE.DAT is the unchanged stock file and locates ffdata.bin's content in
the stock image. Read-only; it never touches a card or camera.

This establishes what FujiMod changed relative to stock. It does not show that
FujiMod's own loader code (ffinit.bin) boots on a camera.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from tools.fuji_firmware_probe import lzss_decode
from tools.x100v_update_package import IMAGE_BASE, STOCK_SHA256



def region_bytes(raw: bytes, source: dict) -> bytes:
    """Decode one recipe source span from the DAT using our own decoder."""
    start = source["dat_offset"]
    span = bytes(b ^ 0xFF for b in raw[start:start + source["size"]])
    if source["compression"] == "raw":
        data = span[:source["decoded_size"]]
    elif source["compression"] == "method4":
        output, packed = int.from_bytes(span[0:4], "little"), int.from_bytes(span[4:8], "little")
        data = lzss_decode(span[20:packed], output)
    else:
        raise ValueError(f"unknown compression {source['compression']}")
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError(f"region at DAT {start:#x} does not match the recipe hash")
    return data


def expected_ram(raw: bytes, plan: dict, length: int) -> tuple[bytearray, list[dict]]:
    image = bytearray(length)
    placed = []
    for region in plan["regions"]:
        data = region_bytes(raw, region["source"])
        image[region["address"]:region["address"] + len(data)] = data
        placed.append({"name": region["name"], "address": hex(region["address"]), "size": hex(len(data))})
    return image, placed


def owner(address: int, plan: dict) -> str:
    for region in plan["regions"]:
        size = region["source"]["decoded_size"]
        if region["address"] <= address < region["address"] + size:
            return region["name"]
    for bss in plan["bss"]:
        if bss["address"] <= address < bss["address"] + bss["size"]:
            return f"bss:{bss['name']}"
    return "gap"


def diff_runs(a: bytes, b: bytes, merge: int = 16) -> list[tuple[int, int]]:
    x = np.frombuffer(a, dtype=np.uint8)
    y = np.frombuffer(b, dtype=np.uint8)
    idx = np.nonzero(x != y)[0]
    runs: list[list[int]] = []
    for i in idx.tolist():
        if runs and i - runs[-1][1] <= merge:
            runs[-1][1] = i + 1
        else:
            runs.append([i, i + 1])
    return [(lo, hi) for lo, hi in runs]


def audit(dat: Path, recipe_path: Path, out_dir: Path) -> dict:
    raw = dat.read_bytes()
    if hashlib.sha256(raw).hexdigest() != STOCK_SHA256:
        raise ValueError("source DAT is not the pinned stock X100V 3.01 update")
    recipe = next(r for r in json.loads(recipe_path.read_text()) if r["firmware_id"] == "x100v-301")
    plan = recipe["plan"]
    boot = (out_dir / "ffboot.bin").read_bytes()
    stock_ram, placed = expected_ram(raw, plan, max(len(boot), plan["size"]))
    stock_ram = bytes(stock_ram[:len(boot)])
    runs = diff_runs(stock_ram, boot)
    declared = {e["address"]: e for e in plan["edits"]}
    rows = []
    for lo, hi in runs:
        rows.append({
            "address": hex(lo), "length": hi - lo, "owner": owner(lo, plan),
            "declared_edit": declared.get(lo, {}).get("what"),
            "stock_head": stock_ram[lo:min(hi, lo + 16)].hex(), "ffboot_head": boot[lo:min(hi, lo + 16)].hex(),
        })
    by_owner: dict[str, int] = {}
    for row in rows:
        by_owner[row["owner"]] = by_owner.get(row["owner"], 0) + row["length"]

    ffdata_hits = []
    if (out_dir / "ffdata.bin").exists():  # preloaded layout before FujiMod b13b12c
        image = bytes(b ^ 0xFF for b in raw[IMAGE_BASE:])
        ffdata = (out_dir / "ffdata.bin").read_bytes()
        for at in range(0, len(ffdata), 0x10000):
            chunk = ffdata[at:at + 0x40]
            if chunk.strip(b"\0"):
                found = image.find(chunk)
                ffdata_hits.append({"ffdata_offset": hex(at), "image_offset": hex(found) if found >= 0 else None})
    located = [h for h in ffdata_hits if h["image_offset"] is not None]

    card_dat = (out_dir / "FPUPDATE.DAT").read_bytes()
    return {
        "files": {p.name: {"size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                  for p in sorted(out_dir.iterdir())},
        "card_fpupdate_is_unchanged_stock": card_dat == raw,
        "recipe_regions_decoded_and_hash_checked": placed,
        "ffboot_size": hex(len(boot)), "plan_size": hex(plan["size"]),
        "ffboot_changed_bytes_total": sum(r["length"] for r in rows),
        "ffboot_changed_bytes_by_owner": by_owner,
        "ffboot_change_runs": rows,
        "ffdata_nonzero_probe_chunks": len(ffdata_hits),
        "ffdata_probe_chunks_found_in_stock_image": len(located),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("dat", type=Path)
    p.add_argument("recipe", type=Path, help="FujiMod catalog/recovery/recipes.generated.json")
    p.add_argument("files", type=Path, help="directory produced by fujimod-recovery build")
    a = p.parse_args()
    print(json.dumps(audit(a.dat, a.recipe, a.files), indent=2))


if __name__ == "__main__":
    main()
