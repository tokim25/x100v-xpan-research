"""Run the 16:9 crop helper rewritten for 65:24 against stock GFX code 4.

Executes the original X100V helper bytes (stock, and with card 4b's two
code-2 words) and the original GFX100 5.18 helper under the Cortex-A15 ISA
model in tools.x100v_ratio_arm_emulator. Synthetic registers and memory
only; this is not a camera or firmware emulator.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from tools.x100v_16x9_to_65x24 import CODE_SITES
from tools.x100v_ratio_arm_emulator import execute, load_stock
from tools.x100v_update_package import PRIMARY_LOAD

INPUTS = [(6240, 4160), (4416, 2944), (3120, 2080), (6000, 4000)]


def patch_primary(stock: bytes) -> bytes:
    image = bytearray(stock)
    for field, part, address, old, new in CODE_SITES:
        if part != 6:
            continue
        at = address - PRIMARY_LOAD
        if image[at:at + 4 * len(old)] != struct.pack(f"<{len(old)}I", *old):
            raise ValueError(f"{field}: stock words differ")
        image[at:at + 4 * len(new)] = struct.pack(f"<{len(new)}I", *new)
    return bytes(image)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--x100v", type=Path, required=True)
    parser.add_argument("--gfx100", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    stock = load_stock(args.x100v, "x100v_3_01")
    patched = patch_primary(stock)
    gfx = load_stock(args.gfx100, "gfx100_5_18")
    rows = []
    for w, h in INPUTS:
        rows.append({
            "input": [w, h],
            "x100v_stock_code2": execute(stock, w, h, 2)["words"],
            "x100v_patched_code2": execute(patched, w, h, 2)["words"],
            "gfx_stock_code4": execute(gfx, w, h, 4, "gfx100_5_18")["words"],
            "x100v_patched_code1_unchanged": execute(patched, w, h, 1) == execute(stock, w, h, 1),
            "x100v_patched_code3_unchanged": execute(patched, w, h, 3) == execute(stock, w, h, 3),
        })
    for r in rows:
        r["patched_code2_equals_gfx_code4"] = r["x100v_patched_code2"] == r["gfx_stock_code4"]
    report = {
        "kind": "original ARM bytes under a Cortex-A15 ISA model; synthetic registers and memory",
        "helper": "X100V 0x0115eee0 with card 4b's code-2 words; GFX 0x01341aa8 stock",
        "rows": rows,
        "all_match_gfx": all(r["patched_code2_equals_gfx_code4"] for r in rows),
        "other_codes_unchanged": all(r["x100v_patched_code1_unchanged"] and r["x100v_patched_code3_unchanged"] for r in rows),
        "not_established": "which callers run during a still shot, movie effects, JPEG or RAF output",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("all_match_gfx", "other_codes_unchanged")}))
    for r in rows:
        print(r["input"], "stock16:9", r["x100v_stock_code2"], "patched", r["x100v_patched_code2"], "gfx65:24", r["gfx_stock_code4"])


if __name__ == "__main__":
    main()
