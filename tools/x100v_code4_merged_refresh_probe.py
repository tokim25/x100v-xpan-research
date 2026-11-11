"""Run the bounded preview-refresh caller on the audited offline merge.

Executes stock ARM in synthetic RAM through threshold processing, stopping
before status publication, recomputation, callback, or camera I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_merged_preview_probe import CANDIDATE_DAT_SHA256
from tools.x100v_estimate_leaf_emulator import load_volume
from tools.x100v_preview_cache_export_emulator import load_images
from tools.x100v_refresh_caller_emulator import MERGED_PRIMARY_SHA256, verify
from tools.x100v_update_package import read_primary, read_secondary

SECONDARY_PAGES = (0x1EA0000, 0x1EA3000, 0x1F68000)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    candidate_raw = args.candidate.read_bytes()
    if hashlib.sha256(candidate_raw).hexdigest() != CANDIDATE_DAT_SHA256:
        raise ValueError("offline package identity changed")
    stock, secondary = load_images(args.stock)
    candidate = read_primary(candidate_raw)[1]
    candidate_secondary = read_secondary(candidate_raw)[1]
    if hashlib.sha256(candidate).hexdigest() != MERGED_PRIMARY_SHA256:
        raise ValueError("merged primary identity changed")
    base = SOURCES["x100v_3_01"]["secondary_load"]
    for page in SECONDARY_PAGES:
        pos = page - base
        if secondary[pos:pos+4096] != candidate_secondary[pos:pos+4096]:
            raise ValueError(f"merged secondary refresh page changed at {page:#x}")
    report = verify(stock, secondary, load_volume(args.stock), candidate,
                    through_threshold=True, candidate_profile="merged")
    counts = Counter(case["stop_pc"] for case in report["cases"])
    report["candidate_update_sha256"] = CANDIDATE_DAT_SHA256
    report["merged_secondary_pages_equal_stock"] = [hex(page) for page in SECONDARY_PAGES]
    report["boundary_counts"] = dict(sorted(counts.items()))
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"{len(report['cases'])} cases passed; boundaries {dict(sorted(counts.items()))}")


if __name__ == "__main__":
    main()
