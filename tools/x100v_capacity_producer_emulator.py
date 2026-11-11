"""Execute original format-0 count entry, both cost wrappers and stock helpers.

Uses exact DAT defaults, an explicit 640x480/mode-1 component, and synthetic
available capacity/limit plus missing-volume registry. No calls are stubbed.
Does not execute cache construction or prove mounted-volume, active-settings,
other-format, capture, boot, or secondary-array behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_estimate_leaf_emulator import execute, load_images, load_defaults, DEFAULTS_SHA256

# Fixed independent counts for C=100000000, cap=1000, using retained
# independently checked wrapper reference costs, not emulator-derived output.
VECTORS = (
    ("L", 6240, 3512, 2304, ((6, 16), (10, 16))),
    ("M", 4416, 2488, 1632, ((14, 32), (21, 32))),
    ("S", 3120, 1760, 1152, ((28, 62), (42, 62))),
)


def verify(primary: bytes, kernel: bytes, defaults: bytes) -> dict:
    import unicorn
    cases = []
    for name, width, old_height, new_height, expected_modes in VECTORS:
        for mode, expected in enumerate(expected_modes):
            for category in (0, 3):
                for available, limit, wanted in ((100000000, 1000, expected),
                                                  (0, 1000, (0, 0)),
                                                  (2**32, 17, (17, 17))):
                    kwargs = dict(mode=mode, category_input=category, initialize_from_settings=True,
                                  settings_defaults=defaults, wrapper_multiplier=0, wrapper_extra=True,
                                  count_available=available, count_limit=limit)
                    before = execute(primary, kernel, width, old_height, None, **kwargs)
                    after = execute(primary, kernel, width, new_height, None, **kwargs)
                    if (before["count_u32"], after["count_u32"]) != wanted:
                        raise AssertionError(f"count fixture failed: {name}/{mode}/{category}/{available}: {before}, {after}")
                    for result in (before, after):
                        if not result["count_entry_executed"] or result["wrapper_calls"] != 2:
                            raise AssertionError("original count path did not call both wrappers")
                        if result["property_reads"] != 134 or result["coefficient_writes"] != 132:
                            raise AssertionError("original property initialization/read sequence changed")
                        if not result["volume_16k_fallback_executed"] or not result["extra_component_executed"]:
                            raise AssertionError("required wrapper routes were not executed")
                    cases.append({"size": name, "mode": mode, "category_input": category,
                                  "available": available, "limit": limit,
                                  "expected_stock": wanted[0], "expected_xpan": wanted[1],
                                  "stock": before, "xpan": after,
                                  "stock_count_no_greater_than_xpan": wanted[0] <= wanted[1]})
    return {"scope": __doc__, "unicorn_version": unicorn.__version__,
            "entry": "0x011672ec", "format": 0,
            "cpu_model": "Cortex-A15 ISA only, FPSCR=0",
            "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(), "defaults_sha256": DEFAULTS_SHA256,
            "cases": cases, "cache_constructor_executed": False,
            "mounted_volume_verified": False, "active_settings_verified": False,
            "secondary_array_verified": False, "cache_reuse_safe_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_defaults(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} full format-0 count comparisons passed; bounded fixtures only")


if __name__ == "__main__":
    main()
