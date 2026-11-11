"""Test stock kind-0 cost wrapper with DAT defaults and missing-volume fixture.

The volume registry is synthetic and selects the original 16-KiB fallback.
No callee is stubbed. Other wrapper kinds, mounted volumes, count production,
cache construction, capture, and boot are not covered here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_estimate_leaf_emulator import execute, load_images, load_defaults, DEFAULTS_SHA256

# Fixed reference outputs: pairs in (mode 0/flag 0, 0/1, 1/0, 1/1) order.
# Each row gives no-extra and 640x480/mode-1-extra controls separately.
VECTORS = (
    ("L", 6240, 3512, 2304,
     ((13238272, 5832704), (16678912, 7438336), (8847360, 5832704), (11206656, 7438336)),
     ((13287424, 5881856), (16744448, 7487488), (8896512, 5881856), (11255808, 7487488))),
    ("M", 4416, 2488, 1632,
     ((6684672, 2965504), (8486912, 3850240), (4472832, 2965504), (5734400, 3850240)),
     ((6717440, 3014656), (8536064, 3899392), (4521984, 3014656), (5799936, 3899392))),
    ("S", 3120, 1760, 1152,
     ((3375104, 1523712), (4358144, 2031616), (2277376, 1523712), (2981888, 2031616)),
     ((3424256, 1572864), (4423680, 2097152), (2326528, 1572864), (3047424, 2097152))),
)


def verify(primary: bytes, kernel: bytes, defaults: bytes) -> dict:
    import unicorn
    cases = []
    for size, width, old_height, new_height, plain, with_extra in VECTORS:
        for extra, expected_pairs in ((False, plain), (True, with_extra)):
            for (mode, multiplier), expected in zip(((0, 0), (0, 1), (1, 0), (1, 1)), expected_pairs):
                for category in (0, 3):
                    args = dict(mode=mode, category_input=category, initialize_from_settings=True,
                                settings_defaults=defaults, wrapper_multiplier=multiplier, wrapper_extra=extra)
                    before = execute(primary, kernel, width, old_height, None, **args)
                    after = execute(primary, kernel, width, new_height, None, **args)
                    if (before["estimated_bytes"], after["estimated_bytes"]) != expected:
                        raise AssertionError(f"wrapper fixed vector failed: {size}/{mode}/{multiplier}/{extra}: {before}, {after}")
                    for result in (before, after):
                        if not result["wrapper_executed"] or not result["volume_16k_fallback_executed"]:
                            raise AssertionError("wrapper or volume fallback not executed")
                        if result["extra_component_executed"] != extra:
                            raise AssertionError("wrong extra-component route")
                        if result["property_reads"] != 133 or result["coefficient_writes"] != 132:
                            raise AssertionError("stock property flow changed")
                    cases.append({"size": size, "mode": mode, "category_input": category,
                                  "multiplier_flag": multiplier, "extra_640x480_mode1": extra,
                                  "expected_stock": expected[0], "expected_xpan": expected[1],
                                  "stock": before, "xpan": after,
                                  "stock_estimate_at_least_xpan": expected[0] >= expected[1]})
    return {"scope": __doc__, "unicorn_version": unicorn.__version__,
            "cpu_model": "Cortex-A15 ISA only, FPSCR=0; not camera processor identification",
            "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(), "defaults_sha256": DEFAULTS_SHA256,
            "volume_fixture": {"selector": 65, "registry_entry": "0xffffffff", "fallback_unit": 16384},
            "cases": cases, "mounted_volume_verified": False, "active_settings_verified": False,
            "cache_reuse_safe_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_defaults(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} stock wrapper comparisons passed; default settings and missing-volume fixture only")


if __name__ == "__main__":
    main()
