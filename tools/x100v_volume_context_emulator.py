"""Execute stock wrappers/counts through the real volume request-8 method.

Only the registry and context are synthetic. DAT code/defaults are hash-pinned.
No camera, mounted card, MMIO, boot or cache construction is emulated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_estimate_leaf_emulator import (
    execute, load_images, load_defaults, load_volume, DEFAULTS_SHA256,
)

SIZES = (("L", 6240, 3512, 2304), ("M", 4416, 2488, 1632), ("S", 3120, 1760, 1152))
UNITS = (512, 4096, 16384, 32768, 65536)


def reference_cost(width: int, height: int, coefficient: int, multiplier: int, unit: int) -> int:
    """Independent integer/IEEE-float oracle for the bounded default kind-0 case.

    Includes the source descriptor's 640x480/mode-1 component. Not a model
    for arbitrary firmware inputs, other modes, overflow or active settings.
    """
    main = width * height * coefficient // 80 + 12288
    extra = 46080
    if multiplier:
        # Inputs are exact float32 integers in this fixture domain; force the
        # intermediate float32 rounding independently of Unicorn's ARM engine.
        main = int(struct.unpack("<f", struct.pack("<f", main * 1.25))[0])
        extra = 57600
    total = main + extra + 65536 + (153600 if multiplier else 0)
    kib = (total + 1023) // 1024 * 1024
    return (kib + unit - 1) // unit * unit if unit else 0


def reference_count(a: int, b: int, capacity: int = 100000000, limit: int = 1000) -> int:
    if not a or not b or capacity < b:
        return 0
    if capacity < 2 * b:
        return 1
    if capacity < 3 * b:
        return 2
    return min(limit, (capacity - 3 * b) // a + 3)


def verify(primary: bytes, kernel: bytes, defaults: bytes, volume: bytes) -> dict:
    import unicorn
    cases = []

    def pair(size, mode, category, unit, status, null, kind, multiplier):
        name, width, old_height, new_height = size
        effective = 16384 if null or not status else unit
        kwargs = dict(mode=mode, category_input=category, initialize_from_settings=True,
                      settings_defaults=defaults, wrapper_multiplier=multiplier,
                      wrapper_extra=True, volume_image=volume, volume_unit=unit,
                      volume_status=status, volume_null=null)
        if kind == "count":
            kwargs.update(count_available=100000000, count_limit=1000)
        actual, expected = [], []
        for height, coefficient in ((old_height, 48 if mode == 0 else 32), (new_height, 32)):
            result = execute(primary, kernel, width, height, None, **kwargs)
            costs = [reference_cost(width, height, coefficient, flag, effective) for flag in (0, 1)]
            wanted = reference_count(*costs) if kind == "count" else costs[multiplier]
            field = "count_u32" if kind == "count" else "estimated_bytes"
            calls = 2 if kind == "count" else 1
            if result[field] != wanted:
                raise AssertionError(f"volume fixture {name}/{mode}/{unit}/{status}/{null}/{kind}: {result}, expected {wanted}")
            if (result["volume_context_query_calls"] != calls or
                    result["volume_units_returned"] != [effective] * calls or
                    result["volume_query_statuses"] != [int(null or not status)] * calls or
                    result["volume_16k_fallback_executed"] != bool(null or not status)):
                raise AssertionError(f"wrong actual volume query route: {result}")
            if (result["wrapper_calls"] != calls or result["property_reads"] != 132 + calls
                    or result["coefficient_writes"] != 132 or not result["extra_component_executed"]):
                raise AssertionError("stock cost initialization/call path changed")
            actual.append(result)
            expected.append(wanted)
        ordering = expected[0] <= expected[1] if kind == "count" else expected[0] >= expected[1]
        if not ordering:
            raise AssertionError("stock/XPan ordering changed within fixture domain")
        cases.append(dict(size=name, mode=mode, category=category, unit=unit, status=status,
                          null_context=null, kind=kind, multiplier=multiplier,
                          effective_unit=effective, expected_stock=expected[0], expected_xpan=expected[1],
                          stock=actual[0], xpan=actual[1], expected_ordering_verified=ordering))

    for size in SIZES:
        for mode in (0, 1):
            for category in (0, 3):
                for unit in UNITS:
                    for flag in (0, 1):
                        pair(size, mode, category, unit, 1, False, "wrapper", flag)
                    pair(size, mode, category, unit, 1, False, "count", 0)
    for unit, status, null in ((0, 1, False), (4096, 0, False), (4096, 1, True), (4096, 255, False)):
        for kind, flag in (("wrapper", 0), ("wrapper", 1), ("count", 0)):
            pair(SIZES[0], 0, 0, unit, status, null, kind, flag)
    return dict(scope=__doc__, unicorn_version=unicorn.__version__,
                cpu_model="Cortex-A15 ISA only, FPSCR=0; not camera hardware identification",
                primary_sha256=hashlib.sha256(primary).hexdigest(),
                kernel_sha256=hashlib.sha256(kernel).hexdigest(),
                volume_sha256=hashlib.sha256(volume).hexdigest(), defaults_sha256=DEFAULTS_SHA256,
                cases=cases, mounted_volume_verified=False, active_settings_verified=False,
                cache_constructor_executed=False, secondary_array_verified=False,
                cache_reuse_safe_verified=False, firmware_modified=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_defaults(args.update), load_volume(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} paired volume-context comparisons passed; synthetic contexts only")


if __name__ == "__main__":
    main()
