"""Run the stock volume-record publisher before the stock format-0 count path.

The 160-byte volume record is synthetic; the original functions compute,
publish and query its unit in the same emulated RAM. No context-unit result
is inserted between these stages. This does not mount a card or boot a camera.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_estimate_leaf_emulator import execute, load_images, load_defaults, load_volume, DEFAULTS_SHA256
from tools.x100v_volume_context_emulator import SIZES, reference_cost, reference_count

# (record +0x1c, record +0x48, expected unit, expected normalized halfword).
# Zero cases deliberately distinguish raw multiplication from nearby normalization.
VECTORS = ((512, 1, 512, 512), (512, 8, 4096, 512), (512, 32, 16384, 512),
           (512, 64, 32768, 512), (512, 128, 65536, 512), (4096, 8, 32768, 4096),
           (0, 32, 0, 512), (512, 0, 0, 512), (0, 0, 0, 512))


def verify(primary: bytes, kernel: bytes, defaults: bytes, volume: bytes) -> dict:
    import unicorn
    cases = []
    for first, second, unit, normalized in VECTORS:
        for size, width, old_height, new_height in SIZES:
            for mode in (0, 1):
                results, expected = [], []
                for height, coefficient in ((old_height, 48 if mode == 0 else 32), (new_height, 32)):
                    result = execute(primary, kernel, width, height, None, mode,
                                     initialize_from_settings=True, settings_defaults=defaults,
                                     wrapper_multiplier=0, wrapper_extra=True, count_available=100000000,
                                     volume_image=volume, volume_record=(first, second))
                    expected_count = reference_count(*(reference_cost(width, height, coefficient, flag, unit)
                                                       for flag in (0, 1)))
                    if (result["count_u32"] != expected_count or result["volume_producer_calls"] != 1
                            or result["volume_record_reader_calls"] != 1
                            or result["volume_producer_context"] != dict(unit=unit, status=1, normalized_halfword=normalized)
                            or result["volume_units_returned"] != [unit, unit]
                            or result["volume_query_statuses"] != [0, 0]
                            or result["volume_context_query_calls"] != 2
                            or result["volume_16k_fallback_executed"]
                            or result["property_reads"] != 134 or result["coefficient_writes"] != 132):
                        raise AssertionError(f"producer fixture failed: {(first, second, size, mode)}, {result}")
                    results.append(result)
                    expected.append(expected_count)
                if expected[0] > expected[1]:
                    raise AssertionError("stock count exceeds XPan count within tested defaults")
                cases.append(dict(record_halfwords=[first, second], expected_unit=unit,
                                  expected_normalized_halfword=normalized, size=size, mode=mode,
                                  expected_stock_count=expected[0], expected_xpan_count=expected[1],
                                  stock=results[0], xpan=results[1]))
    return dict(scope=__doc__, unicorn_version=unicorn.__version__,
                cpu_model="Cortex-A15 ISA only; not physical processor identification",
                primary_sha256=hashlib.sha256(primary).hexdigest(),
                kernel_sha256=hashlib.sha256(kernel).hexdigest(),
                volume_sha256=hashlib.sha256(volume).hexdigest(), defaults_sha256=DEFAULTS_SHA256,
                record_fixture={"index": 0, "stride": 160, "word_0x04": 1048576,
                                "other_bytes": "zero", "unit_source_offsets": [28, 72]},
                cases=cases, mounted_volume_verified=False, active_settings_verified=False,
                secondary_array_verified=False, cache_reuse_safe_verified=False, firmware_modified=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_defaults(args.update), load_volume(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} paired volume-producer/count comparisons passed; synthetic records only")


if __name__ == "__main__":
    main()
