"""Run stock dimension-cost estimation in isolated RAM.

Optionally execute property initialization and the stock keyed-byte getter
against synthetic settings or hash-checked DAT defaults. An optional kind-0
wrapper/count path uses a synthetic missing-volume mapping or volume context. No camera, full cache
constructor, or boot is executed. This never edits firmware files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.x100v_encoder_dimension_emulator import load_images, verify_images
from tools.fuji_xpan_validation import read_dimension_estimate_coeff_table, SOURCES
from tools.fuji_firmware_probe import HEADER_SIZE

ENTRY, END = 0x01168C98, 0x01168E24
TABLE, FLAG = 0x01519744, 0x016FA360
STACK, STOP = 0x20000000, 0x30000000
SETTINGS, SETTINGS_POINTER = 0x10000000, 0x0159EDB4
DEFAULTS_DAT_OFFSET = SOURCES["x100v_3_01"]["configuration_defaults_offset"] + HEADER_SIZE
DEFAULTS_SIZE = SOURCES["x100v_3_01"]["configuration_defaults_size"]
DEFAULTS_SHA256 = SOURCES["x100v_3_01"]["configuration_defaults_sha256"]
DEFAULTS_CATALOG = "https://github.com/justjake/fujimod/blob/130dabad704a4cbdb0440b91b0d40637dbc3f55d/catalog/recovery/recipes.generated.json"
VOLUME_CONTEXT = 0x31000000

# Fixed independent rational-area reference values, not emulator observations.
VECTORS = (
    ("L", 6240, 3512, 2304, (5491008, 5764944, 8778240, 13161216), 5763072),
    ("M", 4416, 2488, 1632, (2759040, 2896377, 4407091, 6604492), 2895052),
    ("S", 3120, 1760, 1152, (1385088, 1453728, 2208768, 3307008), 1449984),
)


def load_defaults(update: Path) -> bytes:
    data = update.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCES["x100v_3_01"]["sha256"]:
        raise ValueError("unrecognized X100V update")
    defaults = bytes(byte ^ 255 for byte in data[DEFAULTS_DAT_OFFSET:DEFAULTS_DAT_OFFSET + DEFAULTS_SIZE])
    verify_defaults(defaults)
    return defaults


def verify_defaults(defaults: bytes) -> None:
    if len(defaults) != DEFAULTS_SIZE or hashlib.sha256(defaults).hexdigest() != DEFAULTS_SHA256:
        raise ValueError("unrecognized configuration defaults")


def verify_volume(volume: bytes) -> None:
    source = SOURCES["x100v_3_01"]
    if (len(volume) != source["volume_partition_size"] or
            hashlib.sha256(volume).hexdigest() != source["volume_partition_sha256"]):
        raise ValueError("unrecognized volume partition")


def load_volume(update: Path) -> bytes:
    data = update.read_bytes()
    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("unrecognized X100V update")
    start = HEADER_SIZE + source["volume_partition_offset"]
    volume = bytes(byte ^ 255 for byte in data[start:start + source["volume_partition_size"]])
    verify_volume(volume)
    return volume


def execute(primary: bytes, kernel: bytes, width: int, height: int,
            coefficient: int | None, mode: int = 0, category_input: int = 0,
            selector: int = 0, *, initialize_from_settings: bool = False,
            settings_defaults: bytes | None = None,
            wrapper_multiplier: int | None = None, wrapper_extra: bool = False,
            count_available: int | None = None, count_limit: int = 1000,
            volume_image: bytes | None = None, volume_unit: int = 16384,
            volume_status: int = 1, volume_null: bool = False,
            volume_record: tuple[int, int] | None = None) -> dict:
    verify_images(primary, kernel)
    for value, limit in ((width, 65535), (height, 65535),
                         (mode, 2), (category_input, 5), (selector, 3)):
        if type(value) is not int or not 0 <= value <= limit:
            raise ValueError("fixture outside bounded estimator domain")
    if settings_defaults is not None:
        verify_defaults(settings_defaults)
        if not initialize_from_settings or coefficient is not None:
            raise ValueError("stock defaults require initialization and no coefficient override")
    elif type(coefficient) is not int or not 0 <= coefficient <= 255:
        raise ValueError("fixture coefficient outside byte domain")
    if wrapper_multiplier is not None:
        if type(wrapper_multiplier) is not int or wrapper_multiplier not in (0, 1):
            raise ValueError("wrapper multiplier flag outside 0/1")
        if settings_defaults is None or selector != 0:
            raise ValueError("wrapper fixture requires stock defaults and selector zero")
    elif wrapper_extra:
        raise ValueError("extra component requires wrapper execution")
    if count_available is not None:
        if (type(count_available) is not int or not 0 <= count_available < 2**64
                or type(count_limit) is not int or not 0 <= count_limit < 2**32):
            raise ValueError("count fixture outside register domains")
        if wrapper_multiplier != 0:
            raise ValueError("count entry requires wrapper setup with initial multiplier zero")
    if volume_image is not None:
        verify_volume(volume_image)
        if wrapper_multiplier is None:
            raise ValueError("volume fixture requires wrapper execution")
        if (type(volume_unit) is not int or volume_unit not in (0, 512, 4096, 16384, 32768, 65536)
                or type(volume_status) is not int or volume_status not in (0, 1, 255)
                or type(volume_null) is not bool):
            raise ValueError("volume fixture outside bounded context domain")
    elif (volume_unit, volume_status, volume_null) != (16384, 1, False):
        raise ValueError("volume context options require a volume image")
    if volume_record is not None:
        if (volume_image is None or volume_null or volume_status != 1 or volume_unit != 16384
                or type(volume_record) is not tuple or len(volume_record) != 2
                or any(type(value) is not int or not 0 <= value <= 65535 for value in volume_record)
                or volume_record[0] * volume_record[1] > 65536):
            raise ValueError("volume-record fixture outside bounded producer domain")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R11, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
        UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC, UC_ARM_REG_FPSCR)

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    pages = [ENTRY & ~4095, 0x01140000, TABLE & ~4095]
    if wrapper_multiplier is not None:
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        uc.reg_write(UC_ARM_REG_C1_C0_2, 0xF << 20)
        uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        uc.reg_write(UC_ARM_REG_FPSCR, 0)
        pages += [0x01169000, 0x01167000, 0x0113A000]
        uc.mem_map(0x01851000, 4096)
        uc.mem_write(0x01851BB4, b"\xff" * 4)  # selector 65 -> no volume
        if volume_image is not None:
            uc.mem_write(0x01851BB4, struct.pack("<I", 0))
            uc.mem_map(0x01850000, 4096)
            uc.mem_write(0x018509B0, struct.pack("<I", 0x00D20400))
            uc.mem_map(0x00D20000, 4096)
            uc.mem_write(0x00D20400, volume_image[:0xC00])
            uc.mem_map(0x00D27000, 4096)
            uc.mem_write(0x00D27000, volume_image[0x6C00:0x7C00])
            uc.mem_map(0x00D89000, 4096)
            uc.mem_write(0x00D89A20, struct.pack("<I", 0 if volume_null else VOLUME_CONTEXT))
            if not volume_null:
                uc.mem_map(VOLUME_CONTEXT, 0x17000)
                if volume_record is None:
                    uc.mem_write(VOLUME_CONTEXT + 0x16B80, struct.pack("<I", volume_unit))
                    uc.mem_write(VOLUME_CONTEXT + 0x16BEC, bytes([volume_status]))
            if volume_record is not None:
                for page in (0x00D34000, 0x00D39000, 0x00D47000):
                    uc.mem_map(page, 4096)
                    start = page - 0x00D20400
                    uc.mem_write(page, volume_image[start:start + 4096])
                uc.mem_map(0x32000000, 4096)
                uc.mem_write(0x00D89A64, struct.pack("<I", 0x32000000))
                uc.mem_write(0x32000004, struct.pack("<I", 1048576))
                uc.mem_write(0x3200001C, struct.pack("<H", volume_record[0]))
                uc.mem_write(0x32000048, struct.pack("<H", volume_record[1]))
    for page in pages:
        uc.mem_map(page, 4096)
        uc.mem_write(page, primary[page - 0x00F21000:page + 4096 - 0x00F21000])
    uc.mem_map(0x0005A000, 4096)
    uc.mem_write(0x0005A000, kernel[0x1A000:0x1B000])
    uc.mem_map(FLAG & ~4095, 4096)
    rows = read_dimension_estimate_coeff_table(primary, 0x00F21000, TABLE, 132)
    expected_keys = [row["runtime_property_key"] for row in rows]
    if not all(0 <= key < 0x3D000 for key in expected_keys):
        raise ValueError("fixture would require an unmodeled settings bank")
    if initialize_from_settings:
        uc.mem_map(0x01127000, 4096)
        uc.mem_write(0x01127000, primary[0x206000:0x207000])
        uc.mem_map(SETTINGS_POINTER & ~4095, 4096)
        uc.mem_write(SETTINGS_POINTER, struct.pack("<I", SETTINGS))
        settings_size = len(settings_defaults) if settings_defaults is not None else max(expected_keys) + 1
        uc.mem_map(SETTINGS, (settings_size + 4095) & ~4095)
        # All bytes are fixtures, not recovered camera settings. Only the
        # 16:9 keys vary; unrelated properties use the explicit fixture 48.
        if settings_defaults is not None:
            uc.mem_write(SETTINGS, settings_defaults)
        else:
            for key in set(expected_keys):
                uc.mem_write(SETTINGS + key, b"\x30")
            for row in rows[24:36]:
                uc.mem_write(SETTINGS + row["runtime_property_key"], bytes([coefficient]))
    else:
        uc.mem_write(FLAG, b"\x01")  # Explicitly bypass property initialization.
        for index in range(24, 36):
            uc.mem_write(TABLE + index * 16 + 7, bytes([coefficient]))
    uc.mem_map(STACK, 4096)
    initial_sp = STACK + 0xF00
    uc.mem_write(initial_sp, struct.pack("<I", selector))
    entry = ENTRY
    if wrapper_multiplier is not None:
        entry = 0x01168E24
        extra_pointer = STACK + 0x100 if wrapper_extra else 0
        if wrapper_extra:
            uc.mem_write(extra_pointer, struct.pack("<HHb", 640, 480, 1))
        uc.mem_write(initial_sp, struct.pack("<4I", mode, wrapper_multiplier, 0, extra_pointer))
        if count_available is not None:
            entry = 0x011672EC
            uc.mem_write(initial_sp, struct.pack("<14I", width, height, 0, 0, 0, 0,
                                               category_input, mode, count_limit, 0,
                                               extra_pointer, 0, 0, 0))
    visited, matched, pairs, property_keys, coefficient_writes = [], [], [], [], []
    volume_units, volume_returns, fallback_writes = [], [], []
    producer_active = False
    producer_context = None
    ranges = ((ENTRY, END), (0x01140A00, 0x01140A28), (0x0005AD28, 0x0005AF34))
    if initialize_from_settings:
        ranges += ((0x0112771C, 0x01127750), (0x01127848, 0x01127868))
    if wrapper_multiplier is not None:
        ranges += ((0x01168E24, 0x01169028), (0x011678DC, 0x0116790C), (0x0113A8E8, 0x0113A940))
    if count_available is not None:
        ranges += ((0x011672EC, 0x0116741C), (0x01167594, 0x011675F4))
    if volume_image is not None:
        ranges += ((0x00D2703C, 0x00D27068), (0x00D27124, 0x00D2714C),
                   (0x00D271E4, 0x00D271F4), (0x00D276FC, 0x00D27704))
    if volume_record is not None:
        ranges += ((0x00D3432C, 0x00D349E0), (0x00D3910C, 0x00D39340),
                   (0x00D476BC, 0x00D47754))

    def instruction(machine, address, size, _):
        if not any(start <= address < end for start, end in ranges):
            raise RuntimeError(f"estimator escaped bounded code: {address:#x}")
        visited.append(address)
        if address == 0x01167904:
            volume_units.append(machine.reg_read(UC_ARM_REG_R0))
        if address == 0x0113A92C:
            volume_returns.append(machine.reg_read(UC_ARM_REG_R0))
        if address == 0x01127848:
            property_keys.append(machine.reg_read(UC_ARM_REG_R0))
        if address == 0x01168D88:
            matched.append((machine.reg_read(UC_ARM_REG_R0) - TABLE) // 16)
        if address == 0x01168D98:
            pairs.append(list(machine.mem_read(machine.reg_read(UC_ARM_REG_R11) - 40, 2)))

    def write(machine, access, address, size, value, _):
        if machine.reg_read(UC_ARM_REG_PC) == 0x011678FC:
            fallback_writes.append(value)
        if producer_active and VOLUME_CONTEXT + 0x16B6C <= address <= VOLUME_CONTEXT + 0x16BF0 - size:
            return
        if initialize_from_settings and size == 1:
            if TABLE <= address < TABLE + 132 * 16 and (address - TABLE) % 16 == 7:
                coefficient_writes.append({"row": (address - TABLE) // 16, "value": value})
                return
            if address == FLAG and value == 1:
                return
        if not STACK <= address <= STACK + 4096 - size:
            raise RuntimeError(f"estimator unexpected write: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    if volume_record is not None:
        producer_active = True
        for reg, value in ((UC_ARM_REG_R0, 0), (UC_ARM_REG_SP, initial_sp), (UC_ARM_REG_LR, STOP)):
            uc.reg_write(reg, value)
        uc.emu_start(0x00D3432C, STOP, count=10000, timeout=1000000)
        if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_SP) != initial_sp:
            raise RuntimeError("volume producer did not return with restored stack")
        producer_active = False
        producer_context = {
            "unit": struct.unpack("<I", uc.mem_read(VOLUME_CONTEXT + 0x16B80, 4))[0],
            "status": uc.mem_read(VOLUME_CONTEXT + 0x16BEC, 1)[0],
            "normalized_halfword": struct.unpack("<H", uc.mem_read(VOLUME_CONTEXT + 0x16BD2, 2))[0],
        }
        if producer_context != {"unit": volume_record[0] * volume_record[1], "status": 1,
                                "normalized_halfword": volume_record[0] or 512}:
            raise AssertionError(f"volume producer context mismatch: {producer_context}")
    for reg, value in ((UC_ARM_REG_R0, width), (UC_ARM_REG_R1, height),
                       (UC_ARM_REG_R2, category_input), (UC_ARM_REG_R3, mode),
                       (UC_ARM_REG_SP, initial_sp), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    if wrapper_multiplier is not None:
        for reg, value in ((UC_ARM_REG_R0, 65), (UC_ARM_REG_R1, width),
                           (UC_ARM_REG_R2, height), (UC_ARM_REG_R3, category_input)):
            uc.reg_write(reg, value)
    if count_available is not None:
        for reg, value in ((UC_ARM_REG_R0, 65), (UC_ARM_REG_R1, 0),
                           (UC_ARM_REG_R2, count_available & 0xFFFFFFFF),
                           (UC_ARM_REG_R3, count_available >> 32)):
            uc.reg_write(reg, value)
    uc.emu_start(entry, STOP, count=30000, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP or uc.reg_read(UC_ARM_REG_SP) != initial_sp:
        raise RuntimeError("estimator did not return with restored stack")
    if initialize_from_settings:
        wrapper_calls = 2 if count_available is not None else int(wrapper_multiplier is not None)
        expected_reads = expected_keys + [0xA8] * wrapper_calls
        if property_keys != expected_reads or [item["row"] for item in coefficient_writes] != list(range(132)):
            raise AssertionError("property initialization did not cover all original rows in order")
        varying_keys = set(expected_keys[24:36])
        expected_values = ([settings_defaults[key] for key in expected_keys] if settings_defaults is not None
                           else [coefficient if key in varying_keys else 48 for key in expected_keys])
        if [item["value"] for item in coefficient_writes] != expected_values:
            raise AssertionError("property getter changed the supplied coefficient bytes")
        if uc.mem_read(FLAG, 1) != b"\x01":
            raise AssertionError("property initialized flag not set")
    return {"estimated_bytes": uc.reg_read(UC_ARM_REG_R0) if count_available is None else None,
            "count_u32": uc.reg_read(UC_ARM_REG_R0) if count_available is not None else None,
            "matched_rows": matched,
            "coefficient_divisor": pairs, "fallback_executed": 0x01168E08 in visited,
            "instructions": len(visited), "stock_division_executed": 0x0005AD28 in visited,
            "property_reads": len(property_keys), "unique_property_keys": len(set(property_keys)),
            "coefficient_writes": len(coefficient_writes),
            "settings_fixture_copied_without_clamping": initialize_from_settings,
            "stock_defaults_used": settings_defaults is not None,
            "wrapper_executed": wrapper_multiplier is not None,
            "wrapper_calls": visited.count(0x01168E24),
            "count_entry_executed": 0x011672EC in visited,
            "volume_16k_fallback_executed": bool(fallback_writes),
            "volume_units_returned": volume_units,
            "volume_query_statuses": volume_returns,
            "volume_context_query_calls": visited.count(0x00D2703C),
            "volume_producer_calls": visited.count(0x00D3432C),
            "volume_record_reader_calls": visited.count(0x00D3910C),
            "volume_producer_context": producer_context,
            "extra_component_executed": 0x01168FD4 in visited or 0x01169020 in visited}


def verify_stock_defaults(primary: bytes, kernel: bytes, defaults: bytes) -> dict:
    import unicorn
    verify_images(primary, kernel)
    verify_defaults(defaults)
    cases = []
    for size, width, old_height, new_height, expected_old, expected_new in VECTORS:
        for mode, coefficient, expected in ((0, 48, expected_old[3]), (1, 32, expected_old[2])):
            for category_input in (0, 3):
                before = execute(primary, kernel, width, old_height, None, mode, category_input,
                                 initialize_from_settings=True, settings_defaults=defaults)
                after = execute(primary, kernel, width, new_height, None, mode, category_input,
                                initialize_from_settings=True, settings_defaults=defaults)
                if before["estimated_bytes"] != expected or before["coefficient_divisor"] != [[coefficient, 10]]:
                    raise AssertionError(f"stock-default 16:9 fixture failed: {size}/{mode}/{category_input}")
                if after["estimated_bytes"] != expected_new or not after["fallback_executed"]:
                    raise AssertionError("stock-default XPan fallback changed")
                if before["fallback_executed"] or not before["matched_rows"] or after["matched_rows"]:
                    raise AssertionError("unexpected coefficient row selection")
                cases.append({"size": size, "mode": mode, "category_input": category_input,
                              "default_coefficient": coefficient, "expected_stock": expected,
                              "expected_xpan": expected_new, "stock": before, "xpan": after,
                              "stock_estimate_at_least_xpan": expected >= expected_new})
    return {"scope": "Stock estimator and initialization on hash-checked DAT configuration defaults; no live camera or full-wrapper execution",
            "unicorn_version": unicorn.__version__, "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
            "defaults": {"dat_offset": DEFAULTS_DAT_OFFSET, "size": DEFAULTS_SIZE,
                         "sha256": DEFAULTS_SHA256, "catalog": DEFAULTS_CATALOG,
                         "magic_0x202": defaults[0x202:0x204].hex()},
            "cases": cases, "property_initialization_executed": True,
            "runtime_coefficients_observed": False, "cache_reuse_safe_verified": False}


def verify(primary: bytes, kernel: bytes, *, initialize_from_settings: bool = False) -> dict:
    import unicorn
    cases = []
    for size, width, old_height, new_height, expected_old, expected_new in VECTORS:
        for coefficient, expected in zip((20, 21, 32, 48), expected_old):
            before = execute(primary, kernel, width, old_height, coefficient,
                             initialize_from_settings=initialize_from_settings)
            after = execute(primary, kernel, width, new_height, coefficient,
                            initialize_from_settings=initialize_from_settings)
            if before["estimated_bytes"] != expected or after["estimated_bytes"] != expected_new:
                raise AssertionError(f"fixed estimator vector failed: {size}/{coefficient}: {before}, {after}")
            if not before["matched_rows"] or before["fallback_executed"]:
                raise AssertionError("16:9 fixture did not use its row")
            if after["matched_rows"] or not after["fallback_executed"] or after["coefficient_divisor"] != [[32, 10]]:
                raise AssertionError("XPan fixture did not use default coefficients")
            cases.append({"size": size, "coefficient_fixture": coefficient,
                          "stock_dimensions": [width, old_height], "xpan_dimensions": [width, new_height],
                          "expected_stock": expected, "expected_xpan": expected_new,
                          "stock": before, "xpan": after,
                          "stock_estimate_at_least_xpan": before["estimated_bytes"] >= after["estimated_bytes"]})
    return {"scope": __doc__, "unicorn_version": unicorn.__version__,
            "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(), "cases": cases,
            "property_initialization_executed": initialize_from_settings, "runtime_coefficients_observed": False,
            "cache_reuse_safe_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--initialize-from-settings", action="store_true")
    parser.add_argument("--stock-defaults", action="store_true")
    args = parser.parse_args()
    images = load_images(args.update)
    report = (verify_stock_defaults(*images, load_defaults(args.update)) if args.stock_defaults else
              verify(*images, initialize_from_settings=args.initialize_from_settings))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} estimator comparisons passed; "
          f"stock defaults: {args.stock_defaults}; no live settings observation")


if __name__ == "__main__":
    main()
