"""Build/test an isolated preview alias experiment, never a flashable update.

All 57 original key rows are retained. Six code-4 keys reuse code-2 indices
and receive separate dimensions. Reusing associated runtime cache values is
UNVERIFIED: this experiment is not integrated into the core candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import (
    SOURCES, encode_arm_unconditional_b, read_preview_key_table,
    scan_aligned_arm_cave_references,
)
from tools.x100v_ratio_arm_emulator import load_stock
from tools.x100v_ratio_offline_candidate import apply_exact_partition_writes

LOAD = 0x00F21000
LOOKUP = 0x0115D6FC
DESCRIPTOR = 0x0115D964
DIM_HOOK, DIM_STOP = 0x0115D9A0, 0x0115D9BC
STUB, DIM_STUB, STUB_SIZE = 0x0128FB20, 0x0128FB60, 168
STUB_SHA256 = "1a6174f66ea407029cb3e59a520bf2dc09cfe44eed9f1a7701c63edfd726bfa1"
INPUT, OUTPUT, STACK, STOP = 0x10000000, 0x10001000, 0x20000000, 0x30000000


def read_elf_text(path: Path) -> bytes:
    """Extract one relocation-free .text section from a bounded ELF32 ARM object."""
    data = path.read_bytes()
    if (len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01"
            or struct.unpack_from("<HH", data, 16) != (1, 40)):
        raise ValueError("expected little-endian ELF32 ARM relocatable object")
    shoff = struct.unpack_from("<I", data, 32)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 46)
    if size != 40 or not 0 <= names_index < count or shoff + count * size > len(data):
        raise ValueError("invalid ELF section table")
    sections = [struct.unpack_from("<10I", data, shoff + i * size) for i in range(count)]

    def contents(section):
        start, length = section[4:6]
        if start + length > len(data):
            raise ValueError("ELF section outside file")
        return data[start:start + length]

    names = contents(sections[names_index])
    matches = [(i, s) for i, s in enumerate(sections)
               if s[0] < len(names) and names[s[0]:].split(b"\0", 1)[0] == b".text"]
    if len(matches) != 1 or matches[0][1][1] != 1:
        raise ValueError("expected one PROGBITS .text section")
    index, section = matches[0]
    if any(s[1] in (4, 9) and s[7] == index and s[5] for s in sections):
        raise ValueError("unresolved .text relocations")
    return contents(section)


def plan(stock: bytes, stub: bytes) -> list[dict]:
    if hashlib.sha256(stock).hexdigest() != SOURCES["x100v_3_01"]["primary_sha256"]:
        raise ValueError("unrecognized stock primary")
    if len(stub) != STUB_SIZE or hashlib.sha256(stub).hexdigest() != STUB_SHA256:
        raise ValueError("unrecognized assembled preview stub")
    writes = []
    for name, address, before, after in (
        ("lookup-entry", LOOKUP, struct.pack("<I", 0xE3500001),
         struct.pack("<I", encode_arm_unconditional_b(LOOKUP, STUB))),
        ("dimension-entry", DIM_HOOK, struct.pack("<I", 0xE3063230),
         struct.pack("<I", encode_arm_unconditional_b(DIM_HOOK, DIM_STUB))),
        ("preview-alias-stubs", STUB, bytes(STUB_SIZE), stub),
    ):
        offset = address - LOAD
        if stock[offset:offset + len(before)] != before:
            raise ValueError(f"original bytes differ: {name}")
        writes.append({"field": name, "address": address, "partition_offset": offset,
                       "before_hex": before.hex(), "after_hex": after.hex()})
    return writes


def execute(image: bytes, key: tuple[int, int, int], bypass: int = 0,
            descriptor: bool = False, kind: int = 0) -> dict:
    """Run only lookup or descriptor dimension-prefix instructions on synthetic RAM."""
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R11,
        UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

    if len(key) != 3 or any(type(x) is not int or not 0 <= x <= 255 for x in (*key, bypass, kind)):
        raise ValueError("invalid fixture bytes")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    # This block includes the type-29 special branch but stops before all
    # subsequent descriptor-processing logic. It is not a full preview emulator.
    ranges = ((LOOKUP, 0x0115D78C), (DESCRIPTOR, 0x0115DAA0),
              (STUB, STUB + 0x28), (DIM_STUB, STUB + 0x94))
    for page in (0x0115D000, STUB & ~4095, 0x014A6000):
        uc.mem_map(page, 4096)
        uc.mem_write(page, image[page - LOAD:page - LOAD + 4096])
    for page in (INPUT, OUTPUT, STACK):
        uc.mem_map(page, 4096)
    record = bytearray(36)
    record[0], record[2], record[4], record[5], record[6] = kind, bypass, key[1], key[0], key[2]
    uc.mem_write(INPUT, bytes(record))
    uc.mem_write(OUTPUT, b"\xcc" * 64)
    visited = []

    def instruction(machine, address, size, _):
        if address == 0x0115D780:
            raise RuntimeError("lookup wrapper entered miss loop")
        if not any(start <= address < end for start, end in ranges):
            raise RuntimeError(f"preview execution escaped: {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if not (STACK <= address <= STACK + 4096 - size or
                descriptor and OUTPUT + 2 <= address <= OUTPUT + 6 - size):
            raise RuntimeError(f"unexpected preview write: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    saved = {UC_ARM_REG_R4: 0x44444444, UC_ARM_REG_R5: 0x55555555, UC_ARM_REG_R11: 0xBBBBBBBB}
    for reg, value in saved.items():
        uc.reg_write(reg, value)
    values = ((UC_ARM_REG_R0, INPUT), (UC_ARM_REG_R1, OUTPUT)) if descriptor else (
        (UC_ARM_REG_R0, bypass), (UC_ARM_REG_R1, key[0]),
        (UC_ARM_REG_R2, key[1]), (UC_ARM_REG_R3, key[2]))
    for reg, value in (*values, (UC_ARM_REG_SP, STACK + 0xF00), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    end = DIM_STOP if descriptor else STOP
    uc.emu_start(DESCRIPTOR if descriptor else LOOKUP, end, count=2000, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != end:
        raise RuntimeError("preview helper did not finish within limit")
    if not descriptor and (uc.reg_read(UC_ARM_REG_SP) != STACK + 0xF00
                           or any(uc.reg_read(reg) != value for reg, value in saved.items())):
        raise RuntimeError("lookup violated callee-saved state")
    return {"row_index": uc.reg_read(UC_ARM_REG_R0) if not descriptor else None,
            "output_hex": bytes(uc.mem_read(OUTPUT, 64)).hex() if descriptor else None,
            "dimensions": list(struct.unpack("<HH", uc.mem_read(OUTPUT + 2, 4))) if descriptor else None,
            "instructions": len(visited), "alias_stub_visited": STUB in visited,
            "dimension_stub_visited": DIM_STUB in visited}


def verify(stock: bytes, patched: bytes, stub: bytes) -> dict:
    import unicorn
    if patched != apply_exact_partition_writes(stock, plan(stock, stub)):
        raise ValueError("candidate differs from exact preview experiment")
    source = SOURCES["x100v_3_01"]
    unchanged_regions = {
        "all_57_key_rows": (source["preview_key_table"], 57 * 8),
        "local_cache_constructor_and_bounds": (0x0115C600, 0x500),
        "ratio_stub_reserved_extent": (0x0128FB14, 12),
    }
    for name, (address, size) in unchanged_regions.items():
        offset = address - LOAD
        if stock[offset:offset + size] != patched[offset:offset + size]:
            raise AssertionError(f"preview experiment changed {name}")
    rows = read_preview_key_table(stock, LOAD, source["preview_key_table"], 57)
    old_cases = 0
    for row in rows:
        for bypass in (0, 1, 2):
            key = tuple(row["key"])
            before, after = execute(stock, key, bypass), execute(patched, key, bypass)
            expected_index = 0 if bypass == 1 else row["index"]
            if before["row_index"] != expected_index or after["row_index"] != expected_index:
                raise AssertionError(f"old key changed: {key}/{bypass}")
            a = execute(stock, key, bypass, descriptor=True)
            b = execute(patched, key, bypass, descriptor=True)
            expected_dims = [0, 0] if bypass == 1 else [row["width"], row["height"]]
            if a["output_hex"] != b["output_hex"] or b["dimensions"] != expected_dims:
                raise AssertionError(f"old descriptor changed: {key}/{bypass}")
            old_cases += 1
    cases = []
    for level, second, index, dims in (
        (0, 1, 5, [6240, 2304]), (0, 0, 6, [6240, 2304]),
        (1, 1, 13, [4416, 1632]), (1, 0, 14, [4416, 1632]),
        (2, 1, 21, [3120, 1152]), (2, 0, 22, [3120, 1152]),
    ):
        key = (level, second, 4)
        if execute(stock, key)["row_index"] != 57:
            raise AssertionError("stock code-4 miss control changed")
        for bypass in (0, 1, 2):
            lookup = execute(patched, key, bypass)
            result = execute(patched, key, bypass, descriptor=True)
            if (lookup["row_index"] != (0 if bypass == 1 else index)
                    or result["dimensions"] != ([0, 0] if bypass == 1 else dims)):
                raise AssertionError(f"new code-4 vector failed: {key}/{bypass}")
            cases.append({"key": list(key), "bypass": bypass, "lookup": lookup, "descriptor_prefix": result})
        special = execute(patched, key, descriptor=True, kind=29)
        if special["dimensions"] != [6400, 2160] or special["dimension_stub_visited"]:
            raise AssertionError("type-29 override changed")
    negatives = [(3, 1, 4), (7, 0, 4), (255, 0, 4), (0, 2, 4), (0, 255, 4), (0, 1, 5)]
    for key in negatives:
        if execute(stock, key)["row_index"] != 57 or execute(patched, key)["row_index"] != 57:
            raise AssertionError("out-of-scope key unexpectedly became valid")
    return {"scope": "isolated stock/candidate lookup and descriptor dimension-prefix; synthetic RAM only",
            "source_update_sha256": source["sha256"],
            "stock_primary_sha256": hashlib.sha256(stock).hexdigest(),
            "candidate_primary_sha256": hashlib.sha256(patched).hexdigest(),
            "stub_sha256": STUB_SHA256,
            "unchanged_regions": {name: {"address": hex(address), "size": size}
                                  for name, (address, size) in unchanged_regions.items()},
            "unicorn_version": unicorn.__version__, "existing_key_bypass_cases_preserved": old_cases,
            "new_code4_cases": cases, "type29_special_cases": 6,
            "unchanged_miss_cases": [list(k) for k in negatives],
            "runtime_cache_suitability_verified": False, "full_preview_behavior_verified": False,
            "camera_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("stub_object", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError("refusing existing experiment directory")
    stock, stub = load_stock(args.update, "x100v_3_01"), read_elf_text(args.stub_object)
    writes = plan(stock, stub)
    refs = scan_aligned_arm_cave_references(stock, LOAD, STUB, STUB + STUB_SIZE)
    if any(refs.values()):
        raise ValueError("stock primary has bounded references into stub extent")
    patched = apply_exact_partition_writes(stock, writes)
    report = verify(stock, patched, stub)
    manifest = {"kind": "isolated preview alias experiment; not core candidate", "flashable": False,
                "source_update_sha256": SOURCES["x100v_3_01"]["sha256"],
                "source_primary_sha256": hashlib.sha256(stock).hexdigest(),
                "candidate_primary_sha256": hashlib.sha256(patched).hexdigest(),
                "stub_sha256": STUB_SHA256, "writes": writes,
                "changed_byte_count": sum(a != b for a, b in zip(stock, patched)),
                "primary_only_aligned_literal_arm_branch_scan": refs,
                "old_key_table_unchanged": True, "cache_bounds_and_arrays_unchanged": True,
                "code4_cache_indices": [5, 6, 13, 14, 21, 22],
                "cache_values_are_original_code2_values": True,
                "cache_suitability_verified": False, "executable_mapping_verified": False,
                "saved_image_and_finder_verified": False,
                "remaining_gates": ["code-2 cache values suitable for code-4 or separate cache route",
                                    "runtime executable mapping and padding ownership",
                                    "full capture/finder paths and chosen geometry", "packaging and physical rollback"]}
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "primary-preview-alias-experimental.bin").write_bytes(patched)
    for filename, value in (("manifest.json", manifest), ("arm-fixtures.json", report)):
        (args.output_dir / filename).write_text(json.dumps(value, indent=2) + "\n")
    print(f"Preview experiment: {report['existing_key_bypass_cases_preserved']} old-key/bypass cases preserved; "
          f"{len(report['new_code4_cases'])} new cases; 6 type-29 and 6 miss controls passed")
    print(f"{manifest['changed_byte_count']} changed bytes; cache suitability UNVERIFIED; not flashable")


if __name__ == "__main__":
    main()
