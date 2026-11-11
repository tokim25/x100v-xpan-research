"""Run the real refresh caller through descriptor construction and gate/lookup.

Synthetic settings disable the diagnostic path, and helper +0x47 is zero.
Stop before recomputation, before its first count estimator, after the first
estimator return or row-0 cache store, before selected-count threshold
processing, before status publication, or after the local-buffer status write.
The 100-byte copy primitive is a host oracle. No complete refresh, callback,
export or camera I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES, verify_hashed_ranges
from tools.x100v_preview_cache_export_emulator import load_images, verify_images, CACHE, BASES
from tools.x100v_cache_descriptor_emulator import reference_descriptor
from tools.x100v_estimate_leaf_emulator import load_volume, verify_volume, verify_defaults
from tools.x100v_preview_alias_candidate import plan, STUB, DIM_STUB, STUB_SIZE
from tools.x100v_ratio_offline_candidate import apply_exact_partition_writes

ENTRY, RECOMPUTE, FIRST_COUNT, FIRST_COUNT_RETURN, FIRST_STORE_DONE, THRESHOLD, TRAP = (
    0x1EA3CFC, 0x115C758, 0x115C810, 0x115C814, 0x115C820, 0x115C040, 0x115D780)
PUBLISH, PUBLISH_DONE, COPY_ORACLE = 0x115BDD4, 0x115BF90, 0x00059128
MERGED_PRIMARY_SHA256 = "0cb9fb15e124205b6d7f745568f2f6373f3e3a4abb03a9b05c6e6cbf025b7e53"
ACTIVE, OBJECT, STACK, STOP = 0x10000000, 0x10001000, 0x20000000, 0x30000000
CONTEXT, SETTINGS, SHARED = 0x31000000, 0x32000000, 0x28787A0
GLOBAL, SCRATCH = CACHE-4, 0x16FA130


def expected_boundary(level: int, second: int, aspect: int, bypass: int,
                      scenario: str, patched: bool) -> tuple[int, int | None]:
    if (type(level) is not int or level not in (0, 1, 2)
            or type(second) is not int or second not in (0, 1)
            or type(aspect) is not int or aspect not in (2, 4)
            or type(bypass) is not int or bypass not in (0, 1, 2)
            or scenario not in ("missing", "clear", "recompute", "valid") or type(patched) is not bool):
        raise ValueError("outside refresh-caller fixture domain")
    if scenario in ("recompute", "valid"):
        if scenario == "valid" and bypass != 0:
            raise ValueError("valid-state fixture only covers bypass zero")
        return RECOMPUTE, None
    if aspect == 4 and not patched and bypass != 1:
        return TRAP, None
    # Independent index fixtures for the six original 16:9 rows.
    rows = ((6, 5), (14, 13), (22, 21))
    return THRESHOLD, 0 if bypass == 1 else rows[level][second]


def verify_candidate(stock: bytes, candidate: bytes, profile: str = "alias") -> None:
    offset = STUB-SOURCES["x100v_3_01"]["primary_load"]
    stub = candidate[offset:offset+STUB_SIZE]
    alias = apply_exact_partition_writes(stock, plan(stock, stub))
    if profile == "alias":
        if candidate != alias:
            raise ValueError("not the exact existing preview-alias experiment")
    elif profile == "merged":
        if hashlib.sha256(candidate).hexdigest() != MERGED_PRIMARY_SHA256:
            raise ValueError("not the exact audited offline merged primary")
        load = SOURCES["x100v_3_01"]["primary_load"]
        # The merged image has other code-4 writes, but this bounded route
        # must retain exactly the isolated alias's lookup hook, descriptor
        # prefix, alias stub, and original 57-key table.
        for address, size in ((0x115D6FC, 4), (0x115D9A0, 4),
                              (STUB, STUB_SIZE), (0x14A6230, 57 * 8)):
            pos = address - load
            if candidate[pos:pos+size] != alias[pos:pos+size]:
                raise ValueError(f"merged preview route differs at {address:#x}")
    else:
        raise ValueError("unknown candidate profile")


def execute(stock: bytes, secondary: bytes, volume: bytes, candidate: bytes, *,
            level: int, second: int, aspect: int, bypass: int,
            scenario: str, patched: bool, through_threshold: bool = False,
            through_publisher: bool = False,
            through_recompute_probe: bool = False,
            through_first_count_result: bool = False,
            through_first_count_store: bool = False,
            through_second_count_store: bool = False,
            settings_defaults: bytes | None = None,
            kernel: bytes | None = None,
            volume_free_bytes: int | None = None,
            candidate_profile: str = "alias") -> dict:
    verify_images(stock, secondary)
    verify_volume(volume)
    verify_candidate(stock, candidate, candidate_profile)
    expected_pc, expected_index = expected_boundary(level, second, aspect, bypass, scenario, patched)
    if any(type(value) is not bool for value in
           (through_threshold, through_publisher, through_recompute_probe,
            through_first_count_result, through_first_count_store,
            through_second_count_store)):
        raise ValueError("execution boundary flags must be boolean")
    if through_second_count_store and not through_first_count_store:
        raise ValueError("second count store requires first count store")
    if through_first_count_store and not through_first_count_result:
        raise ValueError("first count store requires first count result")
    if through_first_count_result and not through_recompute_probe:
        raise ValueError("first count result requires recompute probe")
    if through_first_count_result:
        if settings_defaults is None:
            raise ValueError("first count result requires pinned configuration defaults")
        verify_defaults(settings_defaults)
        if (kernel is None or len(kernel) != SOURCES["x100v_3_01"]["kernel_partition_size"]
                or hashlib.sha256(kernel).hexdigest() != SOURCES["x100v_3_01"]["kernel_partition_sha256"]):
            raise ValueError("first count result requires pinned stock kernel")
    elif settings_defaults is not None:
        raise ValueError("configuration defaults require first count result")
    elif kernel is not None:
        raise ValueError("stock kernel requires first count result")
    if volume_free_bytes is not None and (not through_first_count_result
            or type(volume_free_bytes) is not int or not 0 <= volume_free_bytes < 2**64):
        raise ValueError("volume free-byte oracle outside count fixture domain")
    if through_recompute_probe and scenario != "valid":
        raise ValueError("recompute probe requires valid service state")
    if through_recompute_probe and through_publisher:
        raise ValueError("recompute probe cannot run publisher path")
    if through_publisher and not through_threshold:
        raise ValueError("publisher requires threshold path")
    if through_publisher and scenario == "missing":
        raise ValueError("publisher path not bounded for missing service slot")
    if through_threshold and expected_pc == THRESHOLD:
        expected_pc = PUBLISH_DONE if through_publisher else PUBLISH
    if through_recompute_probe and expected_pc == RECOMPUTE:
        expected_pc = (FIRST_STORE_DONE if through_first_count_store else
                       FIRST_COUNT_RETURN if through_first_count_result else FIRST_COUNT)
    source = SOURCES["x100v_3_01"]
    for kind, data in (("primary", stock), ("secondary", secondary)):
        verify_hashed_ranges(data, source[f"{kind}_load"], source[f"preview_refresh_caller_{kind}_ranges"])
    if through_threshold:
        verify_hashed_ranges(stock, source["primary_load"], source["preview_count_threshold_ranges"])
        verify_hashed_ranges(stock, source["primary_load"], source["preview_count_filter_ranges"])
    primary = candidate if patched else stock
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3, UC_ARM_REG_R5, UC_ARM_REG_R9, UC_ARM_REG_SP,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC,
                                   UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_C1_C0_2,
                                   UC_ARM_REG_FPEXC, UC_ARM_REG_FPSCR)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    if through_first_count_result:
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        uc.reg_write(UC_ARM_REG_C1_C0_2, 0xF << 20)
        uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        uc.reg_write(UC_ARM_REG_FPSCR, 0)
    for data, base, pages in (
        (primary, source["primary_load"], (0x1127000, 0x112F000, 0x113A000, 0x1140000, 0x1159000,
         0x115B000, 0x115C000, 0x115D000, 0x1166000, 0x1167000,
         0x1168000, 0x1169000, 0x128F000, 0x1290000, 0x14A5000,
         0x14A6000, 0x1519000)),
        (secondary, source["secondary_load"], (0x1EA0000, 0x1EA3000, 0x1F68000)),
        (volume, source["volume_partition_load"], (0xD20000, 0xD26000, 0xD27000,
                                                   0xD34000)),
    ):
        if data is volume and through_recompute_probe:
            uc.mem_map(0xD20000, 0x2C000)
            uc.mem_write(base, data)
            continue
        for page in pages:
            uc.mem_map(page, 4096)
            start = max(page, base)
            uc.mem_write(start, data[start-base:page+4096-base])
    for page in (ACTIVE, OBJECT, STACK, SHARED & ~4095, BASES[0] & ~4095,
                 SCRATCH & ~4095, 0x159E000, 0x191E000, 0xD89000):
        uc.mem_map(page, 4096)
    if kernel is not None:
        uc.mem_map(0x5A000, 4096)
        uc.mem_write(0x5A000, kernel[0x1A000:0x1B000])
    uc.mem_map(GLOBAL & ~4095, 0x4000)
    uc.mem_map(CONTEXT, 0x17000)
    uc.mem_map(SETTINGS, len(settings_defaults) if settings_defaults is not None else 0x10000)
    if settings_defaults is not None:
        uc.mem_write(SETTINGS, settings_defaults)
    uc.mem_write(STACK, b"\xa5"*4096)
    active = bytearray(0x600)
    active[0x6B], active[0x6D], active[0x70], active[0x71] = level, second, aspect, bypass
    uc.mem_write(ACTIVE, bytes(active))
    uc.mem_write(OBJECT+0x5C, b"\x01")
    uc.mem_write(SHARED+0x738, struct.pack("<III", OBJECT, ACTIVE, BASES[0]))
    uc.mem_write(0x159EDB4, struct.pack("<I", SETTINGS))
    if through_recompute_probe:
        uc.mem_write(0x191E9E8, struct.pack("<H", 100))
    # Getter of key 0x5e82 returns zero: original diagnostic predicate returns false.
    uc.mem_write(0xD89A20, struct.pack("<I", CONTEXT))
    uc.mem_write(CONTEXT+0x16B6C, struct.pack("<I", 1 if scenario == "clear" else 0))
    uc.mem_write(CONTEXT+0x16BEC, b"\x01")
    if through_first_count_result:
        uc.mem_write(CONTEXT+0x16B80, struct.pack("<I", 16384))
    uc.mem_write(0x1851BB4, struct.pack("<I", 0xFFFFFFFF if scenario == "missing" else 0))
    uc.mem_write(0x18509B0, struct.pack("<I", source["volume_partition_load"]))
    original_cache = struct.pack("<57I", *range(100, 157))
    uc.mem_write(CACHE, original_cache)
    uc.mem_write(BASES[0], b"\xa5"*240)
    uc.mem_write(SCRATCH-4, b"\xa5"*236)
    uc.mem_write(GLOBAL+0x22A4, struct.pack("<I", 0xA5A5A5A5))
    if through_publisher or through_first_count_result:
        uc.mem_map(COPY_ORACLE & ~4095, 4096)
    if through_publisher:
        uc.mem_write(0x16FA214, b"\x01")
        uc.mem_write(0x16FA228, bytes(100))
    scratch_before = bytes(uc.mem_read(SCRATCH-4, 236))
    sp = STACK+0xF00
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    allowed = ((ENTRY, 0x1EA3D3C), (0x1F68898, 0x1F688B4),
               (0x1EA063C, 0x1EA0758), (0x1EA0774, 0x1EA07DC),
               (0x1159270, 0x1159290), (0x1166E68, 0x1166EAC),
               (0x112771C, 0x1127750), (0x1127848, 0x1127868),
               (0x115D028, 0x115D068), (0x115C5B8, 0x115C758),
               (0x115B780, 0x115B7F4), (0x115B8C4, 0x115B97C),
               (0x113A894, 0x113A940), (0xD2703C, 0xD2715C),
               (0x115D6FC, 0x115D78C), (STUB, STUB+0x28))
    if through_threshold:
        allowed += ((THRESHOLD, 0x115C138), (0x115BFE4, THRESHOLD), (0x115B6F8, 0x115B73C))
    if through_publisher:
        allowed += ((PUBLISH, 0x115BFE4), (0x115D65C, 0x115D6B0),
                    (0x115D6B0, 0x115D6FC), (0x1168B24, 0x1168B34),
                    (0x1167960, 0x1167990), (0x1168A50, 0x1168B24),
                    (0xD26000, 0xD28000))
    if through_recompute_probe:
        allowed += ((RECOMPUTE, FIRST_COUNT), (0x115C830, 0x115C84C),
                    (0x115BD54, PUBLISH),
                    (0x115B698, 0x115B780), (0x115B9D0, 0x115BAC4),
                    (0x1168000, 0x1169000),
                    (0x113AE48, 0x113AEC0), (0x1140808, 0x11409D4),
                    (0x112FD64, 0x112FD90), (0x112FE1C, 0x112FE48),
                    (0x115D870, 0x115DB80), (DIM_STUB, STUB+STUB_SIZE),
                    (source["volume_partition_load"],
                     source["volume_partition_load"] + len(volume)))
    if through_first_count_result:
        allowed += ((FIRST_COUNT,
                     0x115C82C if through_second_count_store else
                     0x115C820 if through_first_count_store else 0x115C814),
                    (0x11672EC, 0x11675F4),
                    (0x116792C, 0x1167A4C),
                    (0x11678DC, 0x116790C), (0x1167A50, 0x1167A8C),
                    (0x1167A90, 0x1167FBC), (0x1167FBC, 0x1168024),
                    (0x1168514, 0x11686F4), (0x1169624, 0x1169744),
                    (0x1169000, 0x1169028),
                    (0x1140A00, 0x1140A28), (0x5AD28, 0x5AF34))
    visited, writes, observations = [], [], {}

    def instruction(machine, address, size, _):
        if address == 0x113A8E8 and volume_free_bytes is not None:
            volume_id, request, dest = (machine.reg_read(r) for r in
                                        (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if request in (5, 6):
                if volume_id != 0x41 or not STACK <= dest <= STACK+4096-4:
                    raise AssertionError("free-byte service oracle argument mismatch")
                value = (volume_free_bytes >> (32 if request == 6 else 0)) & 0xFFFFFFFF
                machine.mem_write(dest, struct.pack("<I", value))
                observations.setdefault("free_byte_oracle_calls", []).append((request, dest, value))
                machine.reg_write(UC_ARM_REG_R0, 0)
                machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
                return
        if (through_publisher or through_first_count_result) and address == COPY_ORACLE:
            dest, src, count = (machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if through_publisher:
                if count != 100 or not ((src == 0x16FA228 and STACK <= dest < STACK+4096) or
                                        (dest == 0x16FA228 and STACK <= src < STACK+4096)):
                    raise AssertionError("status record copy argument mismatch")
                observations.setdefault("copy_calls", []).append((dest, src, count))
            else:
                if src not in (0x1290644, 0x1290694, 0x12906e4) or count != 80 or not STACK <= dest <= STACK+4096-count:
                    raise AssertionError("first count table copy argument mismatch")
                observations.setdefault("first_count_copy_calls", []).append((dest, src, count))
            machine.mem_write(dest, bytes(machine.mem_read(src, count)))
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
            return
        if address == FIRST_COUNT and through_recompute_probe:
            count_entry = dict(
                registers=[machine.reg_read(r) for r in
                           (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)],
                row_index=machine.reg_read(UC_ARM_REG_R9),
                stack_arg=struct.unpack("<I", machine.mem_read(machine.reg_read(UC_ARM_REG_SP), 4))[0],
                descriptor_hex=bytes(machine.mem_read(machine.reg_read(UC_ARM_REG_R1), 0x30)).hex(),
            )
            observations.setdefault("count_entries", []).append(count_entry)
            observations.setdefault("first_count", count_entry)
        if through_first_count_result and address in (0x116854C, 0x1168570,
                                                       0x11685A4, 0x1168674,
                                                       0x1168678, 0x1168578):
            observations[hex(address)] = [machine.reg_read(r) for r in
                                          (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                           UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if through_first_count_result and address == FIRST_COUNT_RETURN:
            count_return = machine.reg_read(UC_ARM_REG_R0)
            count_cap = machine.reg_read(UC_ARM_REG_R5)
            observations.setdefault("count_returns", []).append((count_return, count_cap))
            observations.setdefault("first_count_return", count_return)
            observations.setdefault("first_count_cap", count_cap)
        if address in (expected_pc, TRAP):
            if (address == FIRST_STORE_DONE and through_second_count_store
                    and machine.reg_read(UC_ARM_REG_R9) == 0):
                pass
            else:
                machine.emu_stop()
                return
        if not any(a <= address < b for a, b in allowed):
            raise RuntimeError(f"unexpected caller instruction {address:#x}")
        visited.append(address)
        if address == PUBLISH:
            observations["publisher_entry_arguments"] = [machine.reg_read(r) for r in
                                                          (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        if address == 0x115C718:
            observations["threshold_return"] = machine.reg_read(UC_ARM_REG_R0)
        if through_publisher and address in (0x115BE10, 0x115BE74, 0x115BEE0):
            observations[hex(address)] = machine.reg_read(UC_ARM_REG_R0)
        if address in (0x115D028, 0x115C5B8):
            desc = bytes(machine.mem_read(machine.reg_read(UC_ARM_REG_R0), 36))
            if desc != reference_descriptor(bytes(active)):
                raise AssertionError("original caller descriptor differs")
            observations[hex(address)] = dict(descriptor_hex=desc.hex(),
                r1=machine.reg_read(UC_ARM_REG_R1), r2=machine.reg_read(UC_ARM_REG_R2),
                r3=machine.reg_read(UC_ARM_REG_R3),
                stack_word=struct.unpack("<I", machine.mem_read(machine.reg_read(UC_ARM_REG_SP), 4))[0])

    def write(machine, access, address, size, value, _):
        if STACK <= address and address+size <= STACK+4096:
            return
        targets = ((GLOBAL, GLOBAL+1), (CACHE, CACHE+228),
                   (GLOBAL+0x22A0, GLOBAL+0x22A1), (GLOBAL+0x22A4, GLOBAL+0x22A8))
        if through_first_count_result:
            if address == 0x16FA360 and size == 1 and value == 1:
                observations["coefficient_flag_write"] = True
                return
            if (0x1519744 <= address < 0x1519744 + 132*16 and size == 1
                    and (address - 0x1519744) % 16 == 7):
                observations.setdefault("coefficient_writes", []).append((address, value))
                return
        if through_publisher:
            targets += ((0x16FA228, 0x16FA228+100),)
        if not any(a <= address and address+size <= b for a, b in targets):
            raise RuntimeError(f"unexpected caller write {address:#x}/{size}")
        writes.append((address, size, value))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    try:
        uc.emu_start(ENTRY, STOP,
                     count=50000 if through_first_count_result else 6000,
                     timeout=10000000 if through_first_count_result else 1000000)
    except Exception as error:
        raise RuntimeError(f"refresh-caller ARM halted at {uc.reg_read(UC_ARM_REG_PC):#x}; "
                           f"last instructions={[hex(address) for address in visited[-8:]]}; "
                           f"r0-r3={[hex(uc.reg_read(r)) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]}") from error
    pc = uc.reg_read(UC_ARM_REG_PC)
    if pc != expected_pc:
        raise AssertionError(f"wrong boundary {pc:#x} expected {expected_pc:#x}")
    selected = struct.unpack("<I", uc.mem_read(GLOBAL+0x22A4, 4))[0]
    if selected != (0xA5A5A5A5 if expected_index is None else expected_index):
        raise AssertionError(f"selected cache index {selected:#x} differs from {expected_index}; "
                             f"{level}/{second}/{aspect}/{bypass}/{scenario}/patched={patched}")
    expected_cache = original_cache if scenario in ("recompute", "valid") else bytes(228)
    if through_first_count_store:
        expected_row0 = min(observations["first_count_return"], observations["first_count_cap"])
        expected_cache = struct.pack("<I", expected_row0) + expected_cache[4:]
        if through_second_count_store:
            row1_result, row1_cap = observations["count_returns"][1]
            expected_cache = expected_cache[:4] + struct.pack("<I", min(row1_result, row1_cap)) + expected_cache[8:]
    if bytes(uc.mem_read(CACHE, 228)) != expected_cache:
        raise AssertionError("cache clear/preserve differs")
    if bytes(uc.mem_read(BASES[0], 240)) != b"\xa5"*240 or bytes(uc.mem_read(SCRATCH-4, 236)) != scratch_before:
        raise AssertionError("an export unexpectedly occurred")
    if bytes(uc.mem_read(ACTIVE, 0x600)) != active or bytes(uc.mem_read(GLOBAL, 1)) != b"\x01":
        raise AssertionError("active state or enable flag differs")
    wrapper, constructor = observations["0x115d028"], observations["0x115c5b8"]
    if (wrapper["r1"], wrapper["r2"], wrapper["r3"]) != (1, BASES[0]+8, 0x1F04BBC):
        raise AssertionError("wrapper arguments differ")
    if (constructor["r1"], constructor["r2"], constructor["r3"], constructor["stack_word"]) != (1, SCRATCH, 0, 0):
        raise AssertionError("constructor arguments differ")
    if writes[0] != (GLOBAL, 1, 1):
        raise AssertionError("enable flag was not the first non-stack write")
    publisher_arguments = None
    if pc in (PUBLISH, PUBLISH_DONE):
        publisher_arguments = (observations.get("publisher_entry_arguments") if pc == PUBLISH_DONE else
                               [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)])
        if observations.get("threshold_return") != 1 or publisher_arguments != [0, 0, 0]:
            raise AssertionError("threshold result or count-publication arguments differ")
        if pc == PUBLISH and uc.reg_read(UC_ARM_REG_SP) != sp-264:
            raise AssertionError("threshold call did not restore its stack")
    published_status = None
    if pc == PUBLISH_DONE:
        published_status = bytes(uc.mem_read(0x16FA228+0x40, 1))[0]
        if len(observations.get("copy_calls", [])) != 2:
            raise AssertionError("publisher did not use local read/write copy calls")
        if published_status != 2:
            raise AssertionError("clear-state publisher did not preserve status 2")
    first_count = observations.get("first_count")
    if pc in (FIRST_COUNT, FIRST_COUNT_RETURN, FIRST_STORE_DONE):
        if (first_count["registers"][0] != 0x41 or first_count["registers"][2:] != [0, 0]
                or first_count["row_index"] != 0 or first_count["stack_arg"] != 0):
            raise AssertionError("first-row count arguments differ")
    return dict(level=level, second=second, aspect=aspect, bypass=bypass, scenario=scenario,
                patched=patched, stop_pc=hex(pc), selected_index=expected_index,
                alias_stub_executed=STUB in visited,
                dimension_stub_executed=DIM_STUB in visited,
                observations=observations,
                instructions=len(visited), cache_write_bytes=sum(n for a,n,_ in writes if CACHE <= a < CACHE+228),
                threshold_executed=THRESHOLD in visited, publisher_arguments=publisher_arguments,
                publisher_executed=pc == PUBLISH_DONE, published_status=published_status,
                first_count=first_count,
                first_count_result=observations.get("first_count_return"),
                first_count_stored=(struct.unpack("<I", uc.mem_read(CACHE, 4))[0]
                                    if pc == FIRST_STORE_DONE else None),
                second_count_stored=(struct.unpack("<I", uc.mem_read(CACHE+4, 4))[0]
                                     if pc == FIRST_STORE_DONE and through_second_count_store else None),
                count_entries=observations.get("count_entries", []),
                count_returns=observations.get("count_returns", []),
                volume_free_bytes_oracle=volume_free_bytes,
                recompute_setup_executed=pc in (FIRST_COUNT, FIRST_COUNT_RETURN, FIRST_STORE_DONE),
                full_return=False,
                recomputation_executed=pc in (FIRST_COUNT_RETURN, FIRST_STORE_DONE),
                export_executed=False)


def verify(stock: bytes, secondary: bytes, volume: bytes, candidate: bytes,
           through_threshold: bool = False, candidate_profile: str = "alias") -> dict:
    import unicorn
    cases = [execute(stock, secondary, volume, candidate, level=l, second=s, aspect=a,
                     bypass=b, scenario=sc, patched=p, through_threshold=through_threshold,
                     candidate_profile=candidate_profile)
             for l in range(3) for s in range(2) for a in (2, 4) for b in (0, 1, 2)
             for sc in ("missing", "clear", "recompute") for p in (False, True)]
    return dict(scope=__doc__, cases=cases, unicorn_version=unicorn.__version__,
                through_threshold=through_threshold,
                candidate_profile=candidate_profile,
                stock_sha256=hashlib.sha256(stock).hexdigest(),
                candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                secondary_sha256=hashlib.sha256(secondary).hexdigest(),
                volume_sha256=hashlib.sha256(volume).hexdigest(),
                firmware_files_modified=False, hardware_verified=False, callee_stubs=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--through-threshold", action="store_true")
    args = parser.parse_args()
    report = verify(*load_images(args.update), load_volume(args.update), args.candidate.read_bytes(), args.through_threshold)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} refresh-caller boundary cases passed")


if __name__ == "__main__":
    main()
