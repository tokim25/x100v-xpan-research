"""Bounded original-ARM controls for the nested mode-0 message classifier.

The downstream mode matrix and callbacks are not executed here.
"""

from __future__ import annotations

import hashlib
import struct

from tools.fuji_xpan_validation import SOURCES


def run_vectors(secondary: bytes) -> list[dict[str, int]]:
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    base = source["secondary_load"]
    stop, stack = 0x38000000, 0x39000000
    rows = []
    for message_id in (0x123A, 0x1151, 0x1232, 0x11B9):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for code, size in ((0x01F05000, 0x2000), (0x01F29000, 0x1000)):
            uc.mem_map(code, size)
            uc.mem_write(code, secondary[code - base:code - base + size])
        uc.mem_map(0x034CA000, 0x1000)
        uc.mem_map(0x028C0000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x1000)
        uc.mem_write(0x034CAD70, struct.pack("<H", message_id))
        dispatches = []

        def intercept(engine, address, size, _):
            if address in (0x01F29204, 0x01F29238):
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))
            elif address == 0x01F294A0:
                dispatches.append((
                    engine.reg_read(UC_ARM_REG_R0),
                    struct.unpack("<I", engine.mem_read(0x028C0F8C, 4))[0],
                ))
                engine.reg_write(UC_ARM_REG_R0, 0)
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(0x01F05C08, stop, count=500)
        if uc.reg_read(UC_ARM_REG_PC) != stop or len(dispatches) != 1:
            raise AssertionError("nested mode-0 classifier did not dispatch once")
        action, row = dispatches[0]
        rows.append({"message_id": message_id, "action": action, "row": row})
    return rows


def run_followup_vectors(secondary: bytes) -> list[dict[str, int]]:
    """Execute mode-1 and mode-3 classifiers, intercepting their matrix calls."""
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    base = source["secondary_load"]
    stop, stack = 0x38000000, 0x39000000
    rows = []
    cases = ((1, 0x01F05FF0, 0x028C0F8E, (0x123A, 0x1159, 0x1232)),
             (3, 0x01F06614, 0x028C0F92, (0x123A, 0x115E, 0x11A9, 0x9240)))
    for mode, entry, row_address, message_ids in cases:
        for message_id in message_ids:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            for code, size in ((0x01F05000, 0x3000), (0x01F29000, 0x1000)):
                uc.mem_map(code, size)
                uc.mem_write(code, secondary[code - base:code - base + size])
            uc.mem_map(0x034CA000, 0x1000)
            uc.mem_map(0x028C0000, 0x1000)
            uc.mem_map(stop, 0x1000)
            uc.mem_map(stack, 0x1000)
            uc.mem_write(0x034CAD70, struct.pack("<H", message_id))
            dispatches = []

            def intercept(engine, address, size, _):
                if address in (0x01F29204, 0x01F29238):
                    engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))
                elif address == 0x01F294A0:
                    dispatches.append((
                        engine.reg_read(UC_ARM_REG_R0),
                        struct.unpack("<H", engine.mem_read(row_address, 2))[0],
                    ))
                    engine.reg_write(UC_ARM_REG_R0, 0)
                    engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

            uc.hook_add(UC_HOOK_CODE, intercept)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
            uc.reg_write(UC_ARM_REG_LR, stop)
            uc.emu_start(entry, stop, count=500)
            if uc.reg_read(UC_ARM_REG_PC) != stop or len(dispatches) != 1:
                raise AssertionError("nested follow-up classifier did not dispatch once")
            actual_mode, row = dispatches[0]
            rows.append({"message_id": message_id, "mode": actual_mode,
                         "row": row})
    return rows


def run_mode0_row18_matrix_vectors(secondary: bytes) -> list[dict[str, int]]:
    """Execute the stock mode-0 matrix with synthetic row/column RAM.

    Each selected callback is intercepted at entry. This isolates matrix
    selection, post-callback lookup, and its direct column effect; it says
    nothing about what an actual callback subsequently does.
    """
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    base = source["secondary_load"]
    stop, stack = 0x38000000, 0x39000000
    callbacks = (0x01F07794, 0x01F077D8, 0x01F077F8,
                 0x01F07820, 0x01F07928)
    rows = []
    for column in range(5):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for code, size in ((0x01F07000, 0x1000),
                           (0x01F29000, 0x1000),
                           (0x022D7000, 0x1000)):
            uc.mem_map(code, size)
            uc.mem_write(code, secondary[code - base:code - base + size])
        uc.mem_map(0x028C0000, 0x1000)
        uc.mem_map(0x02886000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x1000)
        uc.mem_write(0x028C0F8C, struct.pack("<H", 18))
        uc.mem_write(0x028867F0, struct.pack("<H", column))
        selected = []

        def intercept(engine, address, size, _):
            if address in callbacks:
                selected.append(address)
                engine.reg_write(UC_ARM_REG_R0, 1)
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_R1, 0)
        uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(0x01F294A0, stop, count=300)
        if uc.reg_read(UC_ARM_REG_PC) != stop or len(selected) != 1:
            raise AssertionError("mode-0 matrix did not select one callback")
        after = struct.unpack("<H", uc.mem_read(0x028867F0, 2))[0]
        rows.append({"column": column, "callback": selected[0],
                     "column_after_matrix_only": after})
    return rows


def run_callback_column_vectors(secondary: bytes) -> list[dict[str, int]]:
    """Isolate mode-0 callbacks 15 and 19 with stubbed nested returns.

    The deliberately out-of-range initial column 0x55 is a write sentinel,
    not a claimed live state. No nested controller or downstream helper runs.
    """
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    base = source["secondary_load"]
    stop, stack = 0x38000000, 0x39000000
    rows = []
    for callback, nested, nested_result in (
        (0x01F07794, 0x01F05FF0, 0),
        (0x01F07794, 0x01F05FF0, 1),
        (0x01F07928, 0x01F06614, 0),
        (0x01F07928, 0x01F06614, 1),
    ):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for code in (0x01F05000, 0x01F06000, 0x01F07000,
                     0x01F0E000, 0x01F26000):
            uc.mem_map(code, 0x1000)
            uc.mem_write(code, secondary[code - base:code - base + 0x1000])
        uc.mem_map(0x02886000, 0x1000)
        uc.mem_map(0x034CA000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x1000)
        uc.mem_write(0x028867F0, struct.pack("<H", 0x55))
        called = []

        def intercept(engine, address, size, _):
            if address in (0x01F05FF0, 0x01F06614,
                           0x01F260AC, 0x01F0E5C0, 0x01F0ED1C):
                called.append(address)
                engine.reg_write(UC_ARM_REG_R0,
                                 nested_result if address == nested else 0)
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, intercept)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(callback, stop, count=200)
        if uc.reg_read(UC_ARM_REG_PC) != stop or not called or called[0] != nested:
            raise AssertionError("row-18 callback did not reach its nested controller")
        column = struct.unpack("<H", uc.mem_read(0x028867F0, 2))[0]
        rows.append({"callback": callback, "nested_result": nested_result,
                     "column_after_callback": column,
                     "helper_calls": len(called) - 1})
    return rows
