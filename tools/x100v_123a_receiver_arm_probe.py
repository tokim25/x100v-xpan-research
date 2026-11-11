"""Execute stock packet-ID filter and controller-record copy with synthetic RAM.

The queue sender/receiver and handler scheduling are not executed here.
"""

from __future__ import annotations

import hashlib
import struct

from tools.fuji_xpan_validation import SOURCES


def run_vectors(secondary: bytes) -> list[dict[str, int]]:
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    load = source["secondary_load"]
    code = 0x01F27000
    packet = 0x35000000
    record = 0x034CAD70
    stop = 0x38000000
    stack = 0x39000000
    rows = []

    for message_id in (0x123A, 0x11A2):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(code, 0x3000)
        uc.mem_write(code, secondary[code - load:code - load + 0x3000])
        uc.mem_map(0x034CA000, 0x1000)
        uc.mem_map(packet, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x1000)
        # Eight-byte packet header; payload length zero avoids any copy helper.
        uc.mem_write(packet, struct.pack("<HBBI", message_id, 0x5A, 0xA5, 0))

        def call(entry):
            uc.reg_write(UC_ARM_REG_R0, packet)
            uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
            uc.reg_write(UC_ARM_REG_LR, stop)
            uc.emu_start(entry, stop, count=100)
            if uc.reg_read(UC_ARM_REG_PC) != stop:
                raise AssertionError(f"stock ARM {entry:#x} did not return")
            return uc.reg_read(UC_ARM_REG_R0)

        accepted = call(0x01F293B8)
        copied = call(0x01F27F68)
        actual_id, flag0, flag1, length = struct.unpack(
            "<HBBI", uc.mem_read(record, 8))
        rows.append({"message_id": message_id, "prefilter_result": accepted,
                     "copy_result": copied, "record_id": actual_id,
                     "record_byte2": flag0, "record_byte3": flag1,
                     "record_length": length})
    return rows


def run_gate_vectors(secondary: bytes) -> list[dict[str, int]]:
    """Isolate the 0x123a callback's byte write and the key-4 gate read.

    A one-entry synthetic slot list skips the callback's slot loop. The
    callback's unrelated final notification is intercepted; no message
    scheduling or key-4 send is executed.
    """
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    load = source["secondary_load"]
    stop, stack = 0x38000000, 0x39000000
    gate_address = 0x03421358
    rows = []
    for before in (0x0101, 0x0001, 0x0201, 0x0100):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for code in (0x01ED3000, 0x01F25000, 0x01F30000):
            uc.mem_map(code, 0x1000)
            uc.mem_write(code, secondary[code - load:code - load + 0x1000])
        uc.mem_map(0x0341C000, 0x2000)
        uc.mem_map(0x03421000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x1000)
        uc.mem_write(0x0341CCB8 + 0x4B4, struct.pack("<I", 1))
        uc.mem_write(gate_address, struct.pack("<H", before))

        def intercept(engine, address, size, _):
            if address == 0x01ED3020:
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, intercept)

        def call(entry):
            uc.reg_write(UC_ARM_REG_R0, 7)
            uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
            uc.reg_write(UC_ARM_REG_LR, stop)
            uc.emu_start(entry, stop, count=300)
            if uc.reg_read(UC_ARM_REG_PC) != stop:
                raise AssertionError(f"stock ARM {entry:#x} did not return")
            return uc.reg_read(UC_ARM_REG_R0)

        call(0x01F30694)
        after = struct.unpack("<H", uc.mem_read(gate_address, 2))[0]
        enabled = call(0x01F253FC)
        rows.append({"before": before, "after_callback": after,
                     "gate_result": enabled})
    return rows
