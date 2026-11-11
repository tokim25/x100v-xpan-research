"""Execute the stock event-to-group-1-mode wrapper with synthetic RAM.

Helper calls are intercepted; this proves argument/mode routing only. It does
not execute the group-1 FSM or establish live capture message delivery.
"""

from __future__ import annotations

import hashlib
import struct

from tools.fuji_xpan_validation import SOURCES


def run_vectors(secondary: bytes) -> list[dict[str, int]]:
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_R2, UC_ARM_REG_SP,
    )

    source = SOURCES["x100v_3_01"]
    if hashlib.sha256(secondary).hexdigest() != source["secondary_sha256"]:
        raise ValueError("stock secondary identity mismatch")
    base = source["secondary_load"]
    code = 0x01F29000
    entry = 0x01F29734
    stop = 0x38000000
    stack = 0x39000000
    controller_record = 0x034CAD70
    mode_halfword = 0x027E9D0A
    rows = []

    for message_id, event in ((0x123A, 0), (0x11A2, 0),
                              (0x1239, 0), (0, 5), (0, 10)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(code, 0x2000)
        uc.mem_write(code, secondary[code - base:code - base + 0x2000])
        uc.mem_map(0x034CA000, 0x1000)
        uc.mem_map(0x03421000, 0x2000)
        uc.mem_map(0x027E9000, 0x1000)
        uc.mem_map(stop, 0x1000)
        uc.mem_map(stack, 0x2000)
        uc.mem_write(controller_record, struct.pack("<H", message_id))
        dispatches = []

        def intercept(engine, address, size, _):
            if address in (0x01F29204, 0x01F29238):
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))
            elif address == 0x01F2AD08:
                dispatches.append((engine.reg_read(UC_ARM_REG_R0),
                                   engine.reg_read(UC_ARM_REG_R1),
                                   engine.reg_read(UC_ARM_REG_R2),
                                   struct.unpack("<H", engine.mem_read(mode_halfword, 2))[0]))
                engine.reg_write(UC_ARM_REG_R0, 0)
                engine.reg_write(UC_ARM_REG_PC, engine.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, intercept)
        slot = 7
        uc.reg_write(UC_ARM_REG_R0, slot)
        uc.reg_write(UC_ARM_REG_R1, event)
        uc.reg_write(UC_ARM_REG_SP, stack + 0x1000)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(entry, stop, count=3000)
        if uc.reg_read(UC_ARM_REG_PC) != stop or len(dispatches) != 1:
            raise AssertionError("stock event wrapper did not dispatch once")
        group, actual_slot, actual_event, mode = dispatches[0]
        gate = struct.unpack("<H", uc.mem_read(0x03421358, 2))[0]
        rows.append({"message_id": message_id, "event": event,
                     "group": group, "slot": actual_slot,
                     "forwarded_event": actual_event, "mode": mode,
                     "gate_halfword": gate})
    return rows
