"""Offline ARM slices for command 0xd185 and its external-record pointer.

The command is a static dispatch label, not an identified live still event.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES

SOURCE = SOURCES["x100v_3_01"]
LOAD = SOURCE["secondary_load"]
COMMAND_HALFWORD = 0x0190F92C
RECORD_POINTER_SLOT = 0x017385EC
COMMAND_SOURCE_BASE = 0x017385D4
COMMAND_MODE_WORD = 0x01903DE0
TEST_RECORD = 0x33100000
DESTINATIONS = {
    0xD183: 0x01D6A2E4,
    0xD185: 0x01D6A2BC,
    0xD187: 0x01D6A35C,
}


def _machine(stock: bytes):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import UC_CPU_ARM_CORTEX_A15

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    for page in (0x01D5F000, 0x01D67000, 0x01D68000, 0x01D6A000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, stock[page - LOAD:page - LOAD + 0x1000])
    uc.mem_map(0x0190F000, 0x1000)
    uc.mem_map(0x01903000, 0x1000)
    uc.mem_map(0x01738000, 0x1000)
    return uc


def dispatch_destination(stock: bytes, command: int) -> int:
    from unicorn import UC_HOOK_CODE

    uc = _machine(stock)
    uc.mem_write(COMMAND_HALFWORD, struct.pack("<H", command))
    reached: list[int] = []

    def stop_at_case(engine, address, size, user_data):
        if address in DESTINATIONS.values():
            reached.append(address)
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop_at_case)
    uc.emu_start(0x01D67EC4, 0, count=80, timeout=1_000_000)
    if len(reached) != 1:
        raise AssertionError(f"command dispatch missed case: {reached}")
    return reached[0]


def selected_record_pointer(stock: bytes, pointer: int = TEST_RECORD) -> int:
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0

    uc = _machine(stock)
    uc.mem_write(RECORD_POINTER_SLOT, struct.pack("<I", pointer))
    uc.emu_start(0x01D6A2BC, 0x01D6A2C8, count=5, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x01D6A2C8:
        raise AssertionError("pointer-load slice missed wrapper call")
    return uc.reg_read(UC_ARM_REG_R0)


def source_command_for_mode(stock: bytes, mode: int) -> int:
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP

    uc = _machine(stock)
    uc.mem_map(0x34000000, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, 0x34000800)
    uc.mem_write(COMMAND_MODE_WORD, struct.pack("<I", mode))
    for offset, value in ((0xC, 0xD181), (0x10, 0xD185),
                          (0x14, 0xD187), (0x20, 0xD189)):
        uc.mem_write(COMMAND_SOURCE_BASE + offset, struct.pack("<I", value))
    uc.emu_start(0x01D5F4A0, 0x01D5F4F0, count=50, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x01D5F4F0:
        raise AssertionError("command-source slice missed join")
    return struct.unpack("<H", uc.mem_read(COMMAND_HALFWORD, 2))[0]


def verify(stock: bytes) -> dict:
    digest = hashlib.sha256(stock).hexdigest()
    if digest != SOURCE["secondary_sha256"]:
        raise ValueError("unrecognized X100V 3.01 secondary partition")
    return {
        "scope": "stock command-dispatch and pointer-load ARM slices; synthetic RAM",
        "secondary_sha256": digest,
        "command_cases": {hex(k): hex(dispatch_destination(stock, k))
                          for k in DESTINATIONS},
        "source_modes": {hex(mode): hex(source_command_for_mode(stock, mode))
                         for mode in range(0x8097, 0x809C)},
        "pointer_slot": hex(RECORD_POINTER_SLOT),
        "synthetic_pointer_passed_to_wrapper": hex(selected_record_pointer(stock)),
        "ordinary_still_command_verified": False,
    }


def main() -> None:
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    print(json.dumps(verify(stock), indent=2))


if __name__ == "__main__":
    main()
