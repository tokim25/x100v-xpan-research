"""Offline ARM test of the proposed one-word 16:9 converter replacement.

This does not build a boot image. The caller's live input and relation to
ordinary still capture remain unknown.
"""
from __future__ import annotations

import hashlib
import struct

from tools.fuji_xpan_validation import SOURCES, decode_develop_aspect_jump_table, read_develop_aspect_case_outputs

LOAD = 0x01BA0000
ENTRY = 0x01F6E5AC
END = 0x01F6E630
TABLE = 0x01F6E5BC
CASE = 0x01F6E5EC
STOCK_WORD = 0xE3A03002
PATCHED_WORD = 0xE3A03004
OUTPUT = 0x10000000
RECORD = 0x10001000
STACK = 0x10003000
CONVERTER = 0x01F6E3C4
AFTER_ASPECT = 0x01F6E630


def candidate(stock: bytes) -> bytes:
    if hashlib.sha256(stock).hexdigest() != SOURCES["x100v_3_01"]["secondary_sha256"]:
        raise ValueError("unrecognized stock X100V secondary")
    if struct.unpack_from("<I", stock, CASE - LOAD)[0] != STOCK_WORD:
        raise ValueError("stock converter case differs")
    outputs = read_develop_aspect_case_outputs(stock, LOAD,
                                               {0x01F6E5E0: 1, CASE: 2, 0x01F6E5F8: 3})
    if decode_develop_aspect_jump_table(stock, TABLE - LOAD, 9, outputs) != [1, 2, 3] * 3:
        raise ValueError("stock jump table differs")
    changed = bytearray(stock)
    struct.pack_into("<I", changed, CASE - LOAD, PATCHED_WORD)
    return bytes(changed)


def execute(image: bytes, value: int) -> tuple[int, list[int]]:
    """Run only the in-range dispatch and byte store on synthetic memory."""
    if not 1 <= value <= 9:
        raise ValueError("only bounded in-range values 1..9")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R1, UC_ARM_REG_R4

    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    page = ENTRY & ~4095
    machine.mem_map(page, 4096)
    machine.mem_write(page, image[page-LOAD:page-LOAD+4096])
    machine.mem_map(OUTPUT, 4096)
    machine.mem_write(OUTPUT, b"\xcc" * 16)
    machine.reg_write(UC_ARM_REG_R1, value)
    machine.reg_write(UC_ARM_REG_R4, OUTPUT)
    visited: list[int] = []

    def instruction(_, address, size, __):
        if not (ENTRY <= address < END):
            raise AssertionError(f"dispatch escaped at {address:#x}")
        visited.append(address)

    def write(_, access, address, size, value, __):
        if (address, size) != (OUTPUT + 2, 1):
            raise AssertionError(f"unexpected memory write at {address:#x}")

    machine.hook_add(UC_HOOK_CODE, instruction)
    machine.hook_add(UC_HOOK_MEM_WRITE, write)
    machine.emu_start(ENTRY, END, count=20, timeout=1_000_000)
    if machine.reg_read(UC_ARM_REG_PC) != END:
        raise AssertionError("dispatch did not reach continuation")
    result = bytes(machine.mem_read(OUTPUT, 16))
    if result[:2] != b"\xcc\xcc" or result[3:] != b"\xcc" * 13:
        raise AssertionError("output guard changed")
    return result[2], visited


def execute_converter_aspect(image: bytes, value: int, mode: int) -> tuple[bytes, list[int]]:
    """Run the stock converter from entry through aspect output, not later fields.

    The synthetic record uses the builder's observed type 7 and subtype 2.
    This does not establish an ordinary-still caller or a live record value.
    """
    if not 1 <= value <= 9 or mode not in (0, 1):
        raise ValueError("bounded input 1..9 and converter mode 0 or 1 required")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (
        UC_ARM_REG_FP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP,
    )

    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    page = CONVERTER & ~4095
    machine.mem_map(page, 4096)
    machine.mem_write(page, image[page-LOAD:page-LOAD+4096])
    machine.mem_map(OUTPUT, 4096)
    machine.mem_map(RECORD, 4096)
    machine.mem_map(STACK, 4096)
    machine.mem_write(OUTPUT, b"\xcc" * 16)
    machine.mem_write(RECORD + 0x205, struct.pack("<III", 7, value, 2))
    machine.reg_write(UC_ARM_REG_R0, RECORD)
    machine.reg_write(UC_ARM_REG_R1, mode)
    machine.reg_write(UC_ARM_REG_R2, OUTPUT)
    machine.reg_write(UC_ARM_REG_SP, STACK + 0x800)
    machine.reg_write(UC_ARM_REG_FP, STACK + 0x800)
    machine.reg_write(UC_ARM_REG_LR, AFTER_ASPECT)
    visited: list[int] = []

    def instruction(_, address, size, __):
        if not (CONVERTER <= address < AFTER_ASPECT):
            raise AssertionError(f"converter escaped before aspect at {address:#x}")
        visited.append(address)

    def write(_, access, address, size, value, __):
        if not (OUTPUT <= address < OUTPUT + 3 or STACK <= address < STACK + 4096):
            raise AssertionError(f"unexpected converter write at {address:#x}")

    machine.hook_add(UC_HOOK_CODE, instruction)
    machine.hook_add(UC_HOOK_MEM_WRITE, write)
    machine.emu_start(CONVERTER, AFTER_ASPECT, count=100, timeout=1_000_000)
    if machine.reg_read(UC_ARM_REG_PC) != AFTER_ASPECT:
        raise AssertionError("converter did not reach post-aspect continuation")
    result = bytes(machine.mem_read(OUTPUT, 16))
    if result[3:] != b"\xcc" * 13:
        raise AssertionError("output guard changed")
    return result[:3], visited
