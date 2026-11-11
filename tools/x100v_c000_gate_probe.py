"""Offline original-ARM check of the C000 writer's builder/converter gate.

Each slice uses pinned stock bytes and synthetic RAM. This does not prove that
the camera executes the slices in sequence or that +0xaec stays unchanged.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES

SOURCE = SOURCES["x100v_3_01"]
LOAD = SOURCE["secondary_load"]
ROOT = 0x33000000
RECORD = 0x33100000
OUTPUT = 0x33200000


def _arm(stock: bytes, start: int):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn.arm_const import UC_CPU_ARM_CORTEX_A15

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
    page = start & ~0xFFF
    uc.mem_map(page, 0x1000)
    uc.mem_write(page, stock[page - LOAD:page - LOAD + 0x1000])
    for address in (ROOT, RECORD, OUTPUT):
        uc.mem_map(address, 0x1000)
    return uc


def _word(uc, address: int) -> int:
    return struct.unpack("<I", uc.mem_read(address, 4))[0]


def builder_flag(stock: bytes, context_aec: int) -> int:
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R4, UC_ARM_REG_R5

    uc = _arm(stock, 0x01F6E2BC)
    uc.mem_write(ROOT + 0xAEC, struct.pack("<H", context_aec))
    uc.reg_write(UC_ARM_REG_R5, ROOT)
    uc.reg_write(UC_ARM_REG_R4, RECORD)
    uc.emu_start(0x01F6E2BC, 0x01F6E2FC, count=25, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x01F6E2FC:
        raise AssertionError("builder slice missed join")
    return _word(uc, RECORD + 0x26D)


def converter_byte(stock: bytes, source_flag: int) -> int:
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R4, UC_ARM_REG_R5

    uc = _arm(stock, 0x01F7055C)
    uc.mem_write(RECORD + 0x26D, struct.pack("<I", source_flag))
    uc.mem_write(OUTPUT + 0x1C, b"\x7f")
    uc.reg_write(UC_ARM_REG_R5, RECORD)
    uc.reg_write(UC_ARM_REG_R4, OUTPUT)
    uc.emu_start(0x01F7055C, 0x01F70640, count=30, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x01F70640:
        raise AssertionError("converter slice missed join")
    return uc.mem_read(OUTPUT + 0x1C, 1)[0]


def initializer_calls_writer(stock: bytes, context_aec: int, record_byte: int) -> bool:
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5

    uc = _arm(stock, 0x01F6B494)
    uc.mem_write(ROOT + 0xAEC, struct.pack("<H", context_aec))
    uc.mem_write(OUTPUT + 0x1C, bytes([record_byte]))
    uc.reg_write(UC_ARM_REG_R4, ROOT)
    uc.reg_write(UC_ARM_REG_R5, OUTPUT)
    reached: list[int] = []

    def stop_at_join(engine, address, size, user_data):
        if address in (0x01F6BA28, 0x01F6B4B8):
            reached.append(address)
            engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, stop_at_join)
    uc.emu_start(0x01F6B494, 0, count=20, timeout=1_000_000)
    if len(reached) != 1:
        raise AssertionError(f"initializer gate missed join: {reached}")
    # 0x01f6ba28 is the block containing BL 0x01ed6b78 at 0x01f6ba50.
    return reached[0] == 0x01F6BA28


def verify(stock: bytes) -> dict:
    digest = hashlib.sha256(stock).hexdigest()
    if digest != SOURCE["secondary_sha256"]:
        raise ValueError("unrecognized X100V 3.01 secondary partition")
    rows = []
    for builder_aec, initializer_aec in (
        (0, 0), (0xEA, 0xEA), (0x186, 0x186),
        (0, 0xEA), (0x186, 0),
    ):
        flag = builder_flag(stock, builder_aec)
        byte = converter_byte(stock, flag)
        calls = initializer_calls_writer(stock, initializer_aec, byte)
        rows.append({
            "builder_aec": builder_aec,
            "initializer_aec": initializer_aec,
            "source_record_26d": flag,
            "converted_record_1c": byte,
            "initializer_enters_writer_block": calls,
        })
    return {
        "scope": "three stock ARM local slices; synthetic RAM; no camera execution",
        "secondary_sha256": digest,
        "rows": rows,
    }


def main() -> None:
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    print(json.dumps(verify(stock), indent=2))


if __name__ == "__main__":
    main()
