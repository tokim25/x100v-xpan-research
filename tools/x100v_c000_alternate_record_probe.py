"""Stock ARM selector/copy slices for the alternate C000 writer-gate route.

The slices are deliberately staged; they do not establish real event order or
that the copied external record belongs to a camera still exposure.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_c000_gate_probe import (
    RECORD, _arm, _word, builder_flag, converter_byte,
    initializer_calls_writer,
)

SOURCE = SOURCES["x100v_3_01"]
GLOBAL_BASE = 0x03420CB8
INDEX = GLOBAL_BASE + 0x1AB
FIRST = GLOBAL_BASE + 0x1AC
SECOND = FIRST + 0x274
COPY_SIZE = 0x271
ROOT_AEC = 0xEA


def helper_selects_first(stock: bytes, record_field_201: int) -> bool:
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP

    uc = _arm(stock, 0x01F6D2A8)
    uc.mem_map(0x34000000, 0x1000)
    uc.mem_write(RECORD + 0x201, struct.pack("<I", record_field_201))
    uc.reg_write(UC_ARM_REG_R0, RECORD)
    uc.reg_write(UC_ARM_REG_SP, 0x34000800)
    uc.emu_start(0x01F6D2A8, 0x01F6D2C8, count=15, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x01F6D2C8:
        raise AssertionError("selector helper missed return join")
    return uc.reg_read(UC_ARM_REG_R0) == 1


def selector_copy_plan(stock: bytes, record_field_201: int,
                       external_flag: int) -> dict:
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_R2, UC_ARM_REG_R4,
    )

    first = helper_selects_first(stock, record_field_201)
    start, end = ((0x01F05A74, 0x01F05A80) if first
                  else (0x01F05A8C, 0x01F05AA4))
    uc = _arm(stock, start)
    uc.mem_map(0x03420000, 0x2000)
    uc.mem_write(INDEX, b"\x7f")
    uc.mem_write(FIRST + 0x26D,
                 struct.pack("<I", builder_flag(stock, ROOT_AEC)))
    uc.mem_write(RECORD + 0x26D, struct.pack("<I", external_flag))
    uc.reg_write(UC_ARM_REG_R4, RECORD)
    uc.emu_start(start, end, count=15, timeout=1_000_000)
    if uc.reg_read(UC_ARM_REG_PC) != end:
        raise AssertionError("index/copy slice missed join")
    selected_index = uc.mem_read(INDEX, 1)[0]
    if selected_index != (0 if first else 1):
        raise AssertionError("unexpected selected index")
    copy = None
    if not first:
        copy = {
            "destination": uc.reg_read(UC_ARM_REG_R0),
            "source": uc.reg_read(UC_ARM_REG_R1),
            "length": uc.reg_read(UC_ARM_REG_R2),
        }
        if copy != {"destination": SECOND, "source": RECORD,
                    "length": COPY_SIZE}:
            raise AssertionError(f"unexpected copy call: {copy}")
        # Stage the observed memcpy arguments; the primary-partition BL itself
        # is not executed in this bounded secondary-partition slice.
        uc.mem_write(SECOND, bytes(uc.mem_read(RECORD, COPY_SIZE)))
    selected = FIRST + 0x274 * selected_index
    selected_flag = _word(uc, selected + 0x26D)
    byte = converter_byte(stock, selected_flag)
    return {
        "record_field_201": record_field_201,
        "external_flag_26d": external_flag,
        "selected_index": selected_index,
        "copy_call": copy,
        "selected_flag_26d": selected_flag,
        "converted_byte_1c": byte,
        "initializer_enters_writer_block": initializer_calls_writer(
            stock, ROOT_AEC, byte),
    }


def verify(stock: bytes) -> dict:
    digest = hashlib.sha256(stock).hexdigest()
    if digest != SOURCE["secondary_sha256"]:
        raise ValueError("unrecognized X100V 3.01 secondary partition")
    rows = [selector_copy_plan(stock, field, flag)
            for field, flag in ((1, 2), (2, 1), (2, 2))]
    return {
        "scope": "stock ARM selector/copy and gate local slices; synthetic staged memory only",
        "secondary_sha256": digest,
        "rows": rows,
        "camera_route_verified": False,
    }


def main() -> None:
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    print(json.dumps(verify(stock), indent=2))


if __name__ == "__main__":
    main()
