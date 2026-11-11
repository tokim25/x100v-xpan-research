"""Execute stock ARM status-record copy helpers with bounded synthetic memory.

The 100-byte copy primitive and callback body are explicit host oracles. This
tests helper routing and arguments, not a full preview-status publication.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


PRIMARY_SHA256 = "3be0132c4bb17aa7504aaaf7e6d85d037368d21f49463ea0ce1ae37a764f6c87"
PRIMARY_LOAD = 0x00F21000
READ_HELPER, WRITE_HELPER = 0x0115D65C, 0x0115D6B0
FLAG, CALLBACK_READ, CALLBACK_WRITE, RECORDS = 0x016FA214, 0x016FA21C, 0x016FA218, 0x016FA228
COPY_ORACLE, CALLBACK_ORACLE, STOP = 0x00059128, 0x30000000, 0x30001000
HOST, STACK = 0x10000000, 0x20000000
RECORD_SIZE = 100


def verify_primary(primary: bytes) -> None:
    if hashlib.sha256(primary).hexdigest() != PRIMARY_SHA256:
        raise ValueError("unrecognized X100V stock primary")


def reference_record(slot: int) -> int:
    if type(slot) is not int or not 0 <= slot < 8:
        raise ValueError("slot outside bounded fixture")
    return RECORDS + slot * RECORD_SIZE


def execute(primary: bytes, *, read: bool, local: bool, slot: int) -> dict:
    verify_primary(primary)
    if type(read) is not bool or type(local) is not bool:
        raise ValueError("read/local must be boolean")
    record = reference_record(slot)
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP)

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    for page in (0x0115D000, 0x016FA000, COPY_ORACLE & ~4095, CALLBACK_ORACLE, STOP, HOST, STACK):
        uc.mem_map(page, 4096)
    start = 0x0115D000 - PRIMARY_LOAD
    uc.mem_write(0x0115D000, primary[start:start+4096])
    uc.mem_write(FLAG, bytes((1 if local else 0,)))
    uc.mem_write(CALLBACK_READ, struct.pack("<I", CALLBACK_ORACLE))
    uc.mem_write(CALLBACK_WRITE, struct.pack("<I", CALLBACK_ORACLE))
    bank = bytes((0xA5,)) * 800
    payload = bytes(((index * 37 + slot * 11) & 0xFF) for index in range(RECORD_SIZE))
    uc.mem_write(RECORDS, bank)
    uc.mem_write(HOST, bytes((0x5A,)) * RECORD_SIZE)
    if read:
        uc.mem_write(record, payload)
    else:
        uc.mem_write(HOST, payload)
    before_bank = bytes(uc.mem_read(RECORDS, 800))
    before_host = bytes(uc.mem_read(HOST, RECORD_SIZE))
    uc.reg_write(UC_ARM_REG_R0, slot)
    uc.reg_write(UC_ARM_REG_R1, HOST)
    uc.reg_write(UC_ARM_REG_SP, STACK+0xF00)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    entry = READ_HELPER if read else WRITE_HELPER
    calls: list[dict] = []
    visited: list[int] = []

    def instruction(machine, address, size, _):
        if address in (COPY_ORACLE, CALLBACK_ORACLE):
            r0, r1, r2 = (machine.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if address == COPY_ORACLE:
                dst, src, count = r0, r1, r2
                if (dst, src, count) != ((HOST, record, RECORD_SIZE) if read else
                                         (record, HOST, RECORD_SIZE)):
                    raise AssertionError("stock helper passed unexpected copy arguments")
            else:
                if (r0, r1) != (slot, HOST):
                    raise AssertionError("stock helper passed unexpected callback arguments")
                dst, src, count = ((HOST, record, RECORD_SIZE) if read else
                                   (record, HOST, RECORD_SIZE))
            machine.mem_write(dst, bytes(machine.mem_read(src, count)))
            calls.append(dict(kind="copy" if address == COPY_ORACLE else "callback",
                              r0=r0, r1=r1, r2=r2, bytes=count))
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
            return
        if not entry <= address < (READ_HELPER+0x54 if read else WRITE_HELPER+0x4C):
            raise AssertionError(f"unexpected helper instruction {address:#x}")
        visited.append(address)

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.emu_start(entry, STOP, count=100, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP or len(calls) != 1:
        raise AssertionError("helper did not return after one copy route")
    after_bank = bytes(uc.mem_read(RECORDS, 800))
    after_host = bytes(uc.mem_read(HOST, RECORD_SIZE))
    expected_bank = (before_bank if read else
                     before_bank[:slot*RECORD_SIZE] + payload + before_bank[(slot+1)*RECORD_SIZE:])
    expected_host = payload if read else before_host
    if after_bank != expected_bank or after_host != expected_host:
        raise AssertionError("copy route changed unexpected bytes or missed payload")
    return dict(read=read, local=local, slot=slot, instructions=len(visited),
                route=calls[0], exact_100_byte_copy=True, returned=True,
                original_callback_body_executed=False, full_publisher_executed=False)


def verify(primary: bytes) -> dict:
    cases = [execute(primary, read=read, local=local, slot=slot)
             for read in (False, True) for local in (False, True) for slot in (0, 1, 7)]
    return dict(scope=__doc__, primary_sha256=PRIMARY_SHA256, cases=cases,
                camera_executed=False, firmware_modified=False)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("primary", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.primary.read_bytes())
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} status-record helper cases passed")


if __name__ == "__main__":
    main()
