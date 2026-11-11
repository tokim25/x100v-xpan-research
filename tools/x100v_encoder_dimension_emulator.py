"""Execute the stock dimension setter with a RAM stand-in for one register.

This observes ARM instruction writes, not JPEG encoding, hardware acceptance,
MMU configuration, live camera I/O, or capture-path reachability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_firmware_probe import HEADER_SIZE
from tools.fuji_xpan_validation import SOURCES, decode_partition, read_raw_partition

ENTRY, END = 0x010B239C, 0x010B23EC
ACCESSOR, ACCESSOR_END = 0x0005AA18, 0x0005AA30
INPUT, STACK, STOP = 0x10000000, 0x20000000, 0x30000000
REGISTER = 0xFFFA0044
SENTINEL = 0xA5A5A5A5


def load_images(update: Path) -> tuple[bytes, bytes]:
    source = SOURCES["x100v_3_01"]
    data = update.read_bytes()
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("unrecognized X100V update")
    payload = bytes(byte ^ 255 for byte in data[HEADER_SIZE:])
    primary = decode_partition(payload, source["primary_header"])
    kernel = read_raw_partition(payload, source["kernel_partition_offset"], source["kernel_partition_size"])
    verify_images(primary, kernel)
    return primary, kernel


def verify_images(primary: bytes, kernel: bytes) -> None:
    source = SOURCES["x100v_3_01"]
    for name, image in (("primary", primary), ("kernel_partition", kernel)):
        if hashlib.sha256(image).hexdigest() != source[f"{name}_sha256"]:
            raise ValueError(f"unrecognized {name}")


def execute(primary: bytes, kernel: bytes, width: int, height: int) -> dict:
    verify_images(primary, kernel)
    if not all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in (width, height)):
        raise ValueError("input outside unsigned 32-bit domain")
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    ranges = ((ENTRY, END), (ACCESSOR, ACCESSOR_END))
    source = SOURCES["x100v_3_01"]
    for image, load, (start, end) in (
        (primary, source["primary_load"], ranges[0]),
        (kernel, source["kernel_partition_load"], ranges[1]),
    ):
        uc.mem_map(start & ~4095, 4096)
        uc.mem_write(start, image[start - load:end - load])
    for page in (INPUT, STACK, REGISTER & ~4095):
        uc.mem_map(page, 4096)
    uc.mem_write(INPUT, struct.pack("<II", height, width))
    uc.mem_write(REGISTER, struct.pack("<I", SENTINEL))
    visited, writes = [], []

    def instruction(machine, address, size, _):
        if not any(start <= address < end for start, end in ranges):
            raise RuntimeError(f"execution escaped dimension setter: {address:#x}")
        visited.append(address)

    def write(machine, access, address, size, value, _):
        if address == REGISTER and size == 4:
            writes.append(value)
        elif not STACK <= address <= STACK + 4096 - size:
            raise RuntimeError(f"unexpected setter write: {address:#x}")

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    for reg, value in ((UC_ARM_REG_R0, INPUT), (UC_ARM_REG_SP, STACK + 0xF00), (UC_ARM_REG_LR, STOP)):
        uc.reg_write(reg, value)
    uc.emu_start(ENTRY, STOP, count=100, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise RuntimeError("dimension setter did not return within limit")
    return {"return_u32": uc.reg_read(UC_ARM_REG_R0), "register_writes": writes,
            "register_value": struct.unpack("<I", uc.mem_read(REGISTER, 4))[0],
            "instructions": len(visited), "accessor_executed": ACCESSOR in visited}


def verify(primary: bytes, kernel: bytes) -> dict:
    import unicorn
    # Literal packed words are independent of firmware and helper arithmetic.
    vectors = [
        ("L_candidate", 6240, 2304, 0, 0x09001860),
        ("M_helper", 4416, 1628, 0, 0x065C1140),
        ("M_table", 4416, 1632, 0, 0x06601140),
        ("S_candidate", 3120, 1152, 0, 0x04800C30),
        ("odd_dimensions_not_rejected_here", 4417, 1629, 0, 0x065D1141),
        ("zero_not_rejected_here", 0, 0, 0, 0),
        ("largest_fields", 65535, 65535, 0, 0xFFFFFFFF),
        ("height_overflow", 4416, 65536, 0xFFFFFFE2, None),
        ("width_overflow", 65536, 1628, 0xFFFFFFE2, None),
    ]
    cases = []
    for name, width, height, status, word in vectors:
        result = execute(primary, kernel, width, height)
        expected_writes = [] if word is None else [word]
        if (result["return_u32"] != status or result["register_writes"] != expected_writes
                or result["register_value"] != (SENTINEL if word is None else word)
                or result["accessor_executed"] != (word is not None)):
            raise AssertionError(f"dimension setter vector failed: {name}: {result}")
        cases.append({"name": name, "input_width_height": [width, height],
                      "expected_status_u32": status, "expected_packed_word": word, **result})
    return {"scope": "stock dimension setter plus direct store; simulated register RAM only",
            "unicorn_version": unicorn.__version__,
            "update_sha256": SOURCES["x100v_3_01"]["sha256"],
            "primary_sha256": hashlib.sha256(primary).hexdigest(),
            "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
            "entry": hex(ENTRY), "simulated_register": hex(REGISTER), "cases": cases,
            "encoder_acceptance_verified": False, "saved_jpeg_dimensions_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify(*load_images(args.update))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"{len(report['cases'])} stock dimension-setter ARM fixtures passed; no camera or encoder execution")


if __name__ == "__main__":
    main()
