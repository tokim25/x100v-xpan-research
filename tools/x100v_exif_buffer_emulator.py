"""Execute one stock X100V A32 helper with synthetic RAM, without camera I/O.

The overlay mapping is independently cataloged by FujiMod revision
130dabad704a4cbdb0440b91b0d40637dbc3f55d, x100v-301 recovery recipe.
This is a function harness, not a camera or firmware boot emulator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

UPDATE_SHA256 = "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591"
OVERLAY_DAT_OFFSET = 0xA00274
OVERLAY_SIZE = 0xA00000
OVERLAY_LOAD = 0x03720000
OVERLAY_SHA256 = "cb8770127a28edff2474ce8f05d7ccb39a33a39e02801a2449182fb5843855b3"
ENTRY = 0x03DAC578
END = 0x03DAC6C8
SOURCE = 0x02ED1778
DEST = 0x10000000
STACK = 0x20000000
STOP = 0x30000000


def load_overlay(update: Path) -> bytes:
    data = update.read_bytes()
    if hashlib.sha256(data).hexdigest() != UPDATE_SHA256:
        raise ValueError("X100V update identity mismatch")
    overlay = bytes(b ^ 255 for b in data[OVERLAY_DAT_OFFSET:OVERLAY_DAT_OFFSET + OVERLAY_SIZE])
    if hashlib.sha256(overlay).hexdigest() != OVERLAY_SHA256:
        raise ValueError("X100V raw overlay identity mismatch")
    return overlay


def execute_helper(overlay: bytes, words: dict[int, int]) -> dict:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

    if hashlib.sha256(overlay).hexdigest() != OVERLAY_SHA256:
        raise ValueError("unrecognized overlay")
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(ENTRY & ~0xFFF, 0x1000)
    uc.mem_write(ENTRY, overlay[ENTRY - OVERLAY_LOAD:END - OVERLAY_LOAD])
    uc.mem_map(SOURCE & ~0xFFF, 0x14000)
    uc.mem_map(DEST, 0x1000)
    uc.mem_map(STACK, 0x1000)
    uc.mem_write(DEST, bytes([0xCC]) * 0x100)
    for offset, value in words.items():
        if not 0 <= offset <= 0x1268C or offset % 4 or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("fixture word outside input structure")
        uc.mem_write(SOURCE + offset, struct.pack("<I", value))
    count = 0
    writes = []

    def instruction(machine, address, size, _):
        nonlocal count
        count += 1
        if not ENTRY <= address < END:
            raise RuntimeError(f"execution escaped helper at {address:#x}")

    def write(machine, access, address, size, value, _):
        if not (DEST <= address and address + size <= DEST + 0x8C or
                STACK <= address and address + size <= STACK + 0x1000):
            raise RuntimeError(f"unexpected write at {address:#x}")
        if DEST <= address < DEST + 0x1000:
            writes.append([address - DEST, size, value])

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.reg_write(UC_ARM_REG_R0, DEST)
    uc.reg_write(UC_ARM_REG_R1, SOURCE)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xF00)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    uc.emu_start(ENTRY, STOP, count=1000, timeout=1000000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise RuntimeError("helper did not return within execution limit")
    output = bytes(uc.mem_read(DEST, 0x8C))
    return {
        "instructions": count,
        "pairs": [list(struct.unpack_from("<II", output, 8 + 8 * i)) for i in range(16)],
        "trailer": struct.unpack_from("<I", output, 0x88)[0],
        "prefix_preserved": output[:8] == bytes([0xCC]) * 8,
        "writes": writes,
    }


def verify_vectors(overlay: bytes) -> dict:
    import unicorn
    # Explicit expected outputs are independent of the A32 instructions.
    vectors = [
        ("all_components", {0: 0x41000000, 8: 101, 0x130: 0x42000000, 0x138: 202,
                            0x37C: 0x43000000, 0x380: 303, 0x390: 1,
                            0x250: 0x44000000, 0x258: 404, 0x20: 0x45000000, 0x28: 505},
         [[0x41000000, 101], [0x42000000, 202], [0x43000000, 303], [0x44000000, 404], [0x45000000, 505], [0, 0]]),
        ("omit_optional", {0: 0x41000000, 8: 101, 0x250: 0x44000000, 0x258: 404,
                           0x20: 0x45000000, 0x28: 505},
         [[0x41000000, 101], [0x45000000, 505], [0, 0]]),
        ("skip_incomplete_components", {0: 0x41000000, 0x138: 202, 0x20: 0x45000000, 0x28: 505},
         [[0x45000000, 505], [0, 0]]),
        ("empty", {}, [[0, 0], [0, 0]]),
        ("alternate_six_length_sum", {0x12650: 1, 0x12660: 0x46000000,
                                       0x12678: 1, 0x1267C: 2, 0x12680: 4,
                                       0x12684: 8, 0x12688: 16, 0x1268C: 32},
         [[0x46000000, 63], [0, 0]]),
    ]
    results = []
    for name, words, expected in vectors:
        result = execute_helper(overlay, words)
        if result["pairs"][:len(expected)] != expected or result["trailer"] != 0 or not result["prefix_preserved"]:
            raise AssertionError(f"firmware helper fixture failed: {name}")
        results.append({"name": name, "expected_pairs": expected, **result})
    return {"scope": "stock A32 helper with synthetic RAM only; no camera, MMIO, capture, or boot",
            "unicorn_version": unicorn.__version__,
            "update_sha256": UPDATE_SHA256, "overlay_sha256": OVERLAY_SHA256,
            "entry": hex(ENTRY), "cases": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("update", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify_vectors(load_overlay(args.update))
    if args.report:
        with args.report.open("x") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    print(f"{len(report['cases'])} stock ARM helper fixtures passed")


if __name__ == "__main__":
    main()
