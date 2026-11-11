"""Offline ARM checks for the guarded preview-size encode experiment."""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest

from tools.x100v_jpeg_crop import STUB_ADDRESS
from tools.x100v_preview_alias_candidate import read_elf_text


@pytest.fixture(scope="module")
def stub(tmp_path_factory):
    obj = tmp_path_factory.mktemp("xpan-preview-stub") / "stub.o"
    subprocess.run(
        ["clang", "--target=armv7a-none-eabi", "-c",
         "tools/x100v_jpeg_crop_block_preview_stub.s", "-o", str(obj)],
        check=True,
    )
    data = read_elf_text(obj)
    # Card 5f's EXIF stub begins at 0x0128fe00; this separate candidate must
    # stay entirely before it and in the original primary zero-padding region.
    assert len(data) <= 0x0128FE00 - STUB_ADDRESS
    return data


def run_stub(stub: bytes, width: int, height: int, aspect: int, selector: int):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    descriptor, frame, block, controls, stack, context = (
        0x30000000, 0x31001000, 0x32000000, 0x33000000, 0x34000000, 0x35000000
    )
    base = 0x40000000
    stride = width + 64
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_A15)
    uc.mem_map(STUB_ADDRESS & ~0xFFF, 0x1000)
    uc.mem_write(STUB_ADDRESS, stub)
    for page in (descriptor, frame - 0x1000, block, controls, stack, context):
        uc.mem_map(page, 0x2000)
    uc.mem_write(descriptor, struct.pack("<7I", 0, base, 0, stride, width, height, 0))
    uc.mem_write(frame - 0x44, struct.pack("<I", height))
    uc.mem_write(controls, bytes((0, selector)))
    uc.mem_write(context + 0x5BE, bytes((aspect,)))
    registers = {
        A.UC_ARM_REG_R0: 7, A.UC_ARM_REG_R1: base,
        A.UC_ARM_REG_R3: block, A.UC_ARM_REG_R4: 8,
        A.UC_ARM_REG_R5: context, A.UC_ARM_REG_R6: descriptor,
        A.UC_ARM_REG_R8: controls, A.UC_ARM_REG_FP: frame,
        A.UC_ARM_REG_SP: stack + 0x1000, A.UC_ARM_REG_LR: stack + 0x1800,
    }
    for reg, value in registers.items():
        uc.reg_write(reg, value)
    uc.emu_start(STUB_ADDRESS, stack + 0x1800, count=200)
    output = struct.unpack("<6I", uc.mem_read(block, 24))
    kept = (uc.reg_read(A.UC_ARM_REG_R0), uc.reg_read(A.UC_ARM_REG_R4),
            uc.reg_read(A.UC_ARM_REG_R5), uc.reg_read(A.UC_ARM_REG_R6),
            uc.reg_read(A.UC_ARM_REG_SP))
    assert kept == (7, 8, context, descriptor, stack + 0x1000)
    assert struct.unpack("<I", uc.mem_read(frame - 0x44, 4))[0] == height
    assert uc.mem_read(descriptor, 28) == struct.pack("<7I", 0, base, 0, stride, width, height, 0)
    return output[4], output[5], stride


@pytest.mark.parametrize(
    "width,height,aspect,selector,want_height,skip",
    [
        (8832, 2944, 2, 1, 1632, 656),  # guarded preview-size hypothesis
        (8832, 2944, 0, 1, 0, 0),     # ordinary 3:2 aspect must pass
        (8832, 2944, 2, 0, 0, 0),     # other selector must pass
        (8832, 2944, 2, 2, 0, 0),
        (8832, 2944, 4, 1, 0, 0),
        (8832, 2940, 2, 1, 0, 0),     # exact size guard
        (12480, 3512, 2, 0, 2304, 604),  # card-5f L case
        (8832, 2488, 2, 0, 1632, 428),   # card-5f M case
        (6240, 1760, 2, 0, 1152, 304),   # card-5f S case
    ],
)
def test_guarded_crop(stub, width, height, aspect, selector, want_height, skip):
    output_height, output_base, stride = run_stub(stub, width, height, aspect, selector)
    assert output_height == want_height
    assert output_base == 0x40000000 + skip * stride
