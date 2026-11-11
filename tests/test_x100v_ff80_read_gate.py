"""Stock FF80 memory-read route and parameter-F7 gate, offline only."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def image(number):
    data = Path(f"out/fw-cache/x100v-301-part{number}.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    key = "primary_sha256" if number == 6 else "secondary_sha256"
    load = source["primary_load"] if number == 6 else source["secondary_load"]
    assert hashlib.sha256(data).hexdigest() == source[key]
    return data, load


def word(data, load, address):
    return struct.unpack_from("<I", data, address - load)[0]


def test_ff80_mode2_routes_to_f7_gated_copy():
    secondary, base7 = image(7)
    primary, base6 = image(6)
    assert branch_target(word(secondary, base7, 0x01DFF628), 0x01DFF628) == 0x010538E4
    assert branch_target(word(primary, base6, 0x010538FC), 0x010538FC) == 0x01127848
    assert word(primary, base6, 0x010538F8) == 0xE3A000F7  # mov r0,#0xf7
    assert branch_target(word(primary, base6, 0x01053904), 0x01053904) == 0x01053938
    assert word(primary, base6, 0x01053938) == 0xE3A00002  # error 2


def test_original_arm_copy_is_refused_with_f7_clear_and_succeeds_when_set():
    """Synthetic parameter return and RAM; not a camera USB observation."""
    from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_R2, UC_ARM_REG_SP,
    )

    primary, base = image(6)
    src, dst, stop, stack = 0x30000000, 0x30001000, 0x38000000, 0x39000000
    sample = bytes(range(16))
    for flag, expected_result in ((0, 2), (1, 0)):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x01053000, 0x1000)
        uc.mem_write(0x01053000, primary[0x01053000 - base:0x01054000 - base])
        for address, length in ((src, 0x2000), (stop, 0x1000), (stack, 0x1000)):
            uc.mem_map(address, length)
        uc.mem_write(src, sample)
        uc.mem_write(dst, b"\xaa" * len(sample))

        def parameter_reader(engine, address, _size, _user):
            if address == 0x010538FC:
                assert engine.reg_read(UC_ARM_REG_R0) == 0xF7
                engine.reg_write(UC_ARM_REG_R0, flag)
                engine.reg_write(UC_ARM_REG_PC, 0x01053900)

        uc.hook_add(UC_HOOK_CODE, parameter_reader)
        uc.reg_write(UC_ARM_REG_R0, len(sample))
        uc.reg_write(UC_ARM_REG_R1, src)
        uc.reg_write(UC_ARM_REG_R2, dst)
        uc.reg_write(UC_ARM_REG_SP, stack + 0x800)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.emu_start(0x010538E4, stop, count=256)
        assert uc.reg_read(UC_ARM_REG_PC) == stop
        assert uc.reg_read(UC_ARM_REG_R0) == expected_result
        assert bytes(uc.mem_read(dst, len(sample))) == (sample if flag else b"\xaa" * 16)
