import json
import struct
from pathlib import Path

import pytest

from tools.x100v_jpeg_crop import CROPS, HOOK, RAF_HOOK, RAF_REJOIN, RAF_STUB_ADDRESS, STUB_ADDRESS, bl

BUILD = Path("build/x100v-jpeg-crop-20261103-a")


def _writes(build=BUILD):
    return {w["field"]: w for w in json.loads((build / "manifest.json").read_text())["writes"]}


def _run_stub(width, height, stride, base=0x40000000, build=BUILD):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    stub = bytes.fromhex(_writes(build)["jpeg-crop-stub"]["after_hex"])
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(STUB_ADDRESS & ~0xFFF, 0x1000)
    uc.mem_write(STUB_ADDRESS, stub)
    for page in (0x30000000, 0x31000000, 0x32000000, 0x33000000):
        uc.mem_map(page, 0x2000)
    uc.mem_write(0x30000000, struct.pack("<7I", 0, base, 0, stride, width, height, 0))
    uc.mem_write(0x31001000 - 0x44, struct.pack("<I", height))
    for reg, value in ((A.UC_ARM_REG_R1, base), (A.UC_ARM_REG_R3, 0x32000000), (A.UC_ARM_REG_R6, 0x30000000),
                       (A.UC_ARM_REG_FP, 0x31001000), (A.UC_ARM_REG_SP, 0x33001000), (A.UC_ARM_REG_LR, 0x33001800),
                       (A.UC_ARM_REG_R0, 7), (A.UC_ARM_REG_R4, 8), (A.UC_ARM_REG_R5, 9)):
        uc.reg_write(reg, value)
    uc.emu_start(STUB_ADDRESS, 0x33001800, count=200)
    block = struct.unpack("<6I", uc.mem_read(0x32000000, 24))
    header = struct.unpack("<I", uc.mem_read(0x31001000 - 0x44, 4))[0]
    kept = [uc.reg_read(r) for r in (A.UC_ARM_REG_R0, A.UC_ARM_REG_R4, A.UC_ARM_REG_R5, A.UC_ARM_REG_SP)]
    return block, header, kept


@pytest.mark.parametrize("size", ["L", "M", "S"])
def test_stub_crops_stock_16_9_sizes_to_65_24(size):
    width, height, new_height, rows = CROPS[size]
    stride = width + 64
    block, header, kept = _run_stub(width, height, stride)
    assert block[5] == 0x40000000 + rows * stride
    assert block[4] == new_height == header
    assert (height - new_height) == 2 * rows and new_height % 16 == 0
    assert kept == [7, 8, 9, 0x33001000]


@pytest.mark.parametrize("width,height", [(12480, 4160), (8320, 4160), (1280, 480), (9984, 2808), (12480, 3510)])
def test_stub_leaves_other_images_alone(width, height):
    block, header, kept = _run_stub(width, height, width)
    assert block[5] == 0x40000000 and block[4] == 0 and header == height
    assert kept == [7, 8, 9, 0x33001000]


def test_hook_is_a_bl_from_the_compression_setup_to_the_stub():
    hook = _writes()["jpeg-crop-hook"]
    assert hook["before_hex"] == struct.pack("<I", 0xE5831014).hex()
    assert hook["after_hex"] == struct.pack("<I", bl(HOOK, STUB_ADDRESS)).hex()
    assert json.loads((BUILD / "arm-check.json").read_text())["all_as_expected"]


def test_encoder_table_writes_give_16_9_entries_the_65_24_heights():
    data = json.loads(Path("build/x100v-jpeg-crop-20261103-b/manifest.json").read_text())
    table = [w for w in data["writes"] if w["field"].startswith("encoder-size-")]
    assert [(w["partition"], struct.unpack("<H", bytes.fromhex(w["before_hex"]))[0],
             struct.unpack("<H", bytes.fromhex(w["after_hex"]))[0]) for w in table] == [
        (9, 3512, 2304), (9, 2488, 1632), (9, 1760, 1152)]
    assert [w["address"] for w in table] == [0x03DB1498 + 6 * e + 2 for e in (4, 5, 6)]


def test_encoder_lookup_finds_16_9_configs_for_cropped_sizes_and_keeps_others():
    rows = {r["case"]: r for r in json.loads(
        Path("build/x100v-jpeg-crop-20261103-b/arm-check.json").read_text())["encoder_lookup"]["rows"]}
    assert [rows[f"65:24 {s}"]["stock"] for s in "LMS"] == [0, 0, 0]
    assert [rows[f"65:24 {s}"]["patched"] for s in "LMS"] == [8, 9, 10]
    for case in ("3:2 L", "1:1 L", "640x480", "thumbnail 160x120 mode 0", "preview 640x480 mode 2"):
        assert rows[case]["patched"] == rows[case]["stock"] != 0


@pytest.mark.parametrize("size", ["L", "M", "S"])
def test_block_only_stub_crops_the_encoder_block_but_keeps_the_setup_height(size):
    width, height, new_height, rows = CROPS[size]
    stride = width + 64
    block, header, kept = _run_stub(width, height, stride, build=Path("build/x100v-jpeg-crop-20261103-c"))
    assert block[5] == 0x40000000 + rows * stride and block[4] == new_height
    assert header == height
    assert kept == [7, 8, 9, 0x33001000]


def test_raf_aspect_writes_change_only_the_16_9_pair_to_24_65():
    data = json.loads(Path("build/x100v-jpeg-crop-20261103-d/manifest.json").read_text())
    raf = {w["field"]: w for w in data["writes"] if w["field"].startswith("raf-aspect-")}
    assert raf["raf-aspect-ratio-pair-code2-first"]["address"] == 0x01F69464
    assert raf["raf-aspect-ratio-pair-code2-second"]["address"] == 0x01F6946C
    words = {k: (struct.unpack("<I", bytes.fromhex(w["before_hex"]))[0],
                 struct.unpack("<I", bytes.fromhex(w["after_hex"]))[0]) for k, w in raf.items()}
    # mov r3, #imm: only the immediate changes, 9 -> 24 and 16 -> 65
    assert words["raf-aspect-ratio-pair-code2-first"] == (0xE3A03009, 0xE3A03018)
    assert words["raf-aspect-ratio-pair-code2-second"] == (0xE3A03010, 0xE3A03041)
    assert [w["field"] for w in data["writes"]][:2] == ["jpeg-crop-stub", "jpeg-crop-hook"]


RAF_BUILD = Path("build/x100v-jpeg-crop-20261103-e")


def _run_raf_stub(area, mirror=True):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    stub = bytes.fromhex(_writes(RAF_BUILD)["raf-crop-stub"]["after_hex"])
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(RAF_STUB_ADDRESS & ~0xFFF, 0x1000)
    uc.mem_write(RAF_STUB_ADDRESS, stub)
    for page in (0x30000000, 0x33000000):
        uc.mem_map(page, 0x1000)
    record = bytes(range(0x40, 0x70))
    record = record[:4] + struct.pack("<4H", *area) + record[12:]
    uc.mem_write(0x30000000, record)
    uc.mem_write(0x30000100, record)
    for reg, value in ((A.UC_ARM_REG_R4, 0x30000000), (A.UC_ARM_REG_SL, 0x30000100 if mirror else 0),
                       (A.UC_ARM_REG_SP, 0x33000800), (A.UC_ARM_REG_R0, 7), (A.UC_ARM_REG_R1, 8),
                       (A.UC_ARM_REG_R2, 9), (A.UC_ARM_REG_R5, 10), (A.UC_ARM_REG_R6, 11)):
        uc.reg_write(reg, value)
    uc.emu_start(RAF_STUB_ADDRESS, RAF_REJOIN, count=100)
    out = bytes(uc.mem_read(0x30000000, 0x30))
    copy = bytes(uc.mem_read(0x30000100, 0x30))
    kept = [uc.reg_read(r) for r in (A.UC_ARM_REG_R0, A.UC_ARM_REG_R1, A.UC_ARM_REG_R2, A.UC_ARM_REG_R4,
                                     A.UC_ARM_REG_R5, A.UC_ARM_REG_R6, A.UC_ARM_REG_SP)]
    return record, out, copy, kept, uc.reg_read(A.UC_ARM_REG_PC)


def test_raf_stub_marks_a_centred_65_24_band_of_the_stock_16_9_area():
    record, out, copy, kept, pc = _run_raf_stub((13, 6, 4160, 6240))
    top, left, height, width = struct.unpack_from("<4H", out, 4)
    assert (top, left, height, width) == (13 + 930, 6, 2304, 6240)
    assert height * 65 == width * 24  # exactly 65:24
    assert 930 % 6 == 0 and height % 6 == 0  # X-Trans pattern phase kept
    assert abs((4160 - height) // 2 - 930) <= 2  # centred within two rows
    assert struct.unpack_from("<2H", out, 0x14) == (24, 65)
    assert struct.unpack_from("<4H", copy, 4) == (943, 6, 2304, 6240)
    changed = [i for i in range(0x30) if out[i] != record[i]]
    assert changed == [4, 5, 8, 9, 0x14, 0x15, 0x16, 0x17]
    assert kept == [7, 8, 9, 0x30000000, 10, 11, 0x33000800] and pc == RAF_REJOIN


def test_raf_stub_without_a_mirror_record_writes_only_the_record():
    _, out, copy, _, pc = _run_raf_stub((13, 6, 4160, 6240), mirror=False)
    assert struct.unpack_from("<4H", out, 4) == (943, 6, 2304, 6240)
    assert struct.unpack_from("<4H", copy, 4) == (13, 6, 4160, 6240) and pc == RAF_REJOIN


def test_raf_stub_tags_only_the_aspect_for_an_unexpected_area():
    record, out, copy, _, _ = _run_raf_stub((13, 6, 3512, 6240))
    assert struct.unpack_from("<4H", out, 4) == (13, 6, 3512, 6240)
    assert struct.unpack_from("<2H", out, 0x14) == (24, 65)
    assert copy == record


def test_raf_hook_branches_from_the_16_9_case_to_the_stub():
    hook = _writes(RAF_BUILD)["raf-crop-hook"]
    assert hook["address"] == RAF_HOOK == 0x01F69464
    assert hook["before_hex"] == struct.pack("<I", 0xE3A03009).hex()  # mov r3, #9
    offset = ((RAF_STUB_ADDRESS - (RAF_HOOK + 8)) >> 2) & 0xFFFFFF
    assert hook["after_hex"] == struct.pack("<I", 0xEA000000 | offset).hex()
    stub = bytes.fromhex(_writes(RAF_BUILD)["raf-crop-stub"]["after_hex"])
    assert struct.unpack("<I", stub[-4:])[0] == RAF_REJOIN
    assert RAF_STUB_ADDRESS >= STUB_ADDRESS + len(bytes.fromhex(_writes(RAF_BUILD)["jpeg-crop-stub"]["after_hex"]))


def test_raf_arm_check_changes_only_aspect_code_2():
    check = json.loads((RAF_BUILD / "arm-check.json").read_text())
    assert check["all_as_expected"]
    rows = {r["case"]: r for r in check["raf_area"]["rows"]}
    for code in (0, 1, 3, 4, 5, 6):
        row = rows[f"aspect code {code}"]
        assert row["patched"]["aspect"] == row["stock"]["aspect"] and row["patched"]["area"] == row["stock"]["area"]
        assert not row["patched"]["stub_ran"]
    assert rows["aspect code 2"]["patched"]["area"] == [943, 6, 2304, 6240]
    assert rows["aspect code 2"]["patched"]["mirror_area"] == [943, 6, 2304, 6240]
