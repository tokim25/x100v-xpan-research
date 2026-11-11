import json
import struct
from pathlib import Path

from tools.x100v_jpeg_crop import bl
from tools.x100v_raf_sports_container import (CONTAINER_HOOK, CROP_MODE_HOOK, CROP_MODE_OFFSET, DIRECTORY,
                                              RECORD, STUB_ADDRESS, run_container, run_crop_mode, stock_object)

BUILD = Path("build/x100v-raf-sports-container-20261111-a")


def _writes():
    return {w["field"]: w for w in json.loads((BUILD / "manifest.json").read_text())["writes"]}


def _stub():
    return bytes.fromhex(_writes()["raf-sports-container-stubs"]["after_hex"])


def test_hooks_replace_the_two_stock_instructions():
    writes = _writes()
    hook = writes["raf-sports-container-hook"]
    assert hook["before_hex"] == "18d04be2"  # sub sp, fp, #0x18
    assert hook["after_hex"] == struct.pack("<I", bl(CONTAINER_HOOK, STUB_ADDRESS)).hex()
    hook = writes["raf-crop-mode-hook"]
    assert hook["before_hex"] == "0030a0e3"  # mov r3, #0
    assert hook["after_hex"] == struct.pack("<I", bl(CROP_MODE_HOOK, STUB_ADDRESS + CROP_MODE_OFFSET)).hex()
    stub = _stub()
    assert writes["raf-sports-container-stubs"]["before_hex"] == "00" * len(stub)
    # The stub restores the replaced instruction before returning.
    assert bytes.fromhex("18d04be2") in stub


def test_full_sensor_6524_record_becomes_the_sports_finder_container():
    out = run_container(_stub(), stock_object())
    obj = out["object"]
    # Worked by hand: one row is 6384 * 2 = 12768 bytes; 420 rows = 5,362,560;
    # 3348 rows = 42,747,264; plus the 0x800 directory prefix = 42,749,312.
    assert struct.unpack_from("<II", obj, 0x8C) == (0x50000000 + 5362560, 42747264)
    assert struct.unpack_from("<I", obj, 0x1D4)[0] == 42749312
    assert struct.unpack_from("<10H", obj, RECORD) == (3348, 6384, 519, 6, 2304, 6240, 6240, 2304, 2304, 6240)
    assert struct.unpack_from("<2H", obj, RECORD + 0x14) == (24, 65)
    assert struct.unpack_from("<2H", obj, RECORD + 0x20) == (2304, 6240)
    assert struct.unpack_from("<I", obj, DIRECTORY + 0x28)[0] == 6384
    assert struct.unpack_from("<I", obj, DIRECTORY + 0x34)[0] == 3348
    assert struct.unpack_from("<I", obj, DIRECTORY + 0x7C)[0] == 42747264
    assert out["r0_kept"] and out["r4_kept"] and out["sp_is_fp_minus_0x18"]
    # The top row keeps the Sports Finder colour phase: 519 and 9 differ by a multiple of 6.
    assert (519 - 9) % 6 == 0 and 420 % 6 == 0


def test_other_shots_are_left_alone():
    stub = _stub()
    cases = (stock_object(aspect=(9, 16)), stock_object(aspect=(2, 3)), stock_object(aspect=(1, 1)),
             stock_object(length=40_000_000), stock_object(rows=3348))
    for obj in cases:
        out = run_container(stub, obj)
        assert out["object"] == obj
        assert out["r0_kept"] and out["sp_is_fp_minus_0x18"]


def test_crop_mode_is_2_only_for_aspect_code_2():
    stub = _stub()
    assert [run_crop_mode(stub, a) for a in range(8)] == [0, 0, 2, 0, 0, 0, 0, 0]


def test_recorded_arm_check_passed():
    assert json.loads((BUILD / "arm-check.json").read_text())["all_as_expected"]
