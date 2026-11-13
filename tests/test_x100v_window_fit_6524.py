import json
import struct
from pathlib import Path

import pytest

from tools.x100v_jpeg_crop import bl
from tools.x100v_review_crop import FIT
from tools.x100v_window_fit_6524 import SITES, STUB_ADDRESS, STUB_BYTES

BUILD = Path("build/x100v-window-fit-6524-20261112-a")


def _writes():
    if not (BUILD / "manifest.json").exists():
        pytest.skip("requires locally generated build manifest")
    return {w["field"]: w for w in json.loads((BUILD / "manifest.json").read_text())["writes"]}


def test_stub_sits_after_card_6a_stubs_inside_the_padding():
    # Card 6a's stubs occupy 0x0128fe80..0x0128ff84 (260 bytes); the padding ends at 0x01290000.
    assert STUB_ADDRESS >= 0x0128FE80 + 260
    assert STUB_ADDRESS + STUB_BYTES <= 0x01290000
    stub = bytes.fromhex(_writes()["window-fit-6524-stub"]["after_hex"])
    assert len(stub) == STUB_BYTES and struct.unpack("<I", stub[-4:])[0] == FIT


def test_all_nine_calls_are_redirected():
    writes = _writes()
    assert len(SITES) == 9 and len(writes) == 10
    for site in SITES:
        hook = writes[f"window-fit-hook-{site:08x}"]
        assert hook["before_hex"] == struct.pack("<I", bl(site, FIT)).hex()
        assert hook["after_hex"] == struct.pack("<I", bl(site, STUB_ADDRESS)).hex()


def test_arm_check_changes_only_aspect_2_to_hand_computed_65x24():
    if not (BUILD / "arm-check.json").exists():
        pytest.skip("requires locally generated ARM check")
    check = json.loads((BUILD / "arm-check.json").read_text())
    assert check["all_as_expected"]
    rows = {(tuple(r["base"]), r["aspect"]): r for r in check["rows"]}
    # 640x480: 16:9 is 640x360 with 60-row margins. 640*24/65 = 236.3 -> 236 (a multiple of 4);
    # margins (480 - 236) / 2 = 122.
    assert rows[((640, 480), 2)]["stock"] == [640, 360, 60, 60, 0, 0]
    assert rows[((640, 480), 2)]["patched"] == [640, 236, 122, 122, 0, 0]
    # 900x600 LCD: 900*24/65 = 332.3 -> 332; margins (600 - 332) / 2 = 134.
    assert rows[((900, 600), 2)]["patched"] == [900, 332, 134, 134, 0, 0]
    for (base, aspect), row in rows.items():
        if aspect != 2:
            assert row["patched"] == row["stock"]
