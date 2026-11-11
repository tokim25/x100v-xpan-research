import json
import struct
from pathlib import Path

import pytest

from tools.x100v_jpeg_crop import bl
from tools.x100v_review_crop import FIT, SITES, STUB_ADDRESS

BUILD = Path("build/x100v-review-crop-20261109-a")


def _writes():
    return {w["field"]: w for w in json.loads((BUILD / "manifest.json").read_text())["writes"]}


def test_hooks_replace_only_the_stock_window_fit_calls():
    writes = _writes()
    for site in SITES:
        hook = writes[f"review-crop-hook-{site:08x}"]
        assert hook["before_hex"] == struct.pack("<I", bl(site, FIT)).hex()
        assert hook["after_hex"] == struct.pack("<I", bl(site, STUB_ADDRESS)).hex()
    stub = bytes.fromhex(writes["review-crop-stub"]["after_hex"])
    assert struct.unpack("<I", stub[-4:])[0] == FIT
    assert writes["review-crop-stub"]["before_hex"] == "00" * len(stub)


def test_arm_check_changes_only_aspect_2_to_hand_computed_65x24():
    check = json.loads((BUILD / "arm-check.json").read_text())
    assert check["all_as_expected"]
    rows = {(tuple(r["base"]), r["aspect"]): r for r in check["rows"]}
    # 640x480 review buffer: 16:9 is 640x360 with 60-row margins. 640*24/65 = 236.3,
    # rounded down to a multiple of 4 = 236; margins (480 - 236) / 2 = 122.
    assert rows[((640, 480), 2)]["stock"] == [640, 360, 60, 60, 0, 0]
    assert rows[((640, 480), 2)]["patched"] == [640, 236, 122, 122, 0, 0]
    for (base, aspect), row in rows.items():
        if aspect != 2:
            assert row["patched"] == row["stock"]
