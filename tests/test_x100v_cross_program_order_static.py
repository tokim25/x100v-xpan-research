"""Pinned stock call-site/table anchors; not a live scheduling test."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_stock_controller_and_key4_dispatch_anchors():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == \
        SOURCES["x100v_3_01"]["secondary_sha256"]
    base = SOURCES["x100v_3_01"]["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # The setup branch calls list insertion before the crop-capable builder.
    assert branch_target(word(0x01F25194), 0x01F25194) == 0x01F16A60
    assert branch_target(word(0x01F2522C), 0x01F2522C) == 0x01F284B0
    assert branch_target(word(0x01F2523C), 0x01F2523C) == 0x01F242C8
    assert 0x01F2522C < 0x01F2523C

    # Group-1 callback entry 5 is the separately gated key-4 sender.
    assert word(0x022D8D24) == 0x022D8C58
    assert word(0x022D8C6C) == 0x01F2A1A4
    assert branch_target(word(0x01F2A1B0), 0x01F2A1B0) == 0x01F253FC
    assert branch_target(word(0x01F2A1EC), 0x01F2A1EC) == 0x01F14F10
    assert branch_target(word(0x01F2A13C), 0x01F2A13C) == 0x01F29734
