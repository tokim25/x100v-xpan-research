"""Pinned stock RAF fragment-array bridge; no camera execution claim."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_raf_cfa_pair_joins_the_save_workers_row_two_array():
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    overlay = Path("out/fw-cache/x100v-301-part9.bin").read_bytes()
    assert hashlib.sha256(secondary).hexdigest() == SOURCES["x100v_3_01"]["secondary_sha256"]
    assert hashlib.sha256(overlay).hexdigest() == "cb8770127a28edff2474ce8f05d7ccb39a33a39e02801a2449182fb5843855b3"

    def word(image, base, address):
        return struct.unpack_from("<I", image, address - base)[0]

    s = lambda address: word(secondary, 0x01BA0000, address)
    o = lambda address: word(overlay, 0x03720000, address)

    assert branch_target(s(0x01EE4C5C), 0x01EE4C5C) == 0x03DAE324
    assert [s(0x01EE4B74 + 4 * i) for i in range(5)] == [
        0x01EE4C00, 0x01EE4C18, 0x01EE4C18, 0x01EE4C7C, 0x01EE4C18
    ]
    assert [o(a) for a in (0x03DAE3A8, 0x03DAE3AC, 0x03DAE3B0, 0x03DAE3B4)] == [
        0xE591708C, 0xE78C7003, 0xE5913090, 0xE5843004
    ]
    assert [s(a) for a in (0x01ED9F58, 0x01ED9F60, 0x01ED9F64,
                            0x01ED9EF4, 0x01ED9EFC, 0x01ED9F00)] == [
        0xE0836182, 0xE3038E68, 0xE7963008,
        0xE3033E6C, 0xE7961008, 0xE5993004
    ]
    assert 0x4140 + 8 == 0x3E68 + 2 * 0x170
    assert 0x4140 + 8 + 8 == 0x4150
    assert s(0x01ED932C) == 0xE3A03002  # conditional row-2 selector


def test_key35_command14_can_write_raw_source_before_command15():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    script = image[0x022DF2E0 - base:0x022DF2E0 - base + 14]
    assert script == bytes.fromhex("0413140e151f3029382d27359c9e")
    assert script.index(0x14) < script.index(0x15) < script.index(0x27)
    assert word(0x01F4FBF4) == 0xE3A01014
    assert branch_target(word(0x01F4FBFC), 0x01F4FBFC) == 0x01F4F8C0
    assert word(0x01F4F944) == 0xE3A02000  # variant zero, gated
    assert branch_target(word(0x01F4F950), 0x01F4F950) == 0x01F4F328
    assert branch_target(word(0x01F4F3D0), 0x01F4F3D0) == 0x01F4F4AC
    assert [word(a) for a in (0x01F4F468, 0x01F4F46C, 0x01F4F470,
                               0x01F4F48C, 0x01F4F494, 0x01F4F498,
                               0x01F4F49C, 0x01F4F4A0)] == [
        0xE50B7050, 0xE0010293, 0xE50B104C,
        0xE284C048, 0xE8BE000F, 0xE8AC000F,
        0xE89E0007, 0xE88C0007
    ]
