"""Stock X100V record-key provenance, without a live-capture claim."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_command14_table_key_is_record_field_not_direct_aspect():
    source = SOURCES["x100v_3_01"]
    primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(primary).hexdigest() == source["primary_sha256"]
    assert hashlib.sha256(secondary).hexdigest() == source["secondary_sha256"]

    def p(address):
        return struct.unpack_from("<I", primary, address - source["primary_load"])[0]

    def s(address):
        return struct.unpack_from("<I", secondary, address - source["secondary_load"])[0]

    assert p(0x011C921C) == 0xE5D0001E  # record +0x1e byte
    assert [s(a) for a in (0x01F4F344, 0x01F4F348)] == [
        0xE5D31B96, 0xE5930B5C
    ]
    assert branch_target(s(0x01F4F34C), 0x01F4F34C) == 0x01ED624C
    assert [s(a) for a in (0x01F302A0, 0x01F302A8, 0x01F302B4,
                           0x01F302C8, 0x01F5BED8, 0x01F5BEE0,
                           0x01F5BEEC, 0x01F5BEFC)] == [
        0xE3500001, 0xE5D435BC, 0x05843B5C, 0xE5840B5C,
        0xE3500001, 0xE5DA35BC, 0x058A3B5C, 0xE58A0B5C,
    ]
    assert branch_target(s(0x01F302C4), 0x01F302C4) == 0x011C9214
    assert branch_target(s(0x01F5BEF8), 0x01F5BEF8) == 0x011C9214
    assert s(0x01ED67AC) == 0xE5C45B96
    assert s(0x01EDAFE4) == 0xE3130C01  # bit 0x100
    assert s(0x01EDB000) == 0xE3A01001
    assert s(0x01EDB004) == 0xE5C51B96
    assert branch_target(s(0x01EDB00C), 0x01EDB00C) == 0x01ED624C
    assert [s(a) for a in (0x01F3C4A8, 0x01F3C4AC)] == [
        0xE5900000, 0xE280003C,
    ]
    assert branch_target(s(0x01F3C4B0), 0x01F3C4B0) == 0x01ED232C
