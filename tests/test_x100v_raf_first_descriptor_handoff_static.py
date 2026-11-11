"""Pinned ARM bytes for the conditional first RAF CFA descriptor handoff."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_script_stage_audit import rows_for
from tools.x100v_fw_explore import branch_target


def test_mode_two_passes_context_48_to_first_raf_cfa_object():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    # The normal branch tests its mode byte. Only mode 2 enters the
    # context+0x48 validation branch; other modes clear the fourth argument.
    assert [word(a) for a in (0x01F47690, 0x01F47694, 0x01F47698,
                              0x01F4769C)] == [
        0xE55B3023, 0xE3530002, 0x13A03000, 0x0AFFFF89
    ]
    assert branch_target(word(0x01F4769C), 0x01F4769C) == 0x01F474C8
    assert [word(a) for a in (0x01F474C8, 0x01F474CC, 0x01F474D0,
                              0x01F474D8, 0x01F474DC, 0x01F474E0,
                              0x01F474E4, 0x01F474E8)] == [
        0xE2853901, 0xE2852048, 0xE285103C, 0xEBFE2B0B,
        0xE3500001, 0x05943000, 0x02833048, 0x13A03000
    ]
    assert branch_target(word(0x01F474D8), 0x01F474D8) == 0x01ED210C
    assert branch_target(word(0x01F476AC), 0x01F476AC) == 0x01EE4678

    # Selector 2 is the command-0x2f route. The key-35 RAW-crop script
    # contains command 0x14 and 0x15, but not 0x2f; a cross-program
    # same-exposure handoff remains a separate, unproved scheduler question.
    assert word(0x01F4FF20) == 0xE3A01002
    assert branch_target(word(0x01F4FF28), 0x01F4FF28) == 0x01F472AC
    key35 = image[0x022DF2E0 - base:0x022DF2E0 - base + 14]
    assert key35 == bytes.fromhex("0413140e151f3029382d27359c9e")
    assert 0x14 in key35 and 0x15 in key35 and 0x2F not in key35

    # Exhaustive bounded inventory of the 42 selectable stock programs.
    # The mode-2 command is isolated in key 30, rather than either the
    # crop-bearing key 35 or the save-bearing key 4.
    rows = rows_for(image)
    assert len(rows) == 42
    cmd2f_keys = [r["key"] for r in rows
                   if 0x2F in bytes.fromhex(r["opcodes_hex"])]
    assert cmd2f_keys == [30]
    scripts = {r["key"]: bytes.fromhex(r["opcodes_hex"]) for r in rows}
    assert scripts[30] == bytes.fromhex("2f2b3a25349d9e")
    assert scripts[35] == key35
    assert scripts[4] == bytes.fromhex(
        "4648494a4b4c4d4e4f50515253332a392e2836421f3029382d2735973c3d9d9e")
    assert all(0x2F not in scripts[key] for key in (4, 35))
    assert all(0x15 not in scripts[key] for key in (4, 30))
    assert all(0x3C not in scripts[key] and 0x3D not in scripts[key]
               for key in (30, 35))

    # The other caller mode passes literal zero, a useful negative control.
    assert word(0x01F47494) == 0xE3A03000
    assert branch_target(word(0x01F474A4), 0x01F474A4) == 0x01EE4678

    # Inside the RAF constructor, loop index zero uses that same fourth
    # argument as the source of its first per-shot CFA pointer/length.
    assert branch_target(word(0x01EE48EC), 0x01EE48EC) == 0x01EE4998
    assert [word(a) for a in (0x01EE4998, 0x01EE499C, 0x01EE49A0,
                              0x01EE49A4, 0x01EE49A8)] == [
        0xE3033A18, 0xE340323F, 0xE51B2040, 0xE51B103C, 0xE1A00004
    ]
    assert branch_target(word(0x01EE49AC), 0x01EE49AC) == 0x01ED8544
    assert [word(a) for a in (0x01ED856C, 0x01ED8570,
                              0x01ED8574, 0x01ED8578)] == [
        0xE5973004, 0xE584308C, 0xE5973008, 0xE5843090
    ]
