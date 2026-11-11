"""Pinned static transport links and synthetic original-ARM receive controls."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_123a_receiver_arm_probe import run_gate_vectors, run_vectors
from tools.x100v_fw_explore import branch_target


def test_123a_conditional_channel7_receive_chain_anchors():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    assert branch_target(word(0x01F05BE4), 0x01F05BE4) == 0x0113D87C
    assert branch_target(word(0x01E6AB28), 0x01E6AB28) == 0x01F035BC
    assert branch_target(word(0x01F03678), 0x01F03678) == 0x01F293B8
    assert branch_target(word(0x01F0368C), 0x01F0368C) == 0x01F1CD08
    assert branch_target(word(0x01F1CD18), 0x01F1CD18) == 0x01F27F68
    assert word(0x01F27FD0) == 0x034CACB8
    assert word(0x022DD430) == 0x0000123A  # message table row 96
    assert word(0x022DD438) == 0x000000B2  # per-slot bit 178
    assert word(0x022DD43C) == 0x01F30694  # row callback
    assert branch_target(word(0x01F307C0), 0x01F307C0) == 0x01F28720
    assert branch_target(word(0x01F30800), 0x01F30800) == 0x01ED3020
    assert word(0x01F306B4) == 0xE5C216A0  # 0x123a callback: low gate byte = 0
    assert word(0x01F29940) == 0xE5C306A1  # event 5: high gate byte = 1
    assert word(0x01F25408) == 0xE1D300B0  # key-4 gate: load halfword
    assert word(0x01F2540C) == 0xE3500C01  # require exactly 0x0100


def test_123a_prefilter_and_record_copy_original_arm():
    rows = run_vectors(Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"message_id": message_id, "prefilter_result": 1,
         "copy_result": 0, "record_id": message_id,
         "record_byte2": 0x5A, "record_byte3": 0xA5,
         "record_length": 0}
        for message_id in (0x123A, 0x11A2)
    ]


def test_123a_callback_clears_only_low_byte_of_key4_gate():
    rows = run_gate_vectors(Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"before": 0x0101, "after_callback": 0x0100, "gate_result": 1},
        {"before": 0x0001, "after_callback": 0x0000, "gate_result": 0},
        {"before": 0x0201, "after_callback": 0x0200, "gate_result": 0},
        {"before": 0x0100, "after_callback": 0x0100, "gate_result": 1},
    ]
