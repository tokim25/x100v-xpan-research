"""Pinned default-row matrix and synthetic nested-classifier controls."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_123a_nested_mode_arm_probe import (
    run_callback_column_vectors, run_followup_vectors,
    run_mode0_row18_matrix_vectors, run_vectors,
)
from tools.x100v_fw_explore import branch_target


def test_123a_nested_mode0_default_row_and_callback_anchors():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    assert branch_target(word(0x01F262F4), 0x01F262F4) == 0x01F05C08
    assert word(0x01F05FEC) == 0x034CACB8  # ID at +0xb8
    assert image[0x022D7770 - base:0x022D777A - base] == bytes.fromhex(
        "0f011001110112011301"
    )  # row 18: callback indices 15..19; second byte 1
    assert [word(0x022D7CEC + 4 * i) for i in range(15, 20)] == [
        0x01F07794, 0x01F077D8, 0x01F077F8, 0x01F07820, 0x01F07928,
    ]
    assert branch_target(word(0x01F077A0), 0x01F077A0) == 0x01F05FF0
    assert branch_target(word(0x01F077E4), 0x01F077E4) == 0x01F05FF0
    assert branch_target(word(0x01F07804), 0x01F07804) == 0x01F05FF0
    assert branch_target(word(0x01F0782C), 0x01F0782C) == 0x01F05FF0
    assert branch_target(word(0x01F07934), 0x01F07934) == 0x01F06614


def test_123a_nested_mode0_classifier_original_arm():
    rows = run_vectors(Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"message_id": 0x123A, "action": 0, "row": 18},
        {"message_id": 0x1151, "action": 0, "row": 17},
        {"message_id": 0x1232, "action": 0, "row": 13},
        {"message_id": 0x11B9, "action": 0, "row": 15},
    ]


def test_123a_followup_default_rows_and_matrix_anchors():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    def row(matrix, index, columns):
        start = matrix - base + 2 * index * columns
        return [list(image[start + 2 * i:start + 2 * i + 2])
                for i in range(columns)]

    assert word(0x01F06288) == word(0x01F06734) == 0x034CACB8
    assert word(0x022D7D80) == 0x022D7790  # mode-1 matrix
    assert word(0x022D7D88) == 0x022D7BC8  # mode-3 matrix
    assert row(0x022D7790, 11, 5) == [[14, 1], [11, 1], [12, 1],
                                      [13, 1], [15, 1]]
    assert row(0x022D7BC8, 3, 3) == [[3, 1], [3, 1], [3, 1]]
    assert [word(0x022D7B78 + 4 * i) for i in (11, 12, 13, 14, 15)] == [
        0x01F07ADC, 0x01F07B30, 0x01F07B7C, 0x01F07BA8, 0x01F07BCC,
    ]
    assert word(0x022D7BEC + 4 * 3) == 0x01F07E34
    assert branch_target(word(0x01F07BB4), 0x01F07BB4) == 0x01F06DD8
    assert branch_target(word(0x01F07AE8), 0x01F07AE8) == 0x01F06DD8
    assert branch_target(word(0x01F07B3C), 0x01F07B3C) == 0x01F06738
    assert branch_target(word(0x01F07B88), 0x01F07B88) == 0x01F0628C
    assert branch_target(word(0x01F07BD8), 0x01F07BD8) == 0x01F073AC
    assert branch_target(word(0x01F07E3C), 0x01F07E3C) == 0x01F26338


def test_123a_followup_classifiers_original_arm():
    rows = run_followup_vectors(
        Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"message_id": 0x123A, "mode": 1, "row": 11},
        {"message_id": 0x1159, "mode": 1, "row": 2},
        {"message_id": 0x1232, "mode": 1, "row": 5},
        {"message_id": 0x123A, "mode": 3, "row": 3},
        {"message_id": 0x115E, "mode": 3, "row": 0},
        {"message_id": 0x11A9, "mode": 3, "row": 1},
        {"message_id": 0x9240, "mode": 3, "row": 2},
    ]


def test_123a_mode0_row18_post_callback_pointer_is_null():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]
    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    assert word(0x022D7D9C) == 0x022D7D44  # mode-0 post-callback table
    assert word(0x022D7D48) == 0  # row-18 second byte 1 indexes null
    assert word(0x022D7D4C) == 0x022D7CEC  # distinct main callback table


def test_123a_mode0_row18_matrix_original_arm():
    rows = run_mode0_row18_matrix_vectors(
        Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"column": i, "callback": callback,
         "column_after_matrix_only": i}
        for i, callback in enumerate((0x01F07794, 0x01F077D8,
                                      0x01F077F8, 0x01F07820,
                                      0x01F07928))
    ]


def test_123a_mode0_callbacks_15_and_19_column_write_anchors():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    assert word(0x01F077C8) == 0xE1C320B0  # cb15 writes halfword zero
    assert word(0x01F07964) == 0xE1C320B0  # cb19 writes halfword one
    assert word(0x01F07974) == 0x034CACB8  # cb19 result-byte base


def test_123a_mode0_callbacks_15_and_19_original_arm():
    rows = run_callback_column_vectors(
        Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"callback": 0x01F07794, "nested_result": 0,
         "column_after_callback": 0x55, "helper_calls": 0},
        {"callback": 0x01F07794, "nested_result": 1,
         "column_after_callback": 0, "helper_calls": 2},
        {"callback": 0x01F07928, "nested_result": 0,
         "column_after_callback": 0x55, "helper_calls": 0},
        {"callback": 0x01F07928, "nested_result": 1,
         "column_after_callback": 1, "helper_calls": 2},
    ]
