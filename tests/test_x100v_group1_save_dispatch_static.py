"""Pinned group-1 FSM table: static routing, not observed camera scheduling."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_fw_explore import branch_target


def test_group1_key4_callback_requires_a_different_event_row():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(image).hexdigest() == source["secondary_sha256"]
    base = source["secondary_load"]

    def word(address):
        return struct.unpack_from("<I", image, address - base)[0]

    def halfword(address):
        return struct.unpack_from("<H", image, address - base)[0]

    # Dispatcher index = mode * stride + per-slot state. Pair byte zero is
    # the callback index. These pointers and stride are original image bytes.
    assert word(0x022D8D38) == 0x022D8974
    assert word(0x022D8D24) == 0x022D8C58
    assert halfword(0x022D8D2E) == 10
    assert word(0x022D8C6C) == 0x01F2A1A4  # callback index 5

    program = image[0x022D8974 - base:0x022D8C58 - base]
    assert len(program) == 740
    callback_five = [i for i in range(len(program) // 2)
                     if program[2 * i] == 5]
    assert callback_five == [26, 246]  # modes 2 and 24, state 6
    assert [program[2 * (33 * 10 + state)] for state in range(10)] == \
        [3, 3, 3, 3, 3, 3, 3, 3, 36, 3]

    # The selected-slot call has event 10. In its group-1 wrapper event 10
    # sets mode 33, whereas key-4 callback 5 sits in modes 2 and 24.
    assert branch_target(word(0x01F2E1C8), 0x01F2E1C8) == 0x01F29718
    assert branch_target(word(0x01F2972C), 0x01F2972C) == 0x01F29578
    assert branch_target(word(0x01F2A13C), 0x01F2A13C) == 0x01F29734
    assert word(0x01F29E20) == 0xE3A02021  # mov r2,#33
    assert branch_target(word(0x01F29E34), 0x01F29E34) == 0x01F2AD08

    # A separate event-0 caller takes a slot from context-to-slot search,
    # not from the kind-1 selector above. Its later mode-24 gate is open.
    assert branch_target(word(0x01F14848), 0x01F14848) == 0x01F10A64
    assert branch_target(word(0x01F10AC4), 0x01F10AC4) == 0x01F28720
    assert branch_target(word(0x01F148F0), 0x01F148F0) == 0x01F29718
    assert word(0x01F29884) == 0xE301223A  # event-0 ID 0x123a comparison
    assert branch_target(word(0x01F2988C), 0x01F2988C) == 0x01F29CB0
    assert word(0x01F05BB8) == 0xE301323A  # separate ID-0x123a sender
    assert branch_target(word(0x01F05BE4), 0x01F05BE4) == 0x0113D87C
