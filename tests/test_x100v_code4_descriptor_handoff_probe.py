"""Original-ARM controls for command-0x15 and mode-0 encoder slot selection."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_descriptor_handoff_probe import run_copy, run_select


def test_producer_consumer_branch_matrix():
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(secondary).hexdigest() == SOURCES["x100v_3_01"]["secondary_sha256"]
    descriptor = bytearray(28)
    struct.pack_into("<5I", descriptor, 4, 0x40000000, 2304 * 12544,
                     12544, 12480, 2304)
    for state, bit10, producer_slot, selector1_slot in (
        (25, 0, "+0xf0", "+0xf0"),
        (26, 0, "+0xf0", "+0xf0"),
        (24, 1, "+0xf0", "+0xf0"),
        (24, 0, "+0xd4", "+0xd4"),
    ):
        produced = run_copy(secondary, state, bit10, 1, bytes(descriptor))
        assert produced == {"destination": producer_slot, "other_slot_unchanged": True}
        assert run_select(secondary, state, bit10, 0, 1)["slot"] == "+0xd4"
        assert run_select(secondary, state, bit10, 1, 1)["slot"] == selector1_slot
    assert run_copy(secondary, 25, 0, 0, bytes(descriptor))["destination"] == "+0xd4"
    assert run_select(secondary, 25, 0, 1, 0)["slot"] is None
    assert run_select(secondary, 24, 0, 1, 1, mode=2)["slot"] == "+0x144"
