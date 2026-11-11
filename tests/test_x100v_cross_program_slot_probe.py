"""Independent vectors for the crop/save producers' shared slot index domain."""

import hashlib
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_cross_program_slot_probe import run_accessors


def test_three_original_arm_slot_accessor_vectors():
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(secondary).hexdigest() == SOURCES["x100v_3_01"]["secondary_sha256"]
    vectors = (
        (0x36000000, 0x03421524, "09000000045b200206000000"),
        (0x36005610, 0x03421574, "0a000000105b200206000000"),
        (0x3600AC20, 0x034215C4, "0b0000001c5b200206000000"),
    )
    for slot, (root, record, queue_bytes) in enumerate(vectors):
        assert run_accessors(secondary, slot) == {
            "root": root, "record": record, "queue": 0,
            "queue_bytes": queue_bytes,
        }
