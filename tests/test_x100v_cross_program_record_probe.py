import hashlib
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_cross_program_record_probe import run_case
from tools.x100v_cross_program_slot_probe import RECORD_BASE, ROOT_BASE, SLOT_STRIDE


def test_stock_record_root_handoff():
    secondary_stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(secondary_stock).hexdigest() == \
        SOURCES["x100v_3_01"]["secondary_sha256"]
    for slot in range(3):
        row = run_case(secondary_stock, slot)
        root = ROOT_BASE + slot * SLOT_STRIDE
        assert row["root"] == root
        assert row["record"] == RECORD_BASE + (slot + 2) * 0x50
        assert row["record"] != row["mode_record"]
        assert row["record_word_zero_after_reset"] == 0
        assert row["record_word_zero_after_set_and_copy"] == root
        assert row["mode_record_word_zero_after_set"] == root
        assert row["worker_key_byte"] == f"{slot:02x}"
