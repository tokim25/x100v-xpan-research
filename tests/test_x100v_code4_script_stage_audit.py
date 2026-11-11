"""Pinned byte-program inventory for the crop→compress→save dependency."""

import hashlib
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_script_stage_audit import COUNT, rows_for


def test_all_stored_program_stage_positions():
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(secondary).hexdigest() == SOURCES["x100v_3_01"]["secondary_sha256"]
    rows = rows_for(secondary)
    assert len(rows) == COUNT == 42
    assert [r["key"] for r in rows if r["crop_positions"]] == [3, 21, 35, 37]
    assert [r["key"] for r in rows if r["crop_before_compress"]] == [35]
    assert [r["key"] for r in rows if r["compress_before_save"]] == [4]
    assert not any(r["crop_compress_save_in_order"] for r in rows)
    assert rows[4]["opcodes_hex"] == (
        "4648494a4b4c4d4e4f50515253332a392e2836421f3029382d2735973c3d9d9e"
    )
    assert rows[35]["opcodes_hex"] == "0413140e151f3029382d27359c9e"
