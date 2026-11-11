"""Consistency checks for the saved original-ARM first-count boundary run.

These checks do not execute firmware; the CLI probe does that offline.
"""
import json
from pathlib import Path

from tools.x100v_refresh_caller_emulator import FIRST_COUNT


REPORT = Path(__file__).resolve().parents[1] / "results" / "x100v-code4-valid-recompute-first-count-arm-fixtures-20261108.json"


def test_saved_boundary_matrix_is_complete_and_paired():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert len(report["cases"]) == 12
    assert report["first_count_executed"] is False
    assert report["full_recomputation_executed"] is False
    assert report["export_executed"] is False
    assert report["camera_executed"] is False
    assert report["synthetic_runtime_halfword_0x0191e9e8"] == 100
    assert {(row["level"], row["second"], row["aspect"]) for row in report["cases"]} == {
        (level, second, aspect)
        for level in range(3) for second in range(2) for aspect in (2, 4)
    }
    for row in report["cases"]:
        assert row["stop_pc"] == hex(FIRST_COUNT)
        assert row["row_index"] == row["stack_arg"] == 0
        assert row["registers"][0] == 0x41
        assert row["registers"][2:] == [0, 0]
        assert len(bytes.fromhex(row["descriptor_hex"])) == 0x30
        assert row["dimension_stub_executed"] == (row["aspect"] == 4)
    for level in range(3):
        for second in range(2):
            pair = [row for row in report["cases"]
                    if row["level"] == level and row["second"] == second]
            assert pair[0]["descriptor_hex"] == pair[1]["descriptor_hex"]


def test_first_row_descriptor_is_same_across_selection_settings():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert len({row["descriptor_hex"] for row in report["cases"]}) == 1
