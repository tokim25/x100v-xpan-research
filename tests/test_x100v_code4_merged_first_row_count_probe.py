"""Audit the committed offline ARM report; this is not a camera test."""
import json
from pathlib import Path

from tools.x100v_code4_merged_first_row_count_probe import CAPACITY_VECTORS


REPORT = (Path(__file__).resolve().parents[1] / "results" /
          "x100v-code4-merged-first-row-count-arm-fixtures-20261108.json")


def test_complete_first_row_matrix_and_scope():
    report = json.loads(REPORT.read_text())
    assert report["row0_stored"] is True
    assert report["other_56_rows_executed"] is False
    assert report["cache_export_executed"] is False
    assert report["camera_executed"] is False
    assert report["active_camera_settings_observed"] is False
    cases = report["cases"]
    assert len(cases) == 36
    assert {(c["capacity_oracle_bytes"], c["level"], c["second"], c["aspect"])
            for c in cases} == {(capacity, level, second, aspect)
                              for capacity, _ in CAPACITY_VECTORS
                              for level in range(3) for second in range(2)
                              for aspect in (2, 4)}
    expected = dict(CAPACITY_VECTORS)
    for case in cases:
        assert case["first_count"] == case["cache_row0"] == expected[case["capacity_oracle_bytes"]]
        assert case["stop_pc"] == "0x115c820"
        assert case["dimension_stub_executed"] is (case["aspect"] == 4)
        assert case["coefficient_writes"] == 132
        assert case["table_copy_calls"] == 3
        assert case["free_byte_requests"] == [6, 5]
