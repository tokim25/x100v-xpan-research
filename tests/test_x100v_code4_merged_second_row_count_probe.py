"""Check the committed two-row synthetic ARM matrix, not camera behavior."""
import json
from pathlib import Path


REPORT = (Path(__file__).resolve().parents[1] / "results" /
          "x100v-code4-merged-second-row-count-arm-fixtures-20261108.json")


def test_two_row_matrix_and_boundary():
    report = json.loads(REPORT.read_text())
    assert report["first_two_rows_stored"] is True
    assert report["other_55_rows_executed"] is False
    assert report["cache_export_executed"] is False
    assert report["camera_executed"] is False
    cases = report["cases"]
    assert len(cases) == 24
    assert {(c["capacity_oracle_bytes"], c["level"], c["second"], c["aspect"])
            for c in cases} == {(capacity, level, second, aspect)
                              for capacity in (100_000_000, 500_000_000)
                              for level in range(3) for second in range(2)
                              for aspect in (2, 4)}
    for case in cases:
        expected = ((1, 758) if case["capacity_oracle_bytes"] == 100_000_000
                    else (8, 3809))
        assert (case["row0"], case["row1"]) == expected
        assert case["stop_pc"] == "0x115c820"
        assert case["table_copy_calls"] == 6
        assert case["free_byte_requests"] == [6, 5, 6, 5]
