"""Independent stock-ARM vectors for controller slot-list semantics."""

from pathlib import Path

from tools.x100v_controller_slot_queue_probe import run_vectors


def test_controller_slot_insert_select_remove_vectors():
    rows = run_vectors(Path("out/fw-cache/x100v-301-part7.bin").read_bytes())["rows"]
    expected = (
        ("insert", 4, 1, (4, 1), 4, 4, 0xFFFFFFFF),
        ("insert", 5, 1, (5, 1), 5, 5, 0xFFFFFFFF),
        ("insert", 6, 2, (6, 2), 6, 5, 6),
        ("remove", 5, 0, (6, 2), 6, 4, 6),
        ("remove", 4, 0, (6, 2), 6, 0xFFFFFFFF, 6),
        ("remove", 6, 0, (0xFFFFFFFF, 0xFF),
         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    )
    assert len(rows) == len(expected)
    for row, (action, slot, kind, head, any_slot, kind1, kind2) in zip(rows, expected):
        assert row == {
            "action": action,
            "slot": slot,
            "kind": kind,
            "return": 0,
            "head": head,
            "select_any": any_slot,
            "select_kind_1": kind1,
            "select_kind_2": kind2,
        }
