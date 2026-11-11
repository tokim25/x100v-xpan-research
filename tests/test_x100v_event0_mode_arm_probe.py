"""Synthetic original-ARM controls for event-0, event-5, and event-10 rows."""

from pathlib import Path

from tools.x100v_event0_mode_arm_probe import run_vectors


def test_stock_event_to_group1_mode_and_slot_passthrough():
    rows = run_vectors(Path("out/fw-cache/x100v-301-part7.bin").read_bytes())
    assert rows == [
        {"message_id": 0x123A, "event": 0, "group": 1, "slot": 7,
         "forwarded_event": 0, "mode": 24, "gate_halfword": 0},
        {"message_id": 0x11A2, "event": 0, "group": 1, "slot": 7,
         "forwarded_event": 0, "mode": 5, "gate_halfword": 0},
        {"message_id": 0x1239, "event": 0, "group": 1, "slot": 7,
         "forwarded_event": 0, "mode": 28, "gate_halfword": 0},
        {"message_id": 0, "event": 5, "group": 1, "slot": 7,
         "forwarded_event": 5, "mode": 2, "gate_halfword": 0x0100},
        {"message_id": 0, "event": 10, "group": 1, "slot": 7,
         "forwarded_event": 10, "mode": 33, "gate_halfword": 0},
    ]
