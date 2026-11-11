"""Synthetic trace controls; these do not assert a camera observation."""

from copy import deepcopy

import pytest

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_raf_handoff_trace import check_trace


DESC = [2, 0x20001000, 0x123400, 0x18F0, 6240, 4160, 0]


def sample():
    common = {"epoch": 3, "slot": 7, "context_root": 0x30010000,
              "record_id": 91}
    def event(seq, stage, **extra):
        return {**common, "seq": seq, "stage": stage, **extra}
    return {
        "format": "x100v-raf-handoff-v1",
        "stock_secondary_sha256": SOURCES["x100v_3_01"]["secondary_sha256"],
        "loaded_secondary_sha256": "a" * 64,  # synthetic; not a camera image
        "events": [
            event(1, "command14_post", descriptor=DESC.copy()),
            event(2, "event76_request", group=66),
            event(3, "command2f_pre", descriptor=DESC.copy(), mode=2,
                  arg3="context+0x48"),
            event(4, "raf_object", pointer=DESC[1], length=DESC[2], object_index=0),
            event(5, "save_row2", pointer=DESC[1], length=DESC[2], row=2),
        ],
    }


def test_positive_structural_trace_does_not_claim_camera_or_raw_crop():
    result = check_trace(sample())
    assert result["structurally_consistent"]
    assert result["group"] == 66
    assert result["last_descriptor_writer"] == "command14_post"
    assert result["camera_origin_authenticated"] is False
    assert result["raw_crop_or_file_save_proven"] is False


def test_command0f_can_be_last_writer_before_key30():
    trace = sample()
    changed = [2, 0x20002000, 0x123000, 0x18F0, 6240, 2304, 0]
    trace["events"].insert(1, {**trace["events"][0], "seq": 2,
                                "stage": "command0f_post",
                                "descriptor": changed})
    for event in trace["events"][2:]:
        event["seq"] += 1
    trace["events"][3]["descriptor"] = changed.copy()
    for event in trace["events"][4:]:
        event["pointer"], event["length"] = changed[1:3]
    result = check_trace(trace)
    assert result["structurally_consistent"]
    assert result["last_descriptor_writer"] == "command0f_post"


@pytest.mark.parametrize(("stage", "field", "value"), [
    ("command2f_pre", "mode", 4),
    ("command2f_pre", "arg3", "zero"),
    ("command2f_pre", "descriptor", [2, 0x20003000, 0x123400, 0x18F0, 6240, 4160, 0]),
    ("raf_object", "pointer", 0x20003000),
    ("raf_object", "object_index", 1),
    ("save_row2", "length", 0x1233FF),
    ("save_row2", "row", 3),
    ("event76_request", "group", 99),
    ("save_row2", "slot", 8),
    ("save_row2", "epoch", 4),
    ("save_row2", "context_root", 0x30020000),
    ("save_row2", "record_id", 92),
])
def test_mismatch_fails(stage, field, value):
    trace = sample()
    event = next(e for e in trace["events"] if e["stage"] == stage)
    event[field] = value
    assert not check_trace(trace)["structurally_consistent"]


def test_missing_and_reordered_stages_fail():
    trace = sample()
    trace["events"] = [e for e in trace["events"] if e["stage"] != "command14_post"]
    assert not check_trace(trace)["structurally_consistent"]
    trace = sample()
    trace["events"][2], trace["events"][3] = trace["events"][3], trace["events"][2]
    for i, event in enumerate(trace["events"], 1):
        event["seq"] = i
    assert not check_trace(trace)["structurally_consistent"]


def test_late_command0f_cannot_be_claimed_as_key30_source():
    trace = sample()
    trace["events"].insert(3, {**trace["events"][0], "seq": 4,
                                "stage": "command0f_post",
                                "descriptor": DESC.copy()})
    for event in trace["events"][4:]:
        event["seq"] += 1
    assert not check_trace(trace)["structurally_consistent"]


def test_boolean_word_and_duplicate_stage_fail():
    trace = sample()
    trace["events"][0]["descriptor"][1] = True
    assert not check_trace(trace)["structurally_consistent"]
    trace = sample()
    trace["events"].append(deepcopy(trace["events"][-1]))
    trace["events"][-1]["seq"] = 6
    assert not check_trace(trace)["structurally_consistent"]


def test_loaded_image_identity_is_required_but_not_authenticated():
    trace = sample()
    trace["loaded_secondary_sha256"] = "not-a-hash"
    assert not check_trace(trace)["structurally_consistent"]
