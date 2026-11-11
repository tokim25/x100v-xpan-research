"""Validate a future RAF descriptor trace; never authenticate its origin.

No firmware instrumentation, camera I/O, RAF pixel inspection, or SD write.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES

STAGES = {
    "event76_request", "command14_post", "command0f_post",
    "command2f_pre", "raf_object", "save_row2",
}
REQUIRED = STAGES - {"command0f_post"}


def u32(value: object) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def check_trace(trace: dict) -> dict:
    """Check internal same-context/order/pair consistency, not physical truth."""
    issues: list[str] = []
    if not isinstance(trace, dict):
        return {"structurally_consistent": False, "issues": ["trace must be an object"]}
    if trace.get("format") != "x100v-raf-handoff-v1":
        issues.append("format mismatch")
    if trace.get("stock_secondary_sha256") != SOURCES["x100v_3_01"]["secondary_sha256"]:
        issues.append("stock secondary identity mismatch")
    loaded_sha = trace.get("loaded_secondary_sha256")
    if (not isinstance(loaded_sha, str) or len(loaded_sha) != 64
            or any(c not in "0123456789abcdef" for c in loaded_sha)):
        issues.append("loaded secondary SHA-256 missing or malformed")
    events = trace.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 64:
        issues.append("events must contain 1..64 records")
        return {"structurally_consistent": False, "issues": issues}

    by_stage: dict[str, dict] = {}
    previous_seq = -1
    identity = None
    latest_descriptor = None
    latest_writer = None
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            issues.append(f"event {index}: not an object")
            continue
        stage = event.get("stage")
        if stage not in STAGES:
            issues.append(f"event {index}: unknown stage")
            continue
        if stage in by_stage:
            issues.append(f"event {index}: duplicate {stage}")
        by_stage[stage] = event
        seq = event.get("seq")
        if not u32(seq) or seq <= previous_seq:
            issues.append(f"event {index}: sequence not strictly increasing")
        else:
            previous_seq = seq
        fields = (event.get("epoch"), event.get("slot"),
                  event.get("context_root"), event.get("record_id"))
        if not all(u32(x) for x in fields) or fields[1] > 127 or fields[2] == 0:
            issues.append(f"event {index}: invalid context identity")
        elif identity is None:
            identity = fields
        elif fields != identity:
            issues.append(f"event {index}: cross-context or cross-epoch stage")

        if stage == "event76_request":
            if event.get("group") not in (15, 46, 66):
                issues.append("event76_request: unsupported or absent group")
        elif stage in ("command14_post", "command0f_post", "command2f_pre"):
            descriptor = event.get("descriptor")
            if (not isinstance(descriptor, list) or len(descriptor) != 7
                    or not all(u32(x) for x in descriptor)):
                issues.append(f"{stage}: expected seven unsigned words")
            elif stage == "command2f_pre":
                if event.get("mode") != 2 or event.get("arg3") != "context+0x48":
                    issues.append("command2f_pre: mode-2 +0x48 route not observed")
                if descriptor != latest_descriptor:
                    issues.append("command2f_pre: descriptor differs from last writer")
            else:
                latest_descriptor = descriptor
                latest_writer = stage
        elif stage in ("raf_object", "save_row2"):
            if not u32(event.get("pointer")) or not u32(event.get("length")):
                issues.append(f"{stage}: invalid pointer/length")
            if stage == "raf_object" and event.get("object_index") != 0:
                issues.append("raf_object: not the first object")
            if stage == "save_row2" and event.get("row") != 2:
                issues.append("save_row2: selected row is not 2")

    for stage in REQUIRED:
        if stage not in by_stage:
            issues.append(f"missing {stage}")
    positions = {event["stage"]: i for i, event in enumerate(events)
                 if isinstance(event, dict) and event.get("stage") in STAGES}
    chain = ("command14_post", "command2f_pre", "raf_object", "save_row2")
    if all(stage in positions for stage in chain):
        if [positions[stage] for stage in chain] != sorted(positions[stage] for stage in chain):
            issues.append("required descriptor/RAF/save order not observed")
    if "event76_request" in positions and "command2f_pre" in positions:
        if positions["event76_request"] >= positions["command2f_pre"]:
            issues.append("event 76 did not precede command 2f")
    if "command0f_post" in positions and "command2f_pre" in positions:
        if positions["command0f_post"] >= positions["command2f_pre"]:
            issues.append("command 0f occurred after command 2f")
    descriptor = by_stage.get("command2f_pre", {}).get("descriptor")
    if isinstance(descriptor, list) and len(descriptor) == 7 and all(u32(x) for x in descriptor):
        expected = (descriptor[1], descriptor[2])
        if expected[0] == 0 or expected[1] == 0:
            issues.append("command2f_pre: empty CFA pointer/length")
        for stage in ("raf_object", "save_row2"):
            event = by_stage.get(stage, {})
            if (event.get("pointer"), event.get("length")) != expected:
                issues.append(f"{stage}: CFA pair differs from command2f descriptor")
    return {
        "structurally_consistent": not issues,
        "issues": issues,
        "group": by_stage.get("event76_request", {}).get("group"),
        "last_descriptor_writer": latest_writer,
        "camera_origin_authenticated": False,
        "raw_crop_or_file_save_proven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    result = check_trace(json.loads(args.trace.read_text(encoding="utf-8")))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["structurally_consistent"] else 1)


if __name__ == "__main__":
    main()
