"""Create hash-guarded, header-model-only RAF controls for offline reader tests.

These are deliberately invalid camera-identity combinations, never camera
output or candidates for SD boot. No embedded EXIF/MakerNote or RAW bytes move.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

HEADER_MODEL = slice(0x1C, 0x3C)
MAGIC = b"FUJIFILMCCD-RAW "
X100V_5I_SHA = "becba1f1ade73dcf4ceed188eea0401c4964324088f0661c4c851c22bf76c298"
GFX_6524_SHA = "a01db40177a463281e9ea5d6a3866135af7fbd5218a98030baed064b5b5ad973"


def replace_header_model(data: bytes, expected: str, replacement: str) -> bytes:
    if data[:16] != MAGIC:
        raise ValueError("not a RAF")
    original = data[HEADER_MODEL]
    if original.split(b"\0", 1)[0] != expected.encode("ascii"):
        raise ValueError("unexpected RAF header model")
    encoded = replacement.encode("ascii")
    if not encoded or len(encoded) >= len(original):
        raise ValueError("replacement model does not fit header field")
    changed = data[:HEADER_MODEL.start] + encoded.ljust(len(original), b"\0") + data[HEADER_MODEL.stop:]
    if len(changed) != len(data):
        raise AssertionError("RAF length changed")
    if changed[:HEADER_MODEL.start] != data[:HEADER_MODEL.start] or changed[HEADER_MODEL.stop:] != data[HEADER_MODEL.stop:]:
        raise AssertionError("non-model RAF bytes changed")
    return changed


def checked_control(source: Path, source_sha: str, expected: str, replacement: str, output: Path) -> dict:
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source_sha:
        raise ValueError(f"unrecognized source RAF: {digest}")
    changed = replace_header_model(data, expected, replacement)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    output.write_bytes(changed)
    if output.read_bytes() != changed:
        raise AssertionError("output readback mismatch")
    return {"source": str(source), "source_sha256": digest,
            "output": str(output), "output_sha256": hashlib.sha256(changed).hexdigest(),
            "changed_offsets": [i for i in range(HEADER_MODEL.start, HEADER_MODEL.stop) if data[i] != changed[i]],
            "scope": "synthetic RAF header model only; not valid camera identity or firmware output"}


def main() -> None:
    import json

    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("source", type=Path)
    p.add_argument("source_sha256")
    p.add_argument("expected_model")
    p.add_argument("replacement_model")
    p.add_argument("output", type=Path)
    a = p.parse_args()
    print(json.dumps(checked_control(a.source, a.source_sha256, a.expected_model,
                                     a.replacement_model, a.output), indent=2))


if __name__ == "__main__":
    main()
