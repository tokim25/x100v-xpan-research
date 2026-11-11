"""Back up a Fuji ACTIVITY log without copying camera identifiers.

The source digest is recorded for audit, while the stored log has MSN and
UNQID values redacted. No unredacted log bytes are written outside the card.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PRIVATE_KEYS = (b"MSN", b"UNQID")
FIELD = re.compile(rb'(?<![A-Z])(?P<key>MSN|UNQID):"[^"\r\n]*"')


def redact_log(data: bytes) -> bytes:
    redacted = FIELD.sub(lambda match: match.group("key") + b':"[REDACTED]"', data)
    for key in PRIVATE_KEYS:
        if len(re.findall(rb'(?<![A-Z])' + key + rb':', data)) != len(
            re.findall(rb'(?<![A-Z])' + key + rb':"\[REDACTED\]"', redacted)
        ):
            raise ValueError(f"unrecognized {key.decode()} field syntax")
    return redacted


def backup_log(source: Path, destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError(destination)
    data = source.read_bytes()
    redacted = redact_log(data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(redacted)
    if destination.read_bytes() != redact_log(source.read_bytes()):
        raise OSError("redacted log readback differs from source transformation")
    return {
        "source_name": source.name,
        "source_size": len(data),
        "source_sha256_before_redaction": hashlib.sha256(data).hexdigest(),
        "backup_size": len(redacted),
        "backup_sha256": hashlib.sha256(redacted).hexdigest(),
        "redaction_fields": {key.decode(): len(re.findall(rb'(?<![A-Z])' + key + rb':', data))
                             for key in PRIVATE_KEYS},
        "redacted_readback_matches_source_transformation": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(backup_log(args.source, args.destination), indent=2))


if __name__ == "__main__":
    main()
