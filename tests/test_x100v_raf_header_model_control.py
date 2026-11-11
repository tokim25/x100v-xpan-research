import hashlib

import pytest

from tools.x100v_raf_header_model_control import HEADER_MODEL, MAGIC, replace_header_model


def test_header_model_control_changes_only_exact_field():
    source = bytearray(0x80)
    source[:16] = MAGIC
    source[HEADER_MODEL] = b"X100V".ljust(32, b"\0")
    source[0x54:0x58] = b"RAW!"
    result = replace_header_model(bytes(source), "X100V", "GFX100RF")
    assert result[HEADER_MODEL] == b"GFX100RF".ljust(32, b"\0")
    assert result[:HEADER_MODEL.start] == source[:HEADER_MODEL.start]
    assert result[HEADER_MODEL.stop:] == source[HEADER_MODEL.stop:]
    assert hashlib.sha256(result).digest() != hashlib.sha256(source).digest()


@pytest.mark.parametrize("expected,replacement", [("GFX100RF", "X100V"), ("X100V", ""),
                                                      ("X100V", "A" * 32)])
def test_header_model_control_rejects_wrong_identity_or_size(expected, replacement):
    source = bytearray(0x80)
    source[:16] = MAGIC
    source[HEADER_MODEL] = b"X100V".ljust(32, b"\0")
    with pytest.raises(ValueError):
        replace_header_model(bytes(source), expected, replacement)
