import pytest

from tools.x100v_activity_backup import backup_log, redact_log


def test_redacts_only_private_field_values():
    source = b'H:"XLOG",MSN:"camera-serial",FWVER:"0301"\nR:"CAP",UNQID:"shot-id"\n'
    result = redact_log(source)
    assert result == b'H:"XLOG",MSN:"[REDACTED]",FWVER:"0301"\nR:"CAP",UNQID:"[REDACTED]"\n'
    assert b"camera-serial" not in result and b"shot-id" not in result


@pytest.mark.parametrize("source", [b'MSN:12345', b'UNQID:12345', b'MSN:"unterminated'])
def test_rejects_unknown_private_field_syntax(source):
    with pytest.raises(ValueError):
        redact_log(source)


def test_backup_verifies_redacted_readback_and_refuses_overwrite(tmp_path):
    source = tmp_path / "source.LOG"
    destination = tmp_path / "backup" / "source.LOG"
    source.write_bytes(b'MSN:"private"\n')
    report = backup_log(source, destination)
    assert report["redacted_readback_matches_source_transformation"]
    assert report["redaction_fields"] == {"MSN": 1, "UNQID": 0}
    assert destination.read_bytes() == b'MSN:"[REDACTED]"\n'
    with pytest.raises(FileExistsError):
        backup_log(source, destination)
