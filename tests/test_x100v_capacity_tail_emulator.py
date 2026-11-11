import pytest

from tools.x100v_capacity_tail_emulator import execute


def test_capacity_tail_rejects_unidentified_code_before_execution():
    with pytest.raises(ValueError, match="unrecognized primary"):
        execute(b"not stock code", b"not kernel code", 1000, 20, 30, 100)
