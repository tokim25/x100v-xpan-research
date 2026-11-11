import pytest

from tools.x100v_status_record_copy_emulator import (
    RECORDS, RECORD_SIZE, reference_record, verify_primary,
)


@pytest.mark.parametrize("slot", (0, 1, 7))
def test_fixed_record_stride(slot):
    assert reference_record(slot) == RECORDS + slot * RECORD_SIZE


@pytest.mark.parametrize("slot", (-1, 8, True, 1.0))
def test_rejects_out_of_scope_slot(slot):
    with pytest.raises(ValueError):
        reference_record(slot)


def test_rejects_unknown_primary():
    with pytest.raises(ValueError, match="unrecognized"):
        verify_primary(b"not firmware")
