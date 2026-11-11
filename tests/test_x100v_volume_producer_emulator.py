import pytest

from tools.x100v_volume_producer_emulator import VECTORS


@pytest.mark.parametrize("first,second,unit,normalized", VECTORS)
def test_fixed_product_and_separate_zero_normalization(first, second, unit, normalized):
    assert first * second == unit
    assert normalized == (512 if first == 0 else first)
    assert unit <= 65536


def test_zero_field_does_not_inherit_other_fields_default():
    assert (0, 32, 0, 512) in VECTORS
    assert (0, 32, 16384, 512) not in VECTORS


def test_same_unit_has_distinct_record_factorizations():
    assert [(a, b) for a, b, unit, _ in VECTORS if unit == 32768] == [(512, 64), (4096, 8)]
