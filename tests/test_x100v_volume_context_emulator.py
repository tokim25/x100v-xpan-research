import pytest

from tools.x100v_volume_context_emulator import reference_cost, reference_count, UNITS
from tools.x100v_estimate_wrapper_emulator import VECTORS
from tools.x100v_estimate_leaf_emulator import verify_volume


@pytest.mark.parametrize("vector", VECTORS)
def test_independent_cost_oracle_matches_retained_fixed_vectors(vector):
    _, width, old_height, new_height, _, extra_pairs = vector
    for (mode, flag), pair in zip(((0, 0), (0, 1), (1, 0), (1, 1)), extra_pairs):
        assert reference_cost(width, old_height, 48 if mode == 0 else 32, flag, 16384) == pair[0]
        assert reference_cost(width, new_height, 32, flag, 16384) == pair[1]


@pytest.mark.parametrize("unit,expected", ((512, 5874688), (4096, 5877760), (16384, 5881856),
                                          (32768, 5898240), (65536, 5898240), (0, 0)))
def test_fixed_l_xpan_flag_zero_units(unit, expected):
    # Exact cost before rounding: 6240*2304*32/80 +12288+46080+65536 = 5874688.
    assert reference_cost(6240, 2304, 32, 0, unit) == expected


@pytest.mark.parametrize("unit", UNITS)
def test_small_units_preserve_prior_one_kib_rounding(unit):
    value = reference_cost(6240, 2304, 32, 0, unit)
    assert value % unit == 0
    assert value >= 5874688


def test_count_thresholds_and_invalid_cost():
    assert [reference_count(10, 20, capacity, 0) for capacity in (0, 19, 20, 39, 40, 59, 60)] == [0, 0, 1, 1, 2, 2, 0]
    assert reference_count(0, 20) == reference_count(10, 0) == 0


def test_volume_image_requires_exact_identity():
    with pytest.raises(ValueError, match="unrecognized volume"):
        verify_volume(bytes(0x2AD20))
