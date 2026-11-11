import pytest

from tools.x100v_capacity_producer_emulator import VECTORS
from tools.x100v_estimate_wrapper_emulator import VECTORS as WRAPPER_VECTORS


@pytest.mark.parametrize("vector", VECTORS)
def test_fixed_counts_against_independent_wrapper_reference_costs(vector):
    name, _, _, _, expected_modes = vector
    costs = next(row[5] for row in WRAPPER_VECTORS if row[0] == name)
    for mode, expected in enumerate(expected_modes):
        cost_a, cost_b = costs[mode * 2], costs[mode * 2 + 1]
        for side in (0, 1):
            assert 0 < cost_b[side] * 3 <= 100000000
            assert 3 + (100000000 - cost_b[side] * 3) // cost_a[side] == expected[side]
            assert 3 + (2**32 - cost_b[side] * 3) // cost_a[side] >= 17
