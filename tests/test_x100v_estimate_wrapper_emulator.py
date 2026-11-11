from fractions import Fraction
import math

import pytest

from tools.x100v_estimate_wrapper_emulator import VECTORS
from tools.x100v_estimate_leaf_emulator import VECTORS as LEAF_VECTORS


@pytest.mark.parametrize("vector", VECTORS)
def test_wrapper_fixed_vectors_against_independent_rational_bounds(vector):
    name, width, old_height, new_height, plain, extra_pairs = vector
    leaf = next(row for row in LEAF_VECTORS if row[0] == name)
    for extra, expected_pairs in ((False, plain), (True, extra_pairs)):
        for (mode, multiplier), expected in zip(((0, 0), (0, 1), (1, 0), (1, 1)), expected_pairs):
            coefficient = 48 if mode == 0 else 32
            costs = (math.floor(Fraction(width * old_height * coefficient, 80)) + 12288,
                     math.floor(Fraction(width * new_height * 32, 80)) + 12288)
            assert costs[1] == leaf[5]
            for cost, fixed in zip(costs, expected):
                exact = Fraction(cost * 5, 4) if multiplier else Fraction(cost)
                overhead = 65536 + (153600 if multiplier else 0)
                if extra:
                    overhead += 57600 if multiplier else 46080
                # Inputs and integral scaled results below 2**24 are exact
                # float32 values. Other scaled results can move by at most
                # one integer. Both bounds must match the final bucket.
                assert cost < 2**24 and exact < 2**24
                error = int(bool(multiplier) and exact.denominator != 1)
                low = math.floor(exact) - error
                high = math.ceil(exact) + error
                for value in (low, high):
                    assert ((value + overhead + 16383) // 16384) * 16384 == fixed
