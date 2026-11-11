import pytest
from fractions import Fraction

from tools.x100v_estimate_leaf_emulator import VECTORS, execute, verify_defaults, DEFAULTS_SIZE


def test_estimate_leaf_rejects_unidentified_code_before_execution():
    with pytest.raises(ValueError, match="unrecognized primary"):
        execute(b"unknown", b"unknown", 6240, 2304, 32)


@pytest.mark.parametrize("data", [b"", b"\x00" * DEFAULTS_SIZE])
def test_defaults_rejects_unknown_size_or_digest(data):
    with pytest.raises(ValueError, match="unrecognized configuration defaults"):
        verify_defaults(data)


@pytest.mark.parametrize("vector", VECTORS)
def test_fixed_reference_vectors_against_rational_area(vector):
    # This verifies fixture arithmetic only; actual ARM runs have a separate report.
    _, width, stock_height, xpan_height, stock_costs, xpan_cost = vector
    for coefficient, expected in zip((20, 21, 32, 48), stock_costs):
        assert int(Fraction(width * stock_height * coefficient, 80)) + 12288 == expected
    assert int(Fraction(width * xpan_height * 32, 80)) + 12288 == xpan_cost
    assert stock_costs[0] < xpan_cost <= stock_costs[1]
