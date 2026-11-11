import pytest

from tools.x100v_refresh_caller_emulator import expected_boundary, RECOMPUTE, THRESHOLD, TRAP


@pytest.mark.parametrize("level,second,index", [(0, 0, 6), (0, 1, 5), (1, 0, 14),
                                               (1, 1, 13), (2, 0, 22), (2, 1, 21)])
def test_fixed_selected_indices(level, second, index):
    for scenario in ("missing", "clear"):
        for bypass in (0, 1, 2):
            assert expected_boundary(level, second, 4, bypass, scenario, True) == (
                THRESHOLD, 0 if bypass == 1 else index)
            assert expected_boundary(level, second, 2, bypass, scenario, True) == (
                THRESHOLD, 0 if bypass == 1 else index)
            assert expected_boundary(level, second, 2, bypass, scenario, False) == (
                THRESHOLD, 0 if bypass == 1 else index)


@pytest.mark.parametrize("bypass,expected", [(0, (TRAP, None)), (1, (THRESHOLD, 0)), (2, (TRAP, None))])
def test_stock_missing_key_and_bypass(bypass, expected):
    assert expected_boundary(0, 0, 4, bypass, "clear", False) == expected


def test_recompute_stops_before_selected_lookup():
    for scenario in ("recompute", "valid"):
        for aspect in (2, 4):
            for patched in (False, True):
                assert expected_boundary(0, 0, aspect, 0, scenario, patched) == (RECOMPUTE, None)


def test_valid_state_rejects_unexecuted_bypass():
    with pytest.raises(ValueError, match="bypass zero"):
        expected_boundary(0, 0, 4, 1, "valid", True)


@pytest.mark.parametrize("args", [(3, 0, 4, 0, "clear", True), (0, 2, 4, 0, "clear", True),
                                   (0, 0, 3, 0, "clear", True), (0, 0, 4, 3, "clear", True),
                                   (0, 0, 4, 0, "preserve", True), (True, 0, 4, 0, "clear", True),
                                   (0, 0, 4, 0, "clear", 1)])
def test_rejects_outside_fixture_domain(args):
    with pytest.raises(ValueError):
        expected_boundary(*args)
