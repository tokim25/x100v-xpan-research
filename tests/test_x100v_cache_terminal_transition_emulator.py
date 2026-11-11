import pytest

from tools.x100v_cache_terminal_transition_emulator import reference_payload, reference_control


@pytest.mark.parametrize("status,value,expected", [
    (0, 0, (0, 0)), (0, 1, (1, 0)), (0, 0xFFFFFFFF, (0xFFFFFFFF, 0)),
    (1, 0, (0, 0)), (1, 1, (0, 0)), (1, 0xFFFFFFFF, (0, 0)),
    (255, 0, (0, 0)), (255, 1, (0, 0)), (255, 0xFFFFFFFF, (0, 0)),
])
def test_fixed_payload_vectors(status, value, expected):
    assert reference_payload(status, value) == expected


@pytest.mark.parametrize("status,value", [
    (-1, 0), (256, 0), (True, 0), (0, -1), (0, 0x100000000), (0, False),
])
def test_reject_out_of_domain(status, value):
    with pytest.raises(ValueError):
        reference_payload(status, value)


@pytest.mark.parametrize("mode,before,slots,after", [
    ("missing", 10, [15, 15, 15, 15, 15], 10),
    ("unchanged10", 10, [15, 15, 15, 15, 15], 10),
    ("unchanged4", 4, [4, 15, 15, 15, 15], 4),
    ("changed", 15, [15, 15, 15, 15, 15], 10),
])
def test_fixed_control_vectors(mode, before, slots, after):
    assert reference_control(mode) == (before, slots, after)


def test_control_rejects_unknown_fixture():
    with pytest.raises(ValueError):
        reference_control("successful-hardware")
