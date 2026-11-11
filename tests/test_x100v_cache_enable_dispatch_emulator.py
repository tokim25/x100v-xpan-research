import hashlib

import pytest

from tools.fuji_xpan_validation import verify_hashed_ranges
from tools.x100v_cache_enable_dispatch_emulator import (
    ACCEPT, DIAGNOSTIC, REFRESH_CALLBACK, reference_dispatch, reference_message, reference_nested22,
)


@pytest.mark.parametrize("state,message,second,first,callback", [
    (0, 0, 0, 1, 0x1E6ABE4), (1, 0x1224, 1, 1, 0x1E6AC00),
    (2, 0x1224, 1, 4, 0x1E6AC00), (3, 0, 0, 0, 0x1E6ABB4),
    (3, 65535, 1, 0, 0x1E6ABCC), (4, 0x1223, 1, 3, 0x1E6AC68),
    (4, 0x1224, 0, 2, 0x1E6AC00), (4, 0x1224, 1, 2, REFRESH_CALLBACK),
    (4, 0x122B, 1, 2, REFRESH_CALLBACK), (4, 0x122C, 0, 3, 0x1E6ABB4),
    (255, 0x1224, 1, 4, 0x1E6AC00),
])
def test_fixed_dispatch_vectors(state, message, second, first, callback):
    assert reference_dispatch(state, message, second) == (first, callback)


def test_message_guard_is_narrower_than_dispatch_range():
    assert [m for m in range(65536) if reference_message(m) == ACCEPT] == [
        0x1224, 0x1226, 0x1228, 0x122A]
    for m in (0x1225, 0x1227, 0x1229, 0x122B):
        assert reference_dispatch(4, m, 1)[1] == REFRESH_CALLBACK
        assert reference_message(m) == DIAGNOSTIC


@pytest.mark.parametrize("outer,inner,expected", [
    (0, 0, 0x1E7FDA8), (0, 1, 0x1E7FDA8),
    (1, 0, 0x1E6AC00), (1, 1, REFRESH_CALLBACK),
    (2, 0, 0x1E6AC00), (2, 1, REFRESH_CALLBACK),
])
def test_nested_dispatch_fixed_matrix(outer, inner, expected):
    for message in range(0x1224, 0x122C):
        assert reference_nested22(message, outer, inner) == expected


@pytest.mark.parametrize("message,outer,inner", [
    (0x1223, 1, 1), (0x122C, 1, 1), (0x1224, 3, 1),
    (0x1224, -1, 1), (0x1224, True, 1), (0x1224, 1, 2),
])
def test_nested_dispatch_rejects_unmodeled_domain(message, outer, inner):
    with pytest.raises(ValueError):
        reference_nested22(message, outer, inner)


@pytest.mark.parametrize("state,message,second", [
    (-1, 0, 0), (256, 0, 0), (4, -1, 1), (4, 65536, 1),
    (4, 0x1224, 2), (4, 0x1224, -1), (True, 0, 0),
])
def test_reject_out_of_domain(state, message, second):
    with pytest.raises(ValueError):
        reference_dispatch(state, message, second)


def test_hashed_ranges_check_all_bytes_and_bounds():
    data = bytes(range(32))
    pins = {0x1000: (32, hashlib.sha256(data).hexdigest())}
    verify_hashed_ranges(data, 0x1000, pins)
    for i in range(len(data)):
        mutated = bytearray(data)
        mutated[i] ^= 1
        with pytest.raises(ValueError):
            verify_hashed_ranges(mutated, 0x1000, pins)
    for short, load in ((data[:-1], 0x1000), (data, 0x1001)):
        with pytest.raises(ValueError):
            verify_hashed_ranges(short, load, pins)
