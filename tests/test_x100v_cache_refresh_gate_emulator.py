import pytest
from tools.x100v_cache_refresh_gate_emulator import reference_action, gate_descriptor
from tools.fuji_xpan_validation import SOURCES, verify_arm_words
import struct


@pytest.mark.parametrize("aspect", [2, 4])
def test_aspect_is_byte_six_not_byte_five(aspect):
    descriptor = gate_descriptor(aspect)
    assert len(descriptor) == 36
    assert descriptor[:6] == bytes(6)
    assert descriptor[6] == aspect
    assert descriptor[7:] == bytes(29)


@pytest.mark.parametrize("aspect", [True, -1, 0, 3, 256])
def test_invalid_aspect(aspect):
    with pytest.raises(ValueError):
        gate_descriptor(aspect)


@pytest.mark.parametrize("flag,success,bits,expected", [
    (0, True, 0, "preserve"), (2, True, 0, "preserve"), (255, False, 1, "preserve"),
    (1, False, 0, "clear"), (1, True, 1, "clear"), (1, True, 0xFFFFFFFF, "clear"),
    (1, True, 0, "recompute"), (1, True, 2, "recompute"), (1, True, 0xFFFFFFFE, "recompute"),
])
def test_independent_fixed_gate_vectors(flag, success, bits, expected):
    assert reference_action(flag, success, bits) == expected


def test_each_refresh_instruction_pin_detects_mutation():
    pins = SOURCES["x100v_3_01"]["preview_cache_refresh_gate_primary_words"]
    start = min(pins)
    data = bytearray(max(pins)+4-start)
    for address, value in pins.items():
        struct.pack_into("<I", data, address-start, value)
    verify_arm_words(data, start, pins)
    for address in pins:
        changed = bytearray(data)
        changed[address-start] ^= 1
        with pytest.raises(ValueError):
            verify_arm_words(changed, start, pins)
