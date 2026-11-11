import pytest

from tools.x100v_preview_cache_export_emulator import (
    BASES, COUNT, BYTE_COUNT, reference_slot, verify_images,
)
from tools.fuji_xpan_validation import SOURCES, verify_arm_words, verify_data_words
import struct


@pytest.mark.parametrize("base,first,last", [
    (0x01734A8C, 0x01734A94, 0x01734B74),
    (0x02EEA24C, 0x02EEA254, 0x02EEA334),
])
def test_fixed_array_boundaries(base, first, last):
    assert reference_slot(base, 0) == first
    assert reference_slot(base, 56) == last
    assert last + 4 - first == BYTE_COUNT == 228
    assert COUNT == 57


@pytest.mark.parametrize("base,index", [(0, 0), (BASES[0], -1), (BASES[1], 57), (BASES[0], True)])
def test_reject_unproved_array_or_index(base, index):
    with pytest.raises(ValueError):
        reference_slot(base, index)


def test_reject_unrecognized_images_before_execution():
    with pytest.raises(ValueError, match="primary"):
        verify_images(b"not firmware", b"")


@pytest.mark.parametrize("image,kind", [("primary", "words"), ("secondary", "words"),
                                       ("primary", "data_words"), ("secondary", "data_words")])
def test_each_export_pin_rejects_mutation(image, kind):
    # Synthetic pin-checker regression only, not firmware execution evidence.
    pins = SOURCES["x100v_3_01"][f"preview_runtime_array_cache_export_{image}_{kind}"]
    start, end = min(pins), max(pins) + 4
    data = bytearray(end - start)
    for address, value in pins.items():
        struct.pack_into("<I", data, address-start, value)
    check = verify_data_words if kind == "data_words" else verify_arm_words
    check(data, start, pins)
    for address in pins:
        changed = bytearray(data)
        changed[address-start] ^= 1
        with pytest.raises(ValueError):
            check(changed, start, pins)
