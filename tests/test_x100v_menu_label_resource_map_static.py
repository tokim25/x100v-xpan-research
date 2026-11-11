"""Pin IMAGE SIZE label resources without claiming a live menu rendering."""

import hashlib
import struct
from pathlib import Path

import pytest

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_update_package import read_primary


PRIMARY_LOAD = 0x00F21000
SECONDARY_LOAD = 0x01BA0000
DESCRIPTORS = (
    # Descriptor, index of L/M/S 16:9 rows, expected label-resource word.
    (0x01385554, (4, 7, 10), (0xFF000777, 0xFF000774, 0xFF00077A)),
    (0x0139881C, (4, 7, 10), (0xFF00081A, 0xFF000817, 0xFF00081D)),
    (0x013BBD14, (4, 7, 10), (0xFF00094C, 0xFF000949, 0xFF00094F)),
)
VALUE_IDS = (2, 9, 16)
NAME_TABLE = 0x021CE7C8


def _word(data: bytes, load: int, address: int) -> int:
    return struct.unpack_from("<I", data, address - load)[0]


def test_stock_16x9_menu_entries_and_existing_6524_string_keys_are_distinct():
    source = SOURCES["x100v_3_01"]
    primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(primary).hexdigest() == source["primary_sha256"]
    assert hashlib.sha256(secondary).hexdigest() == source["secondary_sha256"]

    for descriptor, indices, expected_resources in DESCRIPTORS:
        values = _word(primary, PRIMARY_LOAD, descriptor + 0x14)
        items = _word(primary, PRIMARY_LOAD, descriptor + 0x18)
        assert tuple(_word(primary, PRIMARY_LOAD, values + 8 * i) for i in indices) == VALUE_IDS
        resource_offset = 4 if descriptor == 0x013BBD14 else (16 if descriptor == 0x0139881C else 8)
        assert tuple(_word(primary, PRIMARY_LOAD, items + 48 * i + resource_offset)
                     for i in indices) == expected_resources

    # These are name-table entries, not proven numeric menu-resource IDs.
    pairs = (
        (0x021CE7D4, 0x021E43F8, b"UI_PXL_L_16_9"),
        (0x021CE7E4, 0x021E4418, b"UI_PXL_L_65_24"),
        (0x021CE80C, 0x021E4468, b"UI_PXL_M_16_9"),
        (0x021CE81C, 0x021E4488, b"UI_PXL_M_65_24"),
        (0x021CE844, 0x021E44D8, b"UI_PXL_S_16_9"),
        (0x021CE854, 0x021E44F8, b"UI_PXL_S_65_24"),
    )
    for pointer_address, string_address, value in pairs:
        assert _word(secondary, SECONDARY_LOAD, pointer_address) == string_address
        offset = string_address - SECONDARY_LOAD
        assert secondary[offset:offset + len(value) + 1] == value + b"\0"


def test_merged_code4_candidate_changes_value_ids_but_not_item_label_bytes():
    candidate_path = Path("out/code4-merged-offline-20261106-a/candidate-update-NOT-FOR-CARD.DAT")
    if not candidate_path.exists():
        pytest.skip(f"local evidence missing from git-ignored out/: {candidate_path}")
    stock = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    candidate_dat = candidate_path.read_bytes()
    assert hashlib.sha256(candidate_dat).hexdigest() == (
        "20fd97a054f66502a0f58fa42c0adcc24e14377f6d02df75dcfd197eed4b9cf5"
    )
    candidate = read_primary(candidate_dat)[1]
    assert hashlib.sha256(candidate).hexdigest() == (
        "0cb9fb15e124205b6d7f745568f2f6373f3e3a4abb03a9b05c6e6cbf025b7e53"
    )
    for descriptor, indices, _ in DESCRIPTORS:
        stock_values = _word(stock, PRIMARY_LOAD, descriptor + 0x14)
        candidate_values = _word(candidate, PRIMARY_LOAD, descriptor + 0x14)
        assert stock_values == candidate_values
        assert tuple(_word(candidate, PRIMARY_LOAD, candidate_values + 8 * i)
                     for i in indices) == (4, 11, 18)
        items = _word(stock, PRIMARY_LOAD, descriptor + 0x18)
        assert items == _word(candidate, PRIMARY_LOAD, descriptor + 0x18)
        assert candidate[items - PRIMARY_LOAD:items - PRIMARY_LOAD + 13 * 48] == (
            stock[items - PRIMARY_LOAD:items - PRIMARY_LOAD + 13 * 48]
        )


def test_size_value_ids_align_with_stock_named_aspect_table():
    """Establish table-index alignment, not the menu's rendered label route."""
    source = SOURCES["x100v_3_01"]
    primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(primary).hexdigest() == source["primary_sha256"]
    assert hashlib.sha256(secondary).hexdigest() == source["secondary_sha256"]

    expected = (
        (1, b"UI_PXL_L_3_2", 0x021E43E8),
        (2, b"UI_PXL_L_16_9", 0x021E43F8),
        (3, b"UI_PXL_L_1_1", 0x021E4408),
        (4, b"UI_PXL_L_65_24", 0x021E4418),
        (8, b"UI_PXL_M_3_2", 0x021E4458),
        (9, b"UI_PXL_M_16_9", 0x021E4468),
        (10, b"UI_PXL_M_1_1", 0x021E4478),
        (11, b"UI_PXL_M_65_24", 0x021E4488),
        (15, b"UI_PXL_S_3_2", 0x021E44C8),
        (16, b"UI_PXL_S_16_9", 0x021E44D8),
        (17, b"UI_PXL_S_1_1", 0x021E44E8),
        (18, b"UI_PXL_S_65_24", 0x021E44F8),
    )
    assert tuple(NAME_TABLE + 8 * (value_id - 1) for value_id in (2, 9, 16)) == (
        0x021CE7D0, 0x021CE808, 0x021CE840
    )
    assert tuple(NAME_TABLE + 8 * (value_id - 1) for value_id in (4, 11, 18)) == (
        0x021CE7E0, 0x021CE818, 0x021CE850
    )
    for value_id, name, pointer in expected:
        row = NAME_TABLE + 8 * (value_id - 1)
        assert _word(secondary, SECONDARY_LOAD, row) == value_id - 1
        assert _word(secondary, SECONDARY_LOAD, row + 4) == pointer
        offset = pointer - SECONDARY_LOAD
        assert secondary[offset:offset + len(name) + 1] == name + b"\0"

    # The three visible stock aspect groups use the corresponding value IDs.
    for descriptor, _, _ in DESCRIPTORS:
        values = _word(primary, PRIMARY_LOAD, descriptor + 0x14)
        assert tuple(_word(primary, PRIMARY_LOAD, values + 8 * i) for i in range(3, 12)) == (
            1, 2, 3, 8, 9, 10, 15, 16, 17
        )
