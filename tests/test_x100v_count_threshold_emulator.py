import pytest

from tools.x100v_count_threshold_emulator import fixtures, RANGES, FILTER_VECTORS
from tools.fuji_xpan_validation import SOURCES


def test_fixed_fixture_pairing_and_counts():
    rows = fixtures()
    assert len(rows) == 58
    assert len({(r["name"], r["aspect"]) for r in rows}) == 58
    for a, b in zip(rows[::2], rows[1::2]):
        first, second = bytes.fromhex(a["descriptor_hex"]), bytes.fromhex(b["descriptor_hex"])
        assert a["aspect"] == 2 and b["aspect"] == 4
        assert first[:6] == second[:6] and first[7:] == second[7:]
        assert (first[6], second[6]) == (2, 4)
        assert a["expected"] == b["expected"]


@pytest.mark.parametrize("name,expected", [
    ("ordinary", 1), ("paired-flags", 2), ("paired-flags-bypass", 1),
    ("type25", 2), ("type25-control", 1), ("type26", 2), ("type29", 2),
    ("type31", 2), ("normalized-bypass", 1), ("zero-mode-word", 1),
    ("max-mode-word", 0xFFFFFFFF), ("mode-5-flag", 7), ("mode-5-no-flag", 1),
    ("mode-6-no-flag", 7), ("mode-8-flag", 1), ("mode-11-no-flag", 1),
])
def test_independent_expected_fixture_values(name, expected):
    assert [row["expected"] for row in fixtures() if row["name"] == name] == [expected, expected]


def test_all_executable_ranges_have_whole_range_pins():
    pins = SOURCES["x100v_3_01"]["preview_count_threshold_ranges"]
    assert {(a, a+size) for a, (size, _) in pins.items()} == set(RANGES)


@pytest.mark.parametrize("selected,minimum,required,out_selected,out_minimum", FILTER_VECTORS)
def test_fixed_filter_vectors_against_unsigned_rule(selected, minimum, required, out_selected, out_minimum):
    assert out_selected == (selected if selected >= required else 0)
    assert out_minimum == (minimum if minimum >= required else 0)
