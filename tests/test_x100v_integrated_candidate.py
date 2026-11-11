import pytest

from tools.x100v_integrated_candidate import integrated_writes


@pytest.mark.parametrize("flags,count", [((False, False, False), 19), ((True, False, False), 20),
                                         ((True, True, False), 27), ((True, True, True), 36)])
def test_revisions_have_expected_write_counts(flags, count):
    assert len(integrated_writes(*flags)) == count


def test_revision_d_writes_do_not_overlap_and_keep_lengths():
    seen = set()
    for w in integrated_writes(True, True, True):
        before, after = bytes.fromhex(w["before_hex"]), bytes.fromhex(w["after_hex"])
        assert len(before) == len(after) > 0
        span = set(range(w["partition_offset"], w["partition_offset"] + len(before)))
        assert not span & seen, w["field"]
        seen |= span


def test_size_rule_tables_add_only_65_24_sizes():
    import struct

    writes = {w["field"]: w for w in integrated_writes(True, True)}
    a = struct.unpack("<13I", bytes.fromhex(writes["size-rule-table-a"]["after_hex"]))
    b = struct.unpack("<13I", bytes.fromhex(writes["size-rule-table-b"]["after_hex"]))
    stock_sizes = {1, 2, 3, 8, 9, 10, 15, 16, 17}
    assert a[0] == 151 and set(a[1:]) == stock_sizes | {4, 11, 18}
    assert list(a[1:]) == sorted(a[1:])
    assert b == (1,) + (22,) * 12
    assert writes["rule-count"]["after_hex"] == "0d20a0e3"


def test_menu_value_lists_swap_only_16_9_for_65_24():
    import struct

    lists = [w for w in integrated_writes(True, True, True) if "-menu-size-" in w["field"]]
    pairs = [(struct.unpack("<I", bytes.fromhex(w["before_hex"]))[0],
              struct.unpack("<I", bytes.fromhex(w["after_hex"]))[0]) for w in lists]
    assert sorted(pairs) == sorted([(2, 4), (9, 11), (16, 18)] * 3)
    starts = {w["partition_offset"] - 8 * i for i, w in zip([4, 7, 10] * 3, lists)}
    assert len(starts) == 3
