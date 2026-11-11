from tools.x100v_ratio_offline_candidate import apply_exact_partition_writes


def test_exact_partition_writes_independent_vector_and_immutability() -> None:
    original = b"abcdefghijklmnop"
    writes = [
        {"partition_offset": 2, "before_hex": "6364", "after_hex": "5859"},
        {"partition_offset": 10, "before_hex": "6b6c", "after_hex": "3939"},
    ]
    candidate = apply_exact_partition_writes(original, writes)
    assert candidate == b"abXYefghij99mnop"
    assert original == b"abcdefghijklmnop"
    assert [index for index, (old, new) in enumerate(zip(original, candidate)) if old != new] == [2, 3, 10, 11]


def test_exact_partition_writes_reject_overlap_stale_bytes_and_bounds() -> None:
    original = b"abcdefgh"
    invalid_plans = [
        [
            {"partition_offset": 1, "before_hex": "6263", "after_hex": "4243"},
            {"partition_offset": 2, "before_hex": "6364", "after_hex": "4344"},
        ],
        [{"partition_offset": 1, "before_hex": "5859", "after_hex": "4243"}],
        [{"partition_offset": 7, "before_hex": "6869", "after_hex": "4849"}],
        [{"partition_offset": -1, "before_hex": "61", "after_hex": "41"}],
        [{"partition_offset": 0, "before_hex": "61", "after_hex": "61"}],
    ]
    for writes in invalid_plans:
        try:
            apply_exact_partition_writes(original, writes)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid exact-byte patch must fail closed")
