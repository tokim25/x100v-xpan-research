"""One-word converter experiment: synthetic outputs, not live capture."""
from pathlib import Path

from tools.x100v_develop_aspect_case_probe import (
    CASE, candidate, execute, execute_converter_aspect,
)


def test_one_word_converter_patch_changes_only_16x9_slots():
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    modified = candidate(stock)
    assert len(stock) == len(modified)
    assert [i for i, (a, b) in enumerate(zip(stock, modified)) if a != b] == [CASE - 0x01BA0000]
    original = [execute(stock, value)[0] for value in range(1, 10)]
    revised = [execute(modified, value)[0] for value in range(1, 10)]
    assert original == [1, 2, 3] * 3
    assert revised == [1, 4, 3] * 3
    # The only observed record-builder seeds are 4 and 7: neither is changed.
    assert [revised[index-1] for index in (4, 7)] == [1, 1]


def test_full_converter_aspect_gates_and_two_modes():
    stock = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    modified = candidate(stock)
    for mode in (0, 1):
        for value in range(1, 10):
            original, original_path = execute_converter_aspect(stock, value, mode)
            revised, revised_path = execute_converter_aspect(modified, value, mode)
            expected_prefix = bytes((0, 2)) if mode == 0 else bytes((1, 2 - (value - 1) // 3))
            assert original == expected_prefix + bytes(((value - 1) % 3 + 1,))
            assert revised == expected_prefix + bytes((4 if value in (2, 5, 8) else (value - 1) % 3 + 1,))
            assert 0x01F6E3F0 in original_path  # record +0x209, both caller modes
            assert 0x01F6E408 in original_path  # record +0x205 == 7 gate
            assert original_path == revised_path
