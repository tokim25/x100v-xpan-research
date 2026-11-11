import struct

import pytest

from tools.x100v_update_package import (
    FLASH_IMAGE_SIZE,
    IMAGE_BASE,
    OUTER_HEADER,
    apply_writes,
    compute_integrity,
    read_partition,
    reseal,
    splice_encode,
    stored_integrity,
    tokenize,
)


def lit(data: bytes) -> bytes:
    assert 0 < len(data) < 0x80
    return bytes([len(data)]) + data


def ref(distance: int, length: int) -> bytes:
    value = (distance << 4) | length
    return bytes([0x80 | (value >> 8), value & 0xFF])


def independent_decode(stream: bytes) -> bytes:
    """Written separately from tools.fuji_firmware_probe.lzss_decode."""
    out = bytearray()
    i = 0
    while i < len(stream):
        head = stream[i]
        if head & 0x80 == 0:
            out += stream[i + 1:i + 1 + head]
            i += 1 + head
            continue
        word = (head << 8 | stream[i + 1]) & 0x7FFF
        i += 2
        back = word >> 4
        for _ in range(word & 0xF):
            out.append(out[len(out) - back])
    return bytes(out)


STREAM = lit(b"ABCDEFGH") + ref(8, 8) + lit(b"xyz") + ref(3, 6) + lit(b"\0") + ref(1, 15) + lit(b"END")


def test_fixture_grammar_matches_independent_decoder():
    decoded = independent_decode(STREAM)
    assert decoded == b"ABCDEFGH" * 2 + b"xyz" * 3 + b"\0" * 16 + b"END"
    assert [t.literal for t in tokenize(STREAM)] == [True, False, True, False, True, False, True]


def test_unchanged_partition_keeps_stream_identical():
    stock = independent_decode(STREAM)
    stream, stats = splice_encode(STREAM, stock, stock)
    assert stream == STREAM
    assert stats["stream_growth_bytes"] == 0


def test_literal_change_keeps_length_and_other_tokens():
    stock = independent_decode(STREAM)
    patched = bytearray(stock)
    patched[len(stock) - 2] = ord("X")
    stream, stats = splice_encode(STREAM, stock, bytes(patched))
    assert len(stream) == len(STREAM)
    assert stream[:-4] == STREAM[:-4]
    assert independent_decode(stream) == bytes(patched)
    assert stats["rewritten_literal_tokens"] == 1


def test_source_change_invalidates_dependent_back_reference_only():
    stock = independent_decode(STREAM)
    patched = bytearray(stock)
    patched[2] = ord("c")  # the first literal; its later copy must not keep reading it
    stream, stats = splice_encode(STREAM, stock, bytes(patched))
    decoded = independent_decode(stream)
    assert decoded == bytes(patched)
    assert decoded[10] == ord("C")  # the copy still holds the stock byte
    assert stats["replaced_back_references"] == 1
    assert stream.endswith(lit(b"xyz") + ref(3, 6) + lit(b"\0") + ref(1, 15) + lit(b"END"))


def test_change_inside_zero_run_breaks_run_reference():
    stock = independent_decode(STREAM)
    patched = bytearray(stock)
    start = stock.index(b"\0" * 16)
    patched[start + 5] = 0x41
    stream, stats = splice_encode(STREAM, stock, bytes(patched))
    assert independent_decode(stream) == bytes(patched)
    assert stats["replaced_back_references"] == 1
    assert stats["stream_growth_bytes"] > 0


def test_long_replacement_is_split_into_legal_literal_runs():
    stock = b"\0" * 300
    stream_in = lit(b"\0") + b"".join(ref(1, 15) for _ in range(19)) + ref(1, 14)
    assert independent_decode(stream_in) == stock
    patched = bytes(range(256)) + b"\0" * 44
    stream, _ = splice_encode(stream_in, stock, patched)
    assert independent_decode(stream) == patched
    assert all(t.length < 0x80 for t in tokenize(stream) if t.literal)


def test_apply_writes_checks_old_bytes_and_overlap():
    base = bytes(range(16))
    write = {"field": "a", "partition_offset": 4, "before_hex": "0405", "after_hex": "aabb"}
    assert apply_writes(base, [write])[4:6] == b"\xaa\xbb"
    with pytest.raises(ValueError, match="old bytes"):
        apply_writes(base, [{**write, "before_hex": "0000"}])
    with pytest.raises(ValueError, match="overlaps"):
        apply_writes(base, [write, {**write, "field": "b", "partition_offset": 5,
                                    "before_hex": "05", "after_hex": "cc"}])


def test_generic_partition_reader_checks_header_and_decoded_bytes():
    payload = b"test-secondary-slot"
    stream = lit(payload)
    packed = 20 + len(stream)
    header = struct.pack("<5I", len(payload), packed, 1, 0x4000, 4)
    slot = header + stream + bytes(64 - packed)
    raw = bytearray(IMAGE_BASE + 0x100 + 64)
    raw[IMAGE_BASE + 0x100:] = bytes(value ^ 0xFF for value in slot)
    assert read_partition(bytes(raw), 0x100, 64, len(payload)) == (header + stream, payload)
    with pytest.raises(ValueError, match="pinned variant"):
        read_partition(bytes(raw), 0x100, 64, len(payload) + 1)
    with pytest.raises(ValueError, match="does not fit"):
        read_partition(bytes(raw), 0x100, packed - 1, len(payload))


def synthetic_container() -> bytearray:
    raw = bytearray(IMAGE_BASE + 0x2FD05D8)
    for index, value in ((3, 0x2FC45D8), (4, 0xC000), (18, 0x2FC4020),
                         (19, 0x188), (21, 0x2FC41A8), (22, 0x430)):
        struct.pack_into("<I", raw, OUTER_HEADER + 4 * index, value)
    return raw


def test_integrity_words_match_hand_arithmetic_on_zero_container():
    sums = compute_integrity(bytes(synthetic_container()))
    assert sums["outer_image"] == ~(0xFF * FLASH_IMAGE_SIZE) & 0xFFFFFFFF
    assert sums["outer_table"] == ~(0xFF * 0x4000) & 0xFFFFFFFF
    assert sums["inner_trailer"] == ~(0xFF * 0xC000) & 0xFFFFFFFF
    assert sums["inner_segment_a"] == 0xFFFFFFFF
    assert sums["inner_segment_b"] == 0xFFFFFFFF


@pytest.mark.parametrize("image_offset,word", [
    (0x123456, "outer_image"),
    (0x2FC0020 + 7, "outer_table"),
    (0x2FC4020 + 3, "inner_segment_a"),
    (0x2FC41A8 + 9, "inner_segment_b"),
    (0x2FC45D8 + 0xBFFF, "inner_trailer"),
])
def test_each_region_moves_exactly_its_own_word(image_offset, word):
    raw = synthetic_container()
    sealed = reseal(bytes(raw))
    raw[IMAGE_BASE + image_offset] = 0x10
    resealed = reseal(bytes(raw))
    before, after = stored_integrity(sealed), stored_integrity(resealed)
    assert [k for k in before if before[k] != after[k]] == [word]
    assert stored_integrity(resealed) == compute_integrity(resealed)
