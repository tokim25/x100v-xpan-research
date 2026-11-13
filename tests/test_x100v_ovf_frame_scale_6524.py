import struct
from pathlib import Path

import pytest

from tools.x100v_ovf_frame_scale_6524 import LITERAL, PINNED, STOCK_LITERAL, scale_6524, writes_for

LOAD = 0x01BA0000


def _synthetic() -> bytearray:
    data = bytearray(0x300000)
    for address, word in PINNED.items():
        data[address - LOAD:address - LOAD + 4] = bytes.fromhex(word)
    data[LITERAL - LOAD:LITERAL - LOAD + 4] = STOCK_LITERAL
    return data


def test_factor_is_stock_times_128_over_195():
    # By hand: 0x3f587387 is 0.8455128. 0.8455128 * 128 / 195 = 0.5550033.
    # A 3:2 frame of height 1 becomes 0.5550033, and 1.5 / 0.5550033 = 2.7027,
    # against 65/24 = 2.7083: the stock factor's 0.2% excess over 27/32 is kept.
    new = struct.unpack("<f", scale_6524(STOCK_LITERAL))[0]
    assert new == pytest.approx(0.5550033, abs=1e-6)
    assert 1.5 / new == pytest.approx(65 / 24, rel=0.003)
    assert scale_6524(struct.pack("<f", 27 / 32)) == struct.pack("<f", 24 / 65 * 1.5)


def test_one_write_at_the_literal():
    (write,) = writes_for(bytes(_synthetic()))
    assert write["address"] == "0x01e9e660"
    assert write["partition"] == 7 and write["partition_offset"] == 0x2FE660
    assert write["before_hex"] == "8773583f" and write["after_hex"] == "b2140e3f"


def test_changed_literal_or_instruction_is_rejected():
    data = _synthetic()
    data[LITERAL - LOAD] ^= 1
    with pytest.raises(ValueError):
        writes_for(bytes(data))
    data = _synthetic()
    data[0x01E9E584 - LOAD] ^= 1
    with pytest.raises(ValueError):
        writes_for(bytes(data))


def test_pinned_secondary_matches_when_cached():
    path = Path("out/fw-cache/x100v-301-part7.bin")
    if not path.exists():
        pytest.skip("decoded secondary not cached")
    assert len(writes_for(path.read_bytes())) == 1
