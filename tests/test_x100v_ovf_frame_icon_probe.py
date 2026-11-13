import struct
from pathlib import Path

import pytest

from tools.x100v_ovf_frame_icon_probe import (ICONS, OVERLAY_LOAD, POOL, RECORDS, check_stock, word,
                                              writes_for)

CACHE = Path("out/fw-cache/x100v-301-part9.bin")


def _synthetic() -> bytes:
    """A blank overlay holding only the words the probe checks, placed by hand."""
    data = bytearray(0x400000)

    def put(address, value):
        struct.pack_into("<I", data, address - OVERLAY_LOAD, value)

    # Literal pool, record fields and the three `ldr r0, [pc, #imm]` loaders:
    # imm = pool - (loader + 8) = 0x68, 0x44 and 0x20.
    for aspect, imm in (("1:1", 0x68), ("3:2", 0x44), ("16:9", 0x20)):
        put(POOL[aspect], RECORDS[aspect])
        put(RECORDS[aspect] + 4, ICONS[aspect])
        put(RECORDS[aspect] + 0x18, 0x01E00280)
    put(0x03790D90, 0xE59F0068)
    put(0x03790DB8, 0xE59F0044)
    put(0x03790DE0, 0xE59F0020)
    return bytes(data)


def test_write_swaps_only_the_16x9_pool_word():
    (write,) = writes_for(_synthetic())
    assert write["partition"] == 9
    assert write["address"] == "0x03790e08"
    assert write["partition_offset"] == 0x03790E08 - 0x03720000 == 0x70E08
    assert write["before_hex"] == "9833b003"  # 0x03b03398, the 16:9 record
    assert write["after_hex"] == "4433b003"   # 0x03b03344, the 3:2 record


def test_changed_stock_is_rejected():
    data = bytearray(_synthetic())
    struct.pack_into("<I", data, RECORDS["16:9"] + 4 - OVERLAY_LOAD, 0xFF00059A)
    with pytest.raises(ValueError):
        writes_for(bytes(data))
    data = bytearray(_synthetic())
    struct.pack_into("<I", data, 0x03790DE0 - OVERLAY_LOAD, 0xE59F0024)
    with pytest.raises(ValueError):
        writes_for(bytes(data))


def test_pinned_overlay_matches_when_cached():
    if not CACHE.exists():
        pytest.skip("decoded overlay not cached")
    overlay = CACHE.read_bytes()
    check_stock(overlay)
    assert word(overlay, POOL["3:2"]) == RECORDS["3:2"]
