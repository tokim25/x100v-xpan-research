"""Stock X100V context arenas versus FujiMod's published bulk window.

Static bytes and address arithmetic only; no camera memory is read here.
"""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES


LOAD = 0x01BA0000
WINDOW = (0x00F00000, 0x02F00000)  # FujiMod X100V 3.01 catalog, half-open
TABLE = 0x022D8798
STRIDE = 0x5610
SAVE_PAIR_END = 0x4158  # context+0x4154 is the last 32-bit word
EXPECTED = [
    (0, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
    (1, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
    (2, 96, 0x1C032000, 0x1C272000, 0x1C235148),
    (3, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
    (4, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
    (5, 1, 0x1C32C000, 0x1C32A000, 0x1C330158),
    (6, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
    (7, 128, 0x1BF32000, 0x1C232000, 0x1C1E1348),
]


def test_stock_accessor_writer_and_first_eight_source_rows():
    image = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest() == SOURCES["x100v_3_01"]["secondary_sha256"]

    def word(address):
        return struct.unpack_from("<I", image, address - LOAD)[0]

    # Writer takes row+8 from selector table and stores it in the global
    # pointer subsequently consumed by the 0x5610-stride context accessor.
    assert word(0x01F25AE0) == word(0x01F272E4) == 0x03420CB8
    assert word(0x01F258A0) == 0xE58327C8  # str r2,[r3,#0x7c8]
    assert word(0x01F272C0) == 0xE59337C8  # ldr r3,[r3,#0x7c8]
    assert word(0x01F272C4) == 0xE3052610  # movw r2,#0x5610
    assert word(0x01F272C8) == 0xE0203092  # mla r0,r2,r0,r3
    rows = [struct.unpack_from("<4I", image, TABLE - LOAD + 16 * i)
            for i in range(8)]
    assert rows == [r[:4] for r in EXPECTED]


def test_every_published_context_arena_is_outside_bulk_read_window():
    lower, upper = WINDOW
    assert lower <= 0x023F3AA4 < upper  # first RAF object CFA pointer
    assert 0x03426AB0 >= upper  # event-group bitmap
    for mode, count, base, _fourth_field, expected_end in EXPECTED:
        assert 1 <= count <= 128, mode
        end = base + (count - 1) * STRIDE + SAVE_PAIR_END
        assert end == expected_end, mode
        assert base >= upper and end > upper, mode
        assert base + 0x48 >= upper, mode  # seven-word descriptor
