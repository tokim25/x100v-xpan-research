"""The merged image's original-ARM centered-window path has pinned vectors."""

import hashlib
import struct
from pathlib import Path

from tools.fuji_xpan_validation import SOURCES
from tools.x100v_code4_center_window_probe import EXPECTED_OFFSETS, run_slice
from tools.x100v_code4_capture_geometry_probe import FULL_3_2, LEGACY_16_9, SIZES


def test_center_window_full_height_and_legacy_inputs():
    source = SOURCES["x100v_3_01"]
    stock_primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    assert hashlib.sha256(stock_primary).hexdigest() == source["primary_sha256"]
    assert hashlib.sha256(secondary).hexdigest() == source["secondary_sha256"]
    primary = bytearray(stock_primary)
    for level, (width, height) in enumerate(SIZES):
        for table, value in ((0x014A72DC, width), (0x014A75C0, height)):
            cell = table + 4 * (5 * level + 4) - source["primary_load"]
            assert primary[cell:cell + 4] == bytes(4)
            struct.pack_into("<I", primary, cell, value)
    for level, ((width, target_height), full_height, legacy_height) in enumerate(
        zip(SIZES, FULL_3_2, LEGACY_16_9)
    ):
        stride = (2 * width + 255) & ~255
        for label, source_height in (("full_3_2", full_height),
                                     ("legacy_16_9", legacy_height),
                                     ("already_65_24", target_height)):
            result = run_slice(bytes(primary), secondary, level, 4, width,
                               source_height, stride)
            assert result == {
                "base_advance": EXPECTED_OFFSETS[label][level],
                "area_bytes": target_height * stride,
                "stride": stride,
                "width_pixels": width,
                "height": target_height,
            }
