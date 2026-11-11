from pathlib import Path

import pytest

from tools.x100v_exif_mask_route import inspect, mask_allows


@pytest.mark.parametrize("mask,allowed", [(0, True), (1, True), (2, False),
                                           (3, False), (0xFFFF, False)])
def test_mask_gate_independent_halfword_vectors(mask, allowed):
    assert mask_allows(mask, 1) is allowed


@pytest.mark.parametrize("mask,flags", [(-1, 1), (0x10000, 1),
                                        (0, -1), (0, 0x10000)])
def test_rejects_out_of_range_mask(mask, flags):
    with pytest.raises(ValueError):
        mask_allows(mask, flags)


def test_rejects_non_official_update(tmp_path: Path):
    other = tmp_path / "not-firmware.dat"
    other.write_bytes(b"not an X100V update")
    with pytest.raises(ValueError, match="unrecognized X100V update"):
        inspect(other)
