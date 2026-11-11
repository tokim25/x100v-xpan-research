import pytest

from tools.x100v_ratio_arm_emulator import load_images


def test_arm_harness_rejects_unidentified_update_before_candidate_read(tmp_path):
    update = tmp_path / "wrong.dat"
    update.write_bytes(b"not the pinned X100V update")
    with pytest.raises(ValueError, match="unrecognized stock update"):
        load_images(update, tmp_path / "nonexistent-candidate.bin")
    assert update.read_bytes() == b"not the pinned X100V update"
