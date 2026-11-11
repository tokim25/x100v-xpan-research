import pytest

from tools.x100v_encoder_dimension_emulator import load_images, verify_images


def test_dimension_harness_rejects_unknown_update_without_modifying_it(tmp_path):
    path = tmp_path / "wrong.dat"
    path.write_bytes(b"not a Fujifilm update")
    with pytest.raises(ValueError, match="unrecognized X100V update"):
        load_images(path)
    assert path.read_bytes() == b"not a Fujifilm update"


def test_dimension_harness_rejects_unidentified_code_before_emulation():
    with pytest.raises(ValueError, match="unrecognized primary"):
        verify_images(b"unknown primary", b"unknown kernel")
