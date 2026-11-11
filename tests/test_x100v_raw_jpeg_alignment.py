"""Independent synthetic vectors for RAW/JPEG scene registration."""

import numpy as np
import pytest

from tools.x100v_raw_jpeg_alignment import align


def test_centered_crop_survives_contrast_change():
    rng = np.random.default_rng(6524)
    raw = rng.integers(0, 200, size=(100, 120)).astype(float)
    jpeg = raw[27:67] * 0.7 + 20
    result = align(raw, jpeg, max_dx=0)
    assert result["top_px_at_analysis_width"] == 27
    assert result["horizontal_shift_px"] == 0
    assert result["correlation"] > 0.98
    assert result["best_nonlocal_correlation"] < 0.2


def test_unrelated_scene_does_not_claim_strong_registration():
    rng = np.random.default_rng(100)
    raw = rng.integers(0, 256, size=(100, 120)).astype(float)
    unrelated = rng.integers(0, 256, size=(40, 120)).astype(float)
    assert align(raw, unrelated, max_dx=0)["correlation"] < 0.2


def test_invalid_shapes_fail_closed():
    with pytest.raises(ValueError):
        align(np.zeros((20, 100)), np.zeros((21, 100)))
    with pytest.raises(ValueError):
        align(np.zeros((50, 100)), np.zeros((20, 99)))
