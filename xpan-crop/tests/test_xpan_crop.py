import json

import pytest
from PIL import Image

from xpan_crop.cli import main
from xpan_crop.geometry import Rect, centered_crop, parse_ratio, x100v_model


def test_x100v_65_24_vector():
    # 6240 * 24 / 65 = 2304; (4160 - 2304) / 2 = 928
    assert centered_crop(6240, 4160, 65, 24) == Rect(0, 928, 6240, 2304)
    assert x100v_model()["crop"] == {"x": 0, "y": 928, "width": 6240, "height": 2304}


def test_square_and_tall_sources():
    assert centered_crop(6240, 4160, 1, 1) == Rect(1040, 0, 4160, 4160)
    assert centered_crop(4160, 6240, 65, 24) == Rect(0, 2352, 4160, 1536)


def test_bad_input():
    with pytest.raises(ValueError):
        centered_crop(6240, 4160, 65, 0)
    with pytest.raises(ValueError):
        parse_ratio("65")


def _jpeg(path, size=(650, 416)):
    Image.new("RGB", size, (120, 80, 40)).save(path, "JPEG")


def test_crop_preserves_source_and_sizes(tmp_path):
    src = tmp_path / "a.jpg"
    _jpeg(src)
    assert main(["crop", str(src), "--out", str(tmp_path / "o")]) == 0
    with Image.open(tmp_path / "o" / "a_65x24.jpg") as out:
        assert out.size == (650, 240)
    with Image.open(src) as orig:
        assert orig.size == (650, 416)


def test_preview_keeps_full_size(tmp_path):
    src = tmp_path / "a.jpg"
    _jpeg(src)
    main(["preview", str(src), "--out", str(tmp_path / "o")])
    with Image.open(tmp_path / "o" / "a_frame.jpg") as out:
        assert out.size == (650, 416)


def test_sidecar_for_raf_needs_size_and_writes_json(tmp_path):
    raf = tmp_path / "example.RAF"
    raf.write_bytes(b"not a real raf")
    with pytest.raises(SystemExit):
        main(["sidecar", str(raf), "--out", str(tmp_path / "o")])
    main(["sidecar", str(raf), "--size", "6240x4160", "--out", str(tmp_path / "o")])
    data = json.loads((tmp_path / "o" / "example_xpan.json").read_text())
    assert data["crop"] == {"x": 0, "y": 928, "width": 6240, "height": 2304}
    assert raf.read_bytes() == b"not a real raf"


def test_directory_input_and_full_size_x100v_frame(tmp_path):
    shots = tmp_path / "shots"
    shots.mkdir()
    _jpeg(shots / "full.jpg", size=(6240, 4160))
    (shots / ".DS_Store").write_bytes(b"x")
    assert main(["crop", str(shots), "--out", str(tmp_path / "o")]) == 0
    with Image.open(tmp_path / "o" / "full_65x24.jpg") as out:
        assert out.size == (6240, 2304)
    assert [p.name for p in (tmp_path / "o").iterdir()] == ["full_65x24.jpg"]
