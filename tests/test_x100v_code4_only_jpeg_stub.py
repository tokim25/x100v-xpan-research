"""Original-ARM controls for an offline code-4-only JPEG crop stub."""

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.test_x100v_jpeg_crop_block_preview_stub import run_stub
from tools.fuji_xpan_validation import SOURCES
from tools.x100v_jpeg_crop import STUB_ADDRESS
from tools.x100v_preview_alias_candidate import read_elf_text


@pytest.fixture(scope="module")
def stub(tmp_path_factory):
    obj = tmp_path_factory.mktemp("xpan-code4-only-jpeg") / "stub.o"
    subprocess.run(
        ["clang", "--target=armv7a-none-eabi", "-c",
         "tools/x100v_jpeg_crop_block_code4_only_stub.s", "-o", str(obj)],
        check=True,
    )
    data = read_elf_text(obj)
    primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    source = SOURCES["x100v_3_01"]
    assert hashlib.sha256(primary).hexdigest() == source["primary_sha256"]
    assert len(data) <= 0x0128FE00 - STUB_ADDRESS
    offset = STUB_ADDRESS - source["primary_load"]
    assert primary[offset:offset + len(data)] == bytes(len(data))
    return data


@pytest.mark.parametrize("width,height,expected_height,skip", [
    (12480, 3512, 2304, 604),
    (8832, 2488, 1632, 428),
    (6240, 1760, 1152, 304),
    (8832, 2944, 1632, 656),
])
def test_only_code4_crops(stub, width, height, expected_height, skip):
    for aspect in (0, 1, 2, 3, 5):
        out_height, out_base, stride = run_stub(stub, width, height, aspect, 0)
        assert out_height == 0
        assert out_base == 0x40000000
    out_height, out_base, stride = run_stub(stub, width, height, 4, 0)
    assert out_height == expected_height
    assert out_base == 0x40000000 + skip * stride


@pytest.mark.parametrize("width,height", [(8832, 2940), (8000, 3000), (12480, 2304)])
def test_code4_unknown_geometry_passes(stub, width, height):
    out_height, out_base, _ = run_stub(stub, width, height, 4, 0)
    assert out_height == 0
    assert out_base == 0x40000000
