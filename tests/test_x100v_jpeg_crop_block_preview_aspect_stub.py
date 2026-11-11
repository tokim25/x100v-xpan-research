"""ARM fixture checks for the aspect-scoped, selector-agnostic preview probe."""

from itertools import product
import subprocess

import pytest

from tests.test_x100v_jpeg_crop_block_preview_stub import run_stub
from tools.x100v_jpeg_crop import STUB_ADDRESS
from tools.x100v_preview_alias_candidate import read_elf_text


@pytest.fixture(scope="module")
def stub(tmp_path_factory):
    obj = tmp_path_factory.mktemp("xpan-preview-aspect-stub") / "stub.o"
    subprocess.run(
        ["clang", "--target=armv7a-none-eabi", "-c",
         "tools/x100v_jpeg_crop_block_preview_aspect_stub.s", "-o", str(obj)],
        check=True,
    )
    data = read_elf_text(obj)
    assert len(data) <= 0x0128FE00 - STUB_ADDRESS
    return data


@pytest.fixture(scope="module")
def card5g_stub(tmp_path_factory):
    obj = tmp_path_factory.mktemp("xpan-preview-card5g-stub") / "stub.o"
    subprocess.run(
        ["clang", "--target=armv7a-none-eabi", "-c",
         "tools/x100v_jpeg_crop_block_preview_stub.s", "-o", str(obj)],
        check=True,
    )
    return read_elf_text(obj)


@pytest.mark.parametrize("width,height,aspect,selector,want_height,skip", [
    (8832, 2944, 2, 0, 1632, 656),
    (8832, 2944, 2, 1, 1632, 656),
    (8832, 2944, 2, 2, 1632, 656),
    (8832, 2944, 0, 0, 0, 0),
    (8832, 2944, 4, 1, 0, 0),
    (8832, 2940, 2, 1, 0, 0),
    (12480, 3512, 2, 0, 2304, 604),
    (8832, 2488, 2, 1, 1632, 428),
    (6240, 1760, 2, 0, 1152, 304),
])
def test_aspect_scoped_crop(stub, width, height, aspect, selector, want_height, skip):
    output_height, output_base, stride = run_stub(stub, width, height, aspect, selector)
    assert output_height == want_height
    assert output_base == 0x40000000 + skip * stride


def test_only_selector_guard_was_removed(stub, card5g_stub):
    """Compare both actual ARM routines, not just expected source structure."""
    geometries = (
        (8832, 2944), (8832, 2940), (8832, 2488),
        (12480, 3512), (12480, 4160), (6240, 1760),
    )
    changed = []
    for (width, height), aspect, selector in product(geometries, (0, 2, 4), (0, 1, 2)):
        old = run_stub(card5g_stub, width, height, aspect, selector)
        new = run_stub(stub, width, height, aspect, selector)
        if old != new:
            changed.append((width, height, aspect, selector))
            assert (width, height, aspect) == (8832, 2944, 2)
            assert selector in (0, 2)
            assert old[:2] == (0, 0x40000000)
            assert new[:2] == (1632, 0x40000000 + 656 * new[2])
    assert changed == [(8832, 2944, 2, 0), (8832, 2944, 2, 2)]
