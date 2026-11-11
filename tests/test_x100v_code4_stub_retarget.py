"""Offline original-ARM differential for a selectable code-4 successor.

This retargets only the two existing card-5i aspect guards in memory. It
does not construct a boot image or establish code-4 capture geometry.
"""

import struct
import subprocess
from pathlib import Path

import pytest

from tests.test_x100v_jpeg_crop_block_preview_stub import run_stub
from tools.x100v_exif_dimension_serializer import execute
from tools.x100v_preview_alias_candidate import read_elf_text


OLD_GUARD = struct.pack("<I", 0xE3500002)  # cmp r0, #2
NEW_GUARD = struct.pack("<I", 0xE3500004)  # cmp r0, #4


def _retarget(data: bytes) -> bytes:
    assert data.count(OLD_GUARD) == 1
    changed = data.replace(OLD_GUARD, NEW_GUARD)
    assert len(changed) == len(data)
    assert {i for i, (a, b) in enumerate(zip(data, changed)) if a != b} == {
        data.index(OLD_GUARD),
    }
    return changed


@pytest.fixture(scope="module")
def stubs(tmp_path_factory):
    folder = tmp_path_factory.mktemp("xpan-code4-retarget")
    result = []
    for name in (
        "x100v_jpeg_crop_block_preview_aspect_stub.s",
        "x100v_exif_dimension_stub_preview.s",
    ):
        obj = folder / (name + ".o")
        subprocess.run(
            ["clang", "--target=armv7a-none-eabi", "-c", "tools/" + name, "-o", str(obj)],
            check=True,
        )
        original = read_elf_text(obj)
        result.append((original, _retarget(original)))
    return result


def test_code4_preview_guard_only(stubs):
    original, retargeted = stubs[0]
    for aspect, original_height, new_height in ((2, 1632, 0), (4, 0, 1632), (1, 0, 0)):
        before = run_stub(original, 8832, 2944, aspect, 0)
        after = run_stub(retargeted, 8832, 2944, aspect, 0)
        assert before[0] == original_height
        assert after[0] == new_height
        assert before[2] == after[2]  # same source stride
    # Existing L/M/S dimension-table cases have no aspect guard.
    for aspect in (2, 4):
        assert run_stub(retargeted, 12480, 3512, aspect, 0)[0] == 2304


def test_code4_exif_guard_only(stubs):
    original, retargeted = stubs[1]
    primary = Path("out/fw-cache/x100v-301-part6.bin").read_bytes()
    secondary = Path("out/fw-cache/x100v-301-part7.bin").read_bytes()
    for aspect, original_height, new_height in ((2, 1632, 2944), (4, 2944, 1632), (1, 2944, 2944)):
        before = execute(primary, secondary, 4416, 2944, aspect=aspect, flag=0,
                         stub=original, preview_metadata_case=True)
        after = execute(primary, secondary, 4416, 2944, aspect=aspect, flag=0,
                        stub=retargeted, preview_metadata_case=True,
                        expected_stub_aspect=4)
        assert before["serialized_height"] == original_height
        assert after["serialized_height"] == new_height
        assert before["serialized_width"] == after["serialized_width"] == 4416
