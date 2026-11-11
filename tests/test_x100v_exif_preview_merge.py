"""Offline exact-byte and ARM controls for the proposed preview EXIF fix."""
from pathlib import Path
import subprocess

import pytest

from tools.x100v_exif_dimension_serializer import execute
from tools.x100v_exif_preview_merge import merge
from tools.x100v_jpeg_crop import patched
from tools.x100v_preview_alias_candidate import read_elf_text
from tools.fuji_xpan_validation import SOURCES, verify_arm_words, read_arm_bl_call_sites


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    evidence = Path("out/preview-aspect-probe-20261106/card-5h-writes.json")
    if not evidence.exists():
        pytest.skip(f"local evidence missing from git-ignored out/: {evidence}")
    folder = tmp_path_factory.mktemp("exif-preview-stubs")
    result = []
    for name in ("x100v_exif_dimension_stub.s", "x100v_exif_dimension_stub_preview.s"):
        obj = folder / (name + ".o")
        subprocess.run(["clang", "--target=armv7a-none-eabi", "-c",
                        "tools/" + name, "-o", str(obj)], check=True)
        result.append(read_elf_text(obj))
    return (
        Path("out/fw-cache/x100v-301-part6.bin").read_bytes(),
        Path("out/fw-cache/x100v-301-part7.bin").read_bytes(),
        Path("out/preview-aspect-probe-20261106/card-5h-writes.json").read_bytes(),
        *result,
    )


def test_exact_delta_and_stock_guards(samples):
    primary, secondary, baseline, old_stub, new_stub = samples
    assert len(old_stub) == 116
    assert len(new_stub) == 128
    merged = merge(primary, secondary, baseline, new_stub)
    assert len(merged) == 7
    replacement = next(w for w in merged if w["field"] == "exif-dimension-stub")
    assert len(bytes.fromhex(replacement["after_hex"])) == 128
    images = {6: primary, 7: secondary}
    modified = patched(images, merged)
    for part, original in images.items():
        differences = {i for i, (old, new) in enumerate(zip(original, modified[part]))
                       if old != new}
        declared = {i for w in merged if w["partition"] == part
                    for i in range(w["partition_offset"],
                                   w["partition_offset"] + len(bytes.fromhex(w["after_hex"])))}
        assert differences <= declared
        assert len(modified[part]) == len(original)


def test_exif_and_raf_component_builder_share_constructor_context(samples):
    """Static call-order bridge only; not proof of live preview EXIF values."""
    _, secondary, _, _, _ = samples
    load = SOURCES["x100v_3_01"]["secondary_load"]
    verify_arm_words(secondary, load, {
        0x01EE46A0: 0xE5995004,  # component source or default
        0x01EE46B0: 0x01A05003,
        0x01EE47E8: 0xE1A00004,  # shared context r4 -> EXIF builder r0
        0x01EE47EC: 0xEB01CD7C,
        0x01EE48DC: 0xE50B5040,  # preserve component source
        0x01EE49A0: 0xE51B2040,  # same component source -> r2
        0x01EE49A8: 0xE1A00004,  # same context r4 -> component builder r0
        0x01EE49AC: 0xEBFFCEE4,
        0x01F57DF0: 0xE1A04000,  # EXIF builder retains context
        0x01F57DFC: 0xE1A06003,  # staging destination from r3
        0x01F581A8: 0xE59330FC,  # width source, context +0x30fc
        0x01F581AC: 0xE58632A0,
        0x01F581C4: 0xE59330F8,  # height source, context +0x30f8
        0x01F581C8: 0xE58632A4,
        0x01F581CC: 0xE5D43624,  # unchanged hook instruction
        0x01ED8550: 0xE1A06000,  # component builder retains same context
        0x01ED8558: 0xE1A08002,  # source pointer
        0x01ED858C: 0xE5828648,  # source pointer retained for RAF writer
    })
    assert read_arm_bl_call_sites(secondary, load, 0x01F57DE4) == [0x01EE47EC]


@pytest.mark.parametrize("name,width,height,aspect,flag,expected", [
    ("preview-zero", 4416, 2944, 2, 0, (4416, 1632)),
    ("preview-alternate", 4416, 2944, 2, 1, (4416, 1632)),
    ("3:2-negative", 4416, 2944, 1, 0, (4416, 2944)),
    ("4:3-negative", 4416, 2944, 4, 0, (4416, 2944)),
    ("L-16:9", 6240, 3512, 2, 0, (6240, 2304)),
    ("M-16:9", 4416, 2488, 2, 0, (4416, 1632)),
    ("S-16:9", 3120, 1760, 2, 0, (3120, 1152)),
    ("small-negative", 640, 480, 2, 0, (640, 480)),
])
def test_preview_exif_arm(samples, name, width, height, aspect, flag, expected):
    primary, secondary, _, old_stub, new_stub = samples
    actual = execute(primary, secondary, width, height, aspect=aspect, flag=flag,
                     stub=new_stub, preview_metadata_case=True)
    assert (actual["serialized_width"], actual["serialized_height"]) == expected, name
    if name.startswith("preview"):
        old = execute(primary, secondary, width, height, aspect=aspect, flag=flag,
                      stub=old_stub)
        assert (old["serialized_width"], old["serialized_height"]) == (4416, 2944)
