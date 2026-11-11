import json
import struct
from pathlib import Path

import pytest

from tools.x100v_16x9_to_65x24 import height_65_24, ratio_fields

MANIFEST = Path("build/x100v-16x9-to-65x24-dimensions-20261102-a/manifest.json")


@pytest.mark.parametrize("width,height", [(11648, 4304), (8256, 3048), (4000, 1480), (1024, 376)])
def test_height_rule_reproduces_gfx_65_24_rows(width, height):
    assert height_65_24(width) == height


@pytest.mark.parametrize("ratio,fields", [((3, 2), (32768, 1)), ((16, 9), (50972, 1)),
                                          ((4, 3), (21845, 1)), ((65, 24), (46421, 2))])
def test_ratio_fields_match_stored_aspect_list_values(ratio, fields):
    assert ratio_fields(*ratio) == fields


def test_manifest_changes_only_16_9_still_heights():
    writes = json.loads(MANIFEST.read_text())["writes"]
    assert len(writes) == 40
    heights = {3512: 2304, 2488: 1632, 1760: 1152, 432: 280}
    spans = set()
    for w in writes:
        old, new = bytes.fromhex(w["before_hex"]), bytes.fromhex(w["after_hex"])
        fmt = {2: "<H", 4: "<I", 6: "<3H"}[len(old)]
        before, after = struct.unpack(fmt, old), struct.unpack(fmt, new)
        assert heights[before[0]] == after[0], w["field"]
        if len(old) == 6:
            assert before[1:] == (50972, 1) and after[1:] == (46421, 2)
        span = {(w["partition"], w["address"] + k) for k in range(len(old))}
        assert not span & spans, w["field"]
        spans |= span
    assert {w["partition"] for w in writes} == {6, 7}


def _run_branch(words, inputs):
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from unicorn import arm_const as A

    regs = [getattr(A, f"UC_ARM_REG_R{i}") for i in range(13)]
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x10000, 0x1000)
    code = struct.pack(f"<{len(words)}I", *words)
    uc.mem_write(0x10000, code)
    for i, r in enumerate(regs):
        uc.reg_write(r, 0x1000 + i)
    for i, v in inputs.items():
        uc.reg_write(regs[i], v)
    uc.emu_start(0x10000, 0x10000 + len(code))
    return [uc.reg_read(r) for r in regs]


@pytest.mark.parametrize("site", ["geometry-code2-r6", "geometry-code2-r2"])
def test_geometry_branches_compute_24_65_and_touch_only_scratch_registers(site):
    from tools.x100v_16x9_to_65x24 import CODE_SITES

    _, _, _, old, new = next(s for s in CODE_SITES if s[0] == site)
    src, dst = (5, 6) if site.endswith("r6") else (0, 2)
    scratch = {3, dst, 2 if dst == 6 else 1}
    for width in [*range(2, 12001, 2), 6240, 4416, 3120, 768, 3840, 1920, 1280]:
        before = _run_branch(old, {src: width})
        after = _run_branch(new, {src: width})
        assert before[dst] == width * 9 // 16
        assert after[dst] == width * 24 // 65
        changed = {i for i in range(13) if after[i] != 0x1000 + i and i != src}
        assert changed <= scratch, (width, changed)
    assert _run_branch(new, {src: 6240})[dst] == 2304


def test_ratio_code_manifest_adds_only_the_code_sites():
    data = json.loads(Path("build/x100v-16x9-to-65x24-ratio-code-20261102-a/manifest.json").read_text())
    dims = json.loads(MANIFEST.read_text())["writes"]
    assert data["writes"][:40] == dims
    assert [w["field"] for w in data["writes"][40:]] == [
        "crop-helper-code2-ratio", "ratio-pair-code2-first", "ratio-pair-code2-second",
        "geometry-code2-r6", "geometry-code2-r2"]
