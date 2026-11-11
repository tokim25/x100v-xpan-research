import struct

import pytest

from tools.x100v_preview_alias_candidate import read_elf_text, plan


def arm_object_fixture(*, relocation=False):
    """Independent minimal ELF32 fixture: one two-word ARM text section."""
    data = bytearray(0x120)
    data[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
    struct.pack_into("<HHIIIIIHHHHHH", data, 16,
                     1, 40, 1, 0, 0, 0x80, 0, 52, 0, 0, 40, 4, 2)
    data[0x40:0x48] = bytes.fromhex("001080e51eff2fe1")
    names = b"\0.text\0.shstrtab\0.rel.text\0"
    data[0x60:0x60 + len(names)] = names
    for index, section in enumerate((
        (1, 1, 6, 0, 0x40, 8, 0, 0, 4, 0),
        (7, 3, 0, 0, 0x60, len(names), 0, 0, 1, 0),
        (17, 9, 0, 0, 0x48, 8 if relocation else 0, 0, 1, 4, 8),
    ), start=1):
        struct.pack_into("<10I", data, 0x80 + 40 * index, *section)
    return data


def test_elf_text_fixture_and_no_mutation(tmp_path):
    path = tmp_path / "stub.o"
    fixture = arm_object_fixture()
    path.write_bytes(fixture)
    assert read_elf_text(path) == bytes.fromhex("001080e51eff2fe1")
    assert path.read_bytes() == fixture


def test_elf_unresolved_relocations_rejected(tmp_path):
    path = tmp_path / "reloc.o"
    path.write_bytes(arm_object_fixture(relocation=True))
    with pytest.raises(ValueError, match="unresolved"):
        read_elf_text(path)


@pytest.mark.parametrize("length", [0, 51, 52, 0x11F])
def test_elf_truncation_rejected(tmp_path, length):
    path = tmp_path / "truncated.o"
    path.write_bytes(arm_object_fixture()[:length])
    with pytest.raises(ValueError):
        read_elf_text(path)


def test_elf_text_extent_rejected(tmp_path):
    path = tmp_path / "bad-extent.o"
    data = arm_object_fixture()
    struct.pack_into("<I", data, 0x80 + 40 + 16, 0x11F)
    path.write_bytes(data)
    with pytest.raises(ValueError, match="outside file"):
        read_elf_text(path)


def test_preview_plan_rejects_unknown_stock():
    with pytest.raises(ValueError, match="unrecognized stock primary"):
        plan(b"not firmware", b"not a stub")
