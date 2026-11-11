import struct
import zlib

import pytest

from tools.x100v_recovery_audit import diff_runs, owner
from tools.x100v_sd_boot_candidate import config_offset, validate_writes


def test_config_pair_is_found_by_length_and_crc():
    boot = bytes(range(256)) * 4
    init = bytearray(64) + struct.pack("<II", len(boot), zlib.crc32(boot)) + bytes(16)
    assert config_offset(bytes(init), boot) == 64


def test_config_pair_must_be_unique_and_present():
    boot = b"payload"
    pair = struct.pack("<II", len(boot), zlib.crc32(boot))
    with pytest.raises(ValueError, match="not unique"):
        config_offset(pair + bytes(4) + pair, boot)
    with pytest.raises(ValueError, match="not unique"):
        config_offset(bytes(32), boot)


def test_diff_runs_merges_nearby_bytes_only():
    a = bytes(100)
    b = bytearray(a)
    b[10] = b[20] = b[90] = 1
    assert diff_runs(a, bytes(b)) == [(10, 21), (90, 91)]


def test_owner_classifies_regions_bss_and_gaps():
    plan = {"regions": [{"name": "r", "address": 0x100, "source": {"decoded_size": 0x10}}],
            "bss": [{"name": "k", "address": 0x200, "size": 0x20}]}
    assert owner(0x10F, plan) == "r"
    assert owner(0x210, plan) == "bss:k"
    assert owner(0x300, plan) == "gap"


def test_stock_build_is_identified_by_ffboot_hash(tmp_path):
    from tools.x100v_sd_boot_candidate import stock_build

    (tmp_path / "ffboot.bin").write_bytes(b"not an audited image")
    with pytest.raises(ValueError, match="not an audited"):
        stock_build(tmp_path)


def test_known_layouts_declare_their_files_and_fujimod_edits():
    from tools.x100v_sd_boot_candidate import STOCK_BUILDS

    full = STOCK_BUILDS["full-image-b13b12c"]
    assert set(full["files"]) == {"ffinit.bin", "ffboot.bin", "FPUPDATE.DAT"}
    assert "ffdata.bin" in STOCK_BUILDS["preload-130dabad"]["files"]
    assert set(full["edits"]) <= set(STOCK_BUILDS["preload-130dabad"]["edits"])


def test_writes_map_to_their_partition_load_address():
    from tools.x100v_sd_boot_candidate import ram_address

    assert ram_address({"partition_offset": 0x10}) == 0x00F21010
    assert ram_address({"partition": 6, "partition_offset": 0x10}) == 0x00F21010
    assert ram_address({"partition": 7, "partition_offset": 0x742F4}) == 0x01C142F4
    assert ram_address({"partition": 9, "partition_offset": 0x691498}) == 0x03DB1498
    with pytest.raises(KeyError):
        ram_address({"partition": 5, "partition_offset": 0})


def test_write_validation_accepts_nonoverlapping_partition_spans():
    writes = [
        {"field": "primary", "partition": 6, "partition_offset": 0, "before_hex": "0011", "after_hex": "2233"},
        {"field": "secondary", "partition": 7, "partition_offset": 1, "before_hex": "44", "after_hex": "55"},
    ]
    assert validate_writes(writes, 0x04000000, {"edits": []}) == [
        (0x00F21000, b"\x00\x11", b"\x22\x33"),
        (0x01BA0001, b"\x44", b"\x55"),
    ]


@pytest.mark.parametrize("change,match", [
    ({"after_hex": "223344"}, "length-preserving"),
    ({"before_hex": "", "after_hex": ""}, "nonempty"),
    ({"partition_offset": -1}, "invalid partition or offset"),
    ({"partition_offset": 0x603340}, "partition boundary"),
    ({"partition": 7, "partition_offset": 0x82BFFF, "before_hex": "0011", "after_hex": "2233"}, "partition boundary"),
    ({"partition": 9, "partition_offset": 0x9FFFFF, "before_hex": "0011", "after_hex": "2233"}, "partition boundary"),
    ({"partition": 5}, "invalid partition or offset"),
])
def test_write_validation_rejects_invalid_spans(change, match):
    write = {"field": "test", "partition": 6, "partition_offset": 0,
             "before_hex": "0011", "after_hex": "2233"}
    write.update(change)
    with pytest.raises(ValueError, match=match):
        validate_writes([write], 0x04000000, {"edits": []})


def test_write_validation_rejects_boot_end_and_both_overlap_kinds():
    write = {"field": "first", "partition": 6, "partition_offset": 4,
             "before_hex": "0011", "after_hex": "2233"}
    with pytest.raises(ValueError, match="exceeds ffboot"):
        validate_writes([write], 0x00F21005, {"edits": []})
    with pytest.raises(ValueError, match="FujiMod edit"):
        validate_writes([write], 0x04000000, {"edits": [(0x00F21005, 1)]})
    second = {**write, "field": "second", "partition_offset": 5}
    with pytest.raises(ValueError, match="another declared write"):
        validate_writes([write, second], 0x04000000, {"edits": []})
