from tools.fuji_xpan_validation import (
    Q16_65_24,
    decode_develop_aspect_jump_table,
    find_q16_triplets,
    parse_primary_records,
    select_enabled_size_id,
    select_size_id_without_enabled_gate,
    enabled_dimension_labels,
    tables_consistent_and_enabled,
    verify_arm_words,
    verify_raw_partition_words,
    read_arm_bl_call_sites,
    verify_data_words,
    read_recbf_script_table,
    verify_recbf_script_order,
    read_recbf_action_hits,
    read_recbf_action_row,
    read_event_group_ids,
    read_event_group_table,
    read_recbf_message_bit_routes,
    read_recbf_completion_stage_subtypes,
    read_aspect_dimension_grid,
    read_initial_parameter_record_bank,
    read_preview_key_table,
    preview_key_lookup_index,
    addresses_share_4k_page,
    preview_parallel_extension_overlaps_next_array,
    read_dimension_estimate_coeff_table,
    arm_smlabb_record_index,
    plan_x100v_preview_code4_row_reuse,
    plan_x100v_preview_code4_zero_placeholder_reuse,
    plan_x100v_size_and_raw_crop_lookup_data,
    read_vg_geometry_record,
    read_vg_selector_jump_rows,
    read_vg_channel_routes,
    read_crop_ratio_jump_target,
    encode_arm_unconditional_b,
    scan_aligned_arm_cave_references,
    plan_x100v_code4_ratio_stub,
    read_arm_absolute_jump_table,
    read_develop_aspect_case_outputs,
    read_raw_partition,
    read_indexed_dispatch_first_entries,
)

import struct
import hashlib

import pytest


def test_vg_selector_jump_rows_independent_fixture() -> None:
    image = bytearray(0x100)
    for index, row in enumerate((0, 2, 4, 9, 11, 14, 15)):
        target = 0x1040 + 4 * index
        struct.pack_into("<I", image, 0x10 + 4 * index, target)
        struct.pack_into("<I", image, target - 0x1000, 0xE3A03000 | row)
    assert read_vg_selector_jump_rows(image, 0x1000, 0x1010) == [0, 2, 4, 9, 11, 14, 15]
    struct.pack_into("<I", image, 0x10, 0x2000)
    with pytest.raises(ValueError, match="outside partition"):
        read_vg_selector_jump_rows(image, 0x1000, 0x1010)
    struct.pack_into("<I", image, 0x10, 0x1040)
    struct.pack_into("<I", image, 0x40, 0xE3A02000)
    with pytest.raises(ValueError, match="not a bounded row assignment"):
        read_vg_selector_jump_rows(image, 0x1000, 0x1010)


def test_raw_word_verification_independent_fixture() -> None:
    # Literal ARM STR r1,[r0]; BX lr, independent of production address pins.
    code = bytes.fromhex("001080e51eff2fe1")
    payload = b"HEAD" + code + b"TAIL"
    digest = hashlib.sha256(code).hexdigest()
    expected = {0x1000: 0xE5801000, 0x1004: 0xE12FFF1E}
    assert verify_raw_partition_words(payload, 4, 8, 0x1000, digest, expected) == digest
    assert payload == b"HEAD" + code + b"TAIL"
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_raw_partition_words(payload, 4, 8, 0x1000, "0" * 64, expected)
    with pytest.raises(ValueError, match="instruction mismatch"):
        verify_raw_partition_words(payload, 4, 8, 0x1000, digest, {0x1000: 0xE5900000})
    with pytest.raises(ValueError, match="outside partition"):
        verify_raw_partition_words(payload, 4, 8, 0x1000, digest, {0x1008: 0})
    with pytest.raises(ValueError, match="outside payload"):
        verify_raw_partition_words(payload, 4, len(payload), 0x1000, digest, expected)


def test_q16_ratio_independent_vector() -> None:
    # 65/24 in Q16 is 177493.333..., rounded to 177493.
    assert Q16_65_24 == 177493


def test_arm_absolute_jump_table_independent_fixture_and_bounds() -> None:
    image = bytearray(0x40)
    struct.pack_into("<III", image, 0x10, 0x1000, 0x1020, 0x103C)
    assert read_arm_absolute_jump_table(image, 0x1000, 0x1010, 3) == [
        0x1000, 0x1020, 0x103C,
    ]
    for table, count in ((0x1011, 3), (0x103C, 2), (0x1010, 0)):
        try:
            read_arm_absolute_jump_table(image, 0x1000, table, count)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid absolute jump-table bounds must fail closed")
    struct.pack_into("<I", image, 0x14, 0x1040)
    try:
        read_arm_absolute_jump_table(image, 0x1000, 0x1010, 3)
    except ValueError as exc:
        assert "target outside partition" in str(exc)
    else:
        raise AssertionError("outside jump target must fail closed")


def test_raw_partition_independent_fixture_and_bounds() -> None:
    payload = b"PREFIX" + bytes.fromhex("ec09d200") + b"TAIL"
    assert read_raw_partition(payload, 6, 4) == bytes.fromhex("ec09d200")
    for offset, size in ((-1, 4), (6, 0), (6, len(payload))):
        try:
            read_raw_partition(payload, offset, size)
        except ValueError as exc:
            assert "outside payload" in str(exc)
        else:
            raise AssertionError("invalid raw partition bounds must fail closed")


def test_initial_parameter_record_bank_independent_fixture_and_bounds() -> None:
    image = bytearray(0x70)
    struct.pack_into("<I", image, 0, 2)
    struct.pack_into("<I", image, 8, 0x1020)
    image[0x21] = 2
    image[0x21 + 28] = 4
    assert read_initial_parameter_record_bank(image, 0x1000, 0x1000) == {
        "count": 2, "pointer": 0x1020, "subtypes": {2: 1, 4: 1},
    }
    struct.pack_into("<I", image, 8, 0x1060)
    try:
        read_initial_parameter_record_bank(image, 0x1000, 0x1000)
    except ValueError as exc:
        assert "data outside" in str(exc)
    else:
        raise AssertionError("out-of-bounds parameter bank must fail closed")

    gfx_image = bytearray(0xa0)
    struct.pack_into("<I", gfx_image, 0, 2)
    struct.pack_into("<I", gfx_image, 8, 0x1020)
    gfx_image[0x21] = 0
    gfx_image[0x21 + 48] = 2
    assert read_initial_parameter_record_bank(gfx_image, 0x1000, 0x1000, 48) == {
        "count": 2, "pointer": 0x1020, "subtypes": {0: 1, 2: 1},
    }
    try:
        read_initial_parameter_record_bank(gfx_image, 0x1000, 0x1000, 1)
    except ValueError as exc:
        assert "stride outside" in str(exc)
    else:
        raise AssertionError("invalid parameter record stride must fail closed")
    struct.pack_into("<I", gfx_image, 8, 0x1070)
    try:
        read_initial_parameter_record_bank(gfx_image, 0x1000, 0x1000, 48)
    except ValueError as exc:
        assert "data outside" in str(exc)
    else:
        raise AssertionError("out-of-bounds 48-byte parameter bank must fail closed")


def test_preview_key_table_independent_fixture() -> None:
    # First three bytes are compared; final halfwords feed output dimensions.
    image = b"HEAD" + struct.pack("<BBBBHH", 0, 2, 3, 9, 6240, 4160)
    image += struct.pack("<BBBBHH", 1, 0, 4, 8, 8256, 3048)
    rows = read_preview_key_table(image, 0x1000, 0x1004, 2)
    assert rows == [
        {"index": 0, "key": [0, 2, 3], "width": 6240, "height": 4160},
        {"index": 1, "key": [1, 0, 4], "width": 8256, "height": 3048},
    ]
    try:
        read_preview_key_table(image, 0x1000, 0x1004, 3)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("truncated preview key table must fail closed")


def test_dimension_estimate_coefficient_table_independent_fixture() -> None:
    # The static coefficient byte is only an initializer; firmware overwrites
    # it from the record's property key before performing byte-count math.
    image = b"HEAD" + struct.pack("<HHBBBBII", 6240, 2304, 2, 1, 0, 32, 10, 75533)
    rows = read_dimension_estimate_coeff_table(image, 0x1000, 0x1004, 1)
    assert rows == [{
        "index": 0, "width": 6240, "height": 2304, "category": 2,
        "mode": 1, "selector": 0, "initial_coefficient": 32,
        "divisor": 10, "runtime_property_key": 75533,
    }]
    try:
        read_dimension_estimate_coeff_table(image, 0x1000, 0x1004, 2)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("truncated estimate table must fail closed")


def test_arm_callback_record_index_independent_vectors() -> None:
    # SMLABB multiplies signed low halfwords; UXTH keeps the low 16 result bits.
    assert arm_smlabb_record_index(1, 3, 0) == 3
    assert arm_smlabb_record_index(1, 3, 1) == 4
    assert arm_smlabb_record_index(0xFFFF, 3, 5) == 2
    assert arm_smlabb_record_index(0x8000, 3, 0) == 0x8000
    for args in ((-1, 3, 0), (1, 0x10000, 0), (1, 3, 0x10000)):
        try:
            arm_smlabb_record_index(*args)
        except ValueError:
            pass
        else:
            raise AssertionError("out-of-range callback selector must fail closed")


def test_mode6_callback_message_receiver_index_independent_vector() -> None:
    # The sender's selector 7 makes ID 0x143a. The receiver subtracts
    # 0x1433, then indexes 32-bit destination pointers from 0x022efbfc.
    assert 0x143A - 0x1400 - 0x33 == 7
    assert 0x22EFBFC + 7 * 4 == 0x22EFC18
    # A 72-byte payload copied to this buffer retains the callback field.
    assert 0x0288D330 + 0x38 == 0x0288D368
    assert 0x38 + 4 <= 72


def test_mode6_index7_downstream_record_copy_independent_vector() -> None:
    # The accessor returns the index-7 receive buffer. A later caller copies
    # the full 72-byte record into a separate RAM buffer, preserving +0x38.
    source = 0x0288D330
    destination = 0x02E9B174
    submitted = bytearray(72)
    struct.pack_into("<I", submitted, 0x38, 0x01F23828)
    received = bytes(submitted)
    copied = received[:72]
    assert source + 0x38 == 0x0288D368
    assert destination + 0x38 == 0x02E9B1AC
    assert (source + 0x38) - source == (destination + 0x38) - destination
    assert struct.unpack_from("<I", copied, 0x38)[0] == 0x01F23828
    # ARM BLX(register) encoding retains Rm in the low nibble; the observed
    # call is BLX r3 after loading that register from copied record +0x38.
    assert (0xE12FFF33 & 0x0FFFFFF0) == 0x012FFF30
    assert (0xE12FFF33 & 0xF) == 3
    assert 0x02EA07A0 + 36 == 0x02EA07C4
    assert 0x38 + 4 <= 72


def test_mode6_registration_receive_descriptor_callback_offset_independent_vector() -> None:
    # The queued message has an 8-byte header. The receiver does NOT expose
    # that contiguous queue buffer to the handler: it copies the payload
    # through descriptor +8 into inline storage at descriptor +0x10.
    payload = bytearray(84)
    struct.pack_into("<I", payload, 0x38, 0x020366C4)
    struct.pack_into("<I", payload, 0x40, 0x12345678)
    wire = bytes(8) + bytes(payload)
    assert struct.unpack_from("<I", wire, 0x40)[0] == 0x020366C4
    assert struct.unpack_from("<I", wire, 0x48)[0] == 0x12345678
    descriptor = bytearray(232)
    descriptor[:8] = wire[:8]
    struct.pack_into("<I", descriptor, 8, 0x02E98398)
    descriptor[0x10 : 0x10 + len(payload)] = wire[8:]
    copied_descriptor = bytes(descriptor)
    # The inbound handler's +0x48 load is the outgoing payload +0x38
    # field after this receive layout and second descriptor copy.
    module_state_callback = struct.unpack_from("<I", copied_descriptor, 0x48)[0]
    assert module_state_callback == 0x020366C4
    assert struct.unpack_from("<I", copied_descriptor, 0x50)[0] == 0x12345678
    assert 0x025EEBA4 + 0x2C == 0x025EEBD0


def test_indexed_dispatch_first_entries_independent_fixture() -> None:
    image = bytearray(0x80)
    struct.pack_into("<III", image, 0x10, 0x1040, 0x1048, 0x1050)
    struct.pack_into("<II", image, 0x40, 0x1587, 0x211F110)
    struct.pack_into("<II", image, 0x48, 0x1529, 0x211F8D8)
    struct.pack_into("<II", image, 0x50, 0x1529, 0x211FEA4)
    assert read_indexed_dispatch_first_entries(image, 0x1000, 0x1010, 3) == [
        {"state": 0, "record_address": 0x1040, "message_id": 0x1587, "handler": 0x211F110},
        {"state": 1, "record_address": 0x1048, "message_id": 0x1529, "handler": 0x211F8D8},
        {"state": 2, "record_address": 0x1050, "message_id": 0x1529, "handler": 0x211FEA4},
    ]
    for table, count in ((0x100F, 3), (0x1010, 257), (0x1080, 3)):
        try:
            read_indexed_dispatch_first_entries(image, 0x1000, table, count)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid indexed dispatch bounds must fail closed")


def test_id200_conditional_bridge_record_indices_independent_vectors() -> None:
    # The source's callback tables are checked against the DAT separately.
    # These manually computed indices prove the A/B state arithmetic used by
    # the conditional receive -> publish chain, including the alternate A=0
    # branch that must not be conflated with its A=1 callback.
    assert arm_smlabb_record_index(1, 7, 0) == 7   # category 4
    assert arm_smlabb_record_index(0, 7, 0) == 0   # distinct category-4 path
    assert arm_smlabb_record_index(0, 8, 0) == 0   # category 5
    assert arm_smlabb_record_index(0, 1, 0) == 0   # category 79
    assert arm_smlabb_record_index(1, 3, 0) == 3   # category 22


def test_id200_sender_payload_source_address_independent_vector() -> None:
    # Caller records have three 32-bit words. The final two callers form
    # word 2 from a RAM base plus successive literal ARM immediates.
    assert 0x02EE9C08 + 0x74 == 0x02EE9C7C
    assert 0x02EE9C7C + 0x5D0 == 0x02EEA24C
    assert 0x02EE9B00 + 0x17C == 0x02EE9C7C
    assert 0x02EE9B00 + 0x17C + 0x5D0 == 0x02EEA24C
    assert 0x01734A8C != 0x02EEA24C  # first caller is a distinct source


def test_x100v_preview_code4_row_reuse_independent_fixture() -> None:
    # The source rows are observed X100V 16:9 vectors; candidate dimensions
    # are independently specified 65:24 vectors, not read back from the plan.
    image = bytearray(b"\xff" * (57 * 8))
    source = {
        5: (0, 1, 6240, 3512), 6: (0, 0, 6240, 3512),
        13: (1, 1, 4416, 2488), 14: (1, 0, 4416, 2488),
        21: (2, 1, 3120, 1760), 22: (2, 0, 3120, 1760),
        27: (3, 1, 4992, 2808), 28: (3, 0, 4992, 2808),
    }
    for index, (level, variant, width, height) in source.items():
        struct.pack_into("<BBBBHH", image, index * 8, level, variant, 2, 0, width, height)
    original = bytes(image)
    plan = plan_x100v_preview_code4_row_reuse(original, 0x1000, 0x1000, 57)
    assert original == bytes(image)  # planning is read-only
    assert [row["index"] for row in plan] == [5, 6, 13, 14, 21, 22]
    assert [row["height"] for row in plan] == [2304, 2304, 1632, 1632, 1152, 1152]
    assert [row["candidate_hex"] for row in plan] == [
        "0001040060180009", "0000040060180009",
        "0101040040116006", "0100040040116006",
        "02010400300c8004", "02000400300c8004",
    ]
    assert sum(len(row["changes"]) for row in plan) == 18
    assert [change["address"] for change in plan[0]["changes"]] == [0x102A, 0x102E, 0x102F]
    assert original[27 * 8:29 * 8] == bytes(image[27 * 8:29 * 8])
    image[5 * 8 + 2] = 4
    try:
        plan_x100v_preview_code4_row_reuse(bytes(image), 0x1000, 0x1000, 57)
    except ValueError as exc:
        assert "already contains" in str(exc)
    else:
        raise AssertionError("row reuse must reject preexisting code-4 rows")


def test_x100v_preview_zero_placeholder_reuse_preserves_16_9_fixture() -> None:
    image = bytearray(b"\xff" * 0x600)
    for index in range(24):
        code = {0: 0, 7: 1, 14: 2}.get(index, 0x100)
        enabled = 0 if index in (0, 7, 14) else 1
        struct.pack_into("<5I", image, 0x20 + 20 * index, index, code, 3120, 2080, enabled)
    placeholder_rows = {
        1: (0, 1), 2: (0, 0), 9: (1, 1),
        10: (1, 0), 17: (2, 1), 18: (2, 0),
    }
    active_16_9_rows = {
        5: (0, 1, 6240, 3512), 6: (0, 0, 6240, 3512),
        13: (1, 1, 4416, 2488), 14: (1, 0, 4416, 2488),
        21: (2, 1, 3120, 1760), 22: (2, 0, 3120, 1760),
    }
    for index, (level, variant) in placeholder_rows.items():
        struct.pack_into("<BBBBHH", image, 0x300 + 8 * index, level, variant, 0, 0, 0, 0)
    for index, (level, variant, width, height) in active_16_9_rows.items():
        struct.pack_into("<BBBBHH", image, 0x300 + 8 * index, level, variant, 2, 0, width, height)
    source = {
        "primary_load": 0x1000, "primary_table": 0x20,
        "preview_key_table": 0x1300, "preview_key_count": 57,
        "dimension_lookup_reference_code1": [[6240, 4160], [4416, 2944], [3120, 2080]],
    }
    original = bytes(image)
    plan = plan_x100v_preview_code4_zero_placeholder_reuse(original, source)
    assert bytes(image) == original
    assert [row["index"] for row in plan] == [1, 2, 9, 10, 17, 18]
    assert [row["candidate_hex"] for row in plan] == [
        "0001040060180009", "0000040060180009",
        "0101040040116006", "0100040040116006",
        "02010400300c8004", "02000400300c8004",
    ]
    assert sum(len(row["changes"]) for row in plan) == 28
    assert [row["old_key_nonbypass_after_index"] for row in plan] == [57] * 6
    assert [row["old_key_bypass_after_index"] for row in plan] == [0] * 6
    patched = bytearray(original)
    for row in plan:
        offset = 0x300 + 8 * row["index"]
        assert patched[offset:offset + 8] == bytes.fromhex(row["source_hex"])
        patched[offset:offset + 8] = bytes.fromhex(row["candidate_hex"])
    assert all(patched[0x300 + 8 * index:0x300 + 8 * (index + 1)] ==
               original[0x300 + 8 * index:0x300 + 8 * (index + 1)]
               for index in active_16_9_rows)
    assert [row["key"] for row in read_preview_key_table(patched, 0x1000, 0x1300, 57)
            if row["key"][2] == 4] == [
        [0, 1, 4], [0, 0, 4], [1, 1, 4], [1, 0, 4], [2, 1, 4], [2, 0, 4],
    ]
    before_rows = read_preview_key_table(original, 0x1000, 0x1300, 57)
    after_rows = read_preview_key_table(patched, 0x1000, 0x1300, 57)
    for row in plan:
        old_key = tuple(row["key_before"])
        new_key = tuple(row["key_after"])
        assert preview_key_lookup_index(before_rows, old_key) == row["index"]
        assert preview_key_lookup_index(after_rows, old_key) == 57
        assert preview_key_lookup_index(after_rows, new_key) == row["index"]
        assert preview_key_lookup_index(after_rows, old_key, bypass=True) == 0
    image[0x20 + 16] = 1
    try:
        plan_x100v_preview_code4_zero_placeholder_reuse(bytes(image), source)
    except ValueError as exc:
        assert "not all disabled" in str(exc)
    else:
        raise AssertionError("active code-0 size record must fail closed")


def test_preview_key_lookup_independent_vectors() -> None:
    rows = [
        {"index": 0, "key": [0, 3, 0]},
        {"index": 1, "key": [0, 1, 0]},
        {"index": 2, "key": [0, 1, 4]},
    ]
    assert preview_key_lookup_index(rows, (0, 1, 0)) == 1
    assert preview_key_lookup_index(rows, (0, 1, 4)) == 2
    assert preview_key_lookup_index(rows, (2, 1, 0)) == 3
    assert preview_key_lookup_index(rows, (0, 1, 4), bypass=True) == 0
    try:
        preview_key_lookup_index(rows, (256, 1, 0))
    except ValueError as exc:
        assert "three bytes" in str(exc)
    else:
        raise AssertionError("lookup must reject non-byte keys")


def test_addresses_share_4k_page_boundary_vectors() -> None:
    assert addresses_share_4k_page(0x128FAB0, 0x128FB14)
    assert addresses_share_4k_page(0x128F000, 0x128FFFF)
    assert not addresses_share_4k_page(0x128FFFF, 0x1290000)
    try:
        addresses_share_4k_page(-1, 0)
    except ValueError as exc:
        assert "nonnegative" in str(exc)
    else:
        raise AssertionError("negative address must fail closed")


def test_preview_parallel_extension_collision_independent_vector() -> None:
    assert preview_parallel_extension_overlaps_next_array(0x1004, 3, 5, 0x1010) == [
        0x1010, 0x1014,
    ]
    assert preview_parallel_extension_overlaps_next_array(0x1004, 3, 5, 0x1020) == []
    assert preview_parallel_extension_overlaps_next_array(
        0x0184E37C, 57, 63, 0x0184E460,
    ) == [0x0184E460, 0x0184E464, 0x0184E468, 0x0184E46C, 0x0184E470, 0x0184E474]
    for first, count, proposed, following in ((0x1003, 3, 5, 0x1010), (0x1004, 0, 5, 0x1010)):
        try:
            preview_parallel_extension_overlaps_next_array(first, count, proposed, following)
        except ValueError:
            pass
        else:
            raise AssertionError("unaligned address or invalid count must fail closed")


def test_x100v_size_crop_data_plan_independent_fixture() -> None:
    # Construct a synthetic 24-row source with distinct table offsets. The
    # vectors below are literal expectations, not derived from the planner.
    image = bytearray(0x500)
    for index in range(24):
        code = {4: 0x400, 11: 0x401, 18: 0x402}.get(index, 0x100)
        flags = {4: 0xF00, 11: 0x1300, 18: 0xB00}.get(index, 0x101)
        struct.pack_into("<5I", image, 0x20 + 20 * index, index, code, 3120, 2080, flags)
    for level, (width, height) in enumerate(((6240, 4160), (4416, 2944), (3120, 2080))):
        struct.pack_into("<I", image, 0x300 + 4 * (level * 5 + 1), width)
        struct.pack_into("<I", image, 0x380 + 4 * (level * 5 + 1), height)
    source = {
        "primary_load": 0x1000, "primary_table": 0x20,
        "dimension_lookup_width": 0x1300, "dimension_lookup_height": 0x1380,
        "dimension_lookup_columns": 5,
        "dimension_lookup_reference_code1": [[6240, 4160], [4416, 2944], [3120, 2080]],
    }
    original = bytes(image)
    plan = plan_x100v_size_and_raw_crop_lookup_data(original, source)
    assert image == original  # planner has no write effect
    assert len(plan) == 14
    by_field = {write["field"]: write for write in plan}
    assert by_field["size-4-width"]["after_hex"] == "60180000"
    assert by_field["size-4-height"]["after_hex"] == "00090000"
    assert by_field["size-11-width"]["after_hex"] == "40110000"
    assert by_field["size-11-height"]["after_hex"] == "60060000"
    assert by_field["size-18-height"]["after_hex"] == "80040000"
    assert "size-18-width" not in by_field
    assert [by_field[f"crop-height-{level}"]["address"] for level in range(3)] == [
        0x1390, 0x13A4, 0x13B8,
    ]
    assert {name for name in by_field if name.endswith("enabled")} == {
        "size-4-enabled", "size-11-enabled", "size-18-enabled",
    }
    patched = bytearray(original)
    for write in plan:
        offset = write["partition_offset"]
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        assert patched[offset:offset + len(before)] == before
        patched[offset:offset + len(before)] = after
    rows = parse_primary_records(patched, 0x20)
    assert [(rows[size_id]["width"], rows[size_id]["height"], rows[size_id]["enabled_byte"])
            for size_id in (4, 11, 18)] == [
        (6240, 2304, 1), (4416, 1632, 1), (3120, 1152, 1),
    ]
    assert [list(struct.unpack_from("<I", patched, 0x300 + 4 * (level * 5 + 4)))
            for level in range(3)] == [[6240], [4416], [3120]]
    image[0x300 + 4 * 4] = 1
    try:
        plan_x100v_size_and_raw_crop_lookup_data(bytes(image), source)
    except ValueError as exc:
        assert "occupied" in str(exc)
    else:
        raise AssertionError("occupied code-4 lookup cells must fail closed")


def test_secondary_triplet_fixture() -> None:
    rows = [(6240, 2304), (4416, 1632), (3120, 1152)]
    image = b"HEAD" + b"".join(struct.pack("<HHI", w, h, 177493) for w, h in rows) + b"TAIL"
    assert find_q16_triplets(image, 177493) == [{"partition_offset": 4, "sizes": [[w, h] for w, h in rows]}]


def test_primary_record_fixture() -> None:
    image = b"".join(struct.pack("<5I", i, 0x400 | (i % 3), 100 + i, 50 + i, 0xF01) for i in range(24))
    records = parse_primary_records(image, 0)
    assert records[4]["id"] == 4
    assert records[4]["enabled_byte"] == 1
    assert records[18]["width"] == 118


def test_consistency_requires_enabled_matching_dimensions() -> None:
    rows = [
        {"width": 6240, "height": 2304, "enabled_byte": 1},
        {"width": 4416, "height": 1632, "enabled_byte": 1},
        {"width": 3120, "height": 1152, "enabled_byte": 1},
    ]
    matching = [{"sizes": [[6240, 2304], [4416, 1632], [3120, 1152]]}]
    assert tables_consistent_and_enabled(rows, matching)
    assert not tables_consistent_and_enabled(rows, [])
    assert not tables_consistent_and_enabled(rows, [{"sizes": [[6240, 2304], [4416, 1632], [3120, 1150]]}])
    disabled = [dict(row) for row in rows]
    disabled[1]["enabled_byte"] = 0
    assert not tables_consistent_and_enabled(disabled, matching)


def test_static_lookup_and_labels_skip_disabled_rows() -> None:
    records = [
        {"id": 4, "code": 0x400, "width": 3120, "height": 2080, "enabled_byte": 0},
        {"id": 1, "code": 0x100, "width": 6240, "height": 4160, "enabled_byte": 1},
        {"id": 11, "code": 0x401, "width": 4416, "height": 1632, "enabled_byte": 1},
    ]
    assert select_enabled_size_id(records, 4, 0) is None
    assert select_size_id_without_enabled_gate(records, 4, 0) == 4
    assert select_enabled_size_id(records, 4, 1) == 11
    assert enabled_dimension_labels(records) == [
        {"id": 1, "label": "6240x4160"},
        {"id": 11, "label": "4416x1632"},
    ]


def test_develop_aspect_jump_table_fixture() -> None:
    image = b"HEAD" + struct.pack("<3I", 0x1000, 0x2000, 0x1000) + b"TAIL"
    assert decode_develop_aspect_jump_table(image, 4, 3, {0x1000: 1, 0x2000: 4}) == [1, 4, 1]
    try:
        decode_develop_aspect_jump_table(image, 4, 3, {0x1000: 1})
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("unknown jump target must fail closed")


def test_develop_aspect_case_alias_independent_fixture() -> None:
    # Three 16:9 input slots share one case body; a one-word change alters all
    # three outputs without changing the jump table's size or its pointers.
    image = bytearray(0x70)
    addresses = (0x1024, 0x1030, 0x103C)
    struct.pack_into("<9I", image, 0, *(addresses * 3))
    for address, code in zip(addresses, (1, 2, 3)):
        branch_address = address + 8
        displacement = (0x1060 - branch_address - 8) // 4
        struct.pack_into("<III", image, address - 0x1000,
                         0xE3A03000 | code, 0xE5C43002, 0xEA000000 | displacement)
    cases = read_develop_aspect_case_outputs(image, 0x1000, {address: code for address, code in zip(addresses, (1, 2, 3))})
    assert decode_develop_aspect_jump_table(image, 0, 9, cases) == [1, 2, 3] * 3
    struct.pack_into("<I", image, 0x30, 0xE3A03004)
    changed = read_develop_aspect_case_outputs(image, 0x1000, cases)
    assert decode_develop_aspect_jump_table(image, 0, 9, changed) == [1, 4, 3] * 3
    image[0x34] ^= 1
    try:
        read_develop_aspect_case_outputs(image, 0x1000, cases)
    except ValueError as exc:
        assert "case body" in str(exc)
    else:
        raise AssertionError("changed case byte store must fail closed")


def test_arm_word_chain_fixture_fails_on_changed_instruction() -> None:
    image = struct.pack("<3I", 0xE24B2034, 0xEB0129C2, 0xE5D13002)
    expected = {0x1000: 0xE24B2034, 0x1004: 0xEB0129C2, 0x1008: 0xE5D13002}
    verify_arm_words(image, 0x1000, expected)
    altered = bytearray(image)
    altered[8] ^= 1
    try:
        verify_arm_words(altered, 0x1000, expected)
    except ValueError as exc:
        assert "0x1008" in str(exc)
    else:
        raise AssertionError("changed instruction must fail closed")


def test_arm_bl_call_site_scan_independent_fixture() -> None:
    # ARM BL target = instruction address + 8 + sign-extended imm24 * 4.
    # The first call points forward to 0x1020; the second points backward
    # to 0x0ff0. A BLX-like word and a plain branch are not ARM BL calls.
    image = struct.pack("<4I", 0xEB000006, 0xEBFFFFF9, 0xFB000004, 0xEA000001)
    assert read_arm_bl_call_sites(image, 0x1000, 0x1020) == [0x1000]
    assert read_arm_bl_call_sites(image, 0x1000, 0x0FF0) == [0x1004]
    assert read_arm_bl_call_sites(image, 0x1000, 0x1024) == []
    try:
        read_arm_bl_call_sites(image[:-1], 0x1000, 0x1020)
    except ValueError as exc:
        assert "aligned" in str(exc)
    else:
        raise AssertionError("unaligned ARM image must fail closed")


def test_event_group_ids_independent_fixture() -> None:
    image = struct.pack("<III", 66, 0, 0x1234)
    image += struct.pack("<III", 44, 0, 0x5678)
    image += struct.pack("<III", 44, 0x9999, 0xABCD)
    image += struct.pack("<III", 0xFFFFFFFF, 0, 0)
    assert read_event_group_ids(image, 0x1000, 0x1000) == [66, 44, 44]
    try:
        read_event_group_ids(image[:-12], 0x1000, 0x1000)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("unterminated event group must fail closed")
    try:
        read_event_group_ids(image, 0x1000, 0x1000, max_entries=2)
    except ValueError as exc:
        assert "terminator" in str(exc)
    else:
        raise AssertionError("bounded event group must fail closed")


def test_event_group_table_independent_fixture_and_bounds() -> None:
    image = bytearray(0x60)
    struct.pack_into("<IIIIII", image, 0, 13, 0x1020, 34, 0x1040, 0xFFFFFFFF, 0)
    struct.pack_into("<IIIIII", image, 0x20, 58, 0, 0x1060, 0xFFFFFFFF, 0, 0)
    struct.pack_into("<IIIIII", image, 0x40, 44, 0, 0x1064, 0xFFFFFFFF, 0, 0)
    assert read_event_group_table(image, 0x1000, 0x1000) == {13: [58], 34: [44]}
    try:
        read_event_group_table(image, 0x1000, 0x1000, max_groups=1)
    except ValueError as exc:
        assert "terminator" in str(exc)
    else:
        raise AssertionError("bounded group table must fail closed")
    struct.pack_into("<I", image, 8, 13)
    try:
        read_event_group_table(image, 0x1000, 0x1000)
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("duplicate groups must fail closed")


def test_recbf_message_bit_routes_independent_fixture() -> None:
    image = bytearray(48)
    struct.pack_into("<HHB3xII", image, 0, 0x923B, 0x1D, 42, 103, 0)
    struct.pack_into("<HHB3xII", image, 16, 0x923B, 0xED, 42, 103, 0)
    assert read_recbf_message_bit_routes(image, 0x1000, 0x1000) == [
        {"index": 0, "command": 0x923B, "subtype": 0x1D, "selector": 42, "bit_id": 103, "callback": 0},
        {"index": 1, "command": 0x923B, "subtype": 0xED, "selector": 42, "bit_id": 103, "callback": 0},
    ]
    try:
        read_recbf_message_bit_routes(image, 0x1000, 0x1000, max_entries=1)
    except ValueError as exc:
        assert "terminator" in str(exc)
    else:
        raise AssertionError("bounded message-bit scan must fail closed")
    try:
        read_recbf_message_bit_routes(image[:32], 0x1000, 0x1000)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("unterminated message-bit scan must fail closed")


def test_recbf_completion_stage_subtypes_independent_fixture() -> None:
    image = bytearray(4 * 40)
    image[0] = 0x40  # unrelated selector 8
    image[16] = 8
    image[40] = 0x93
    struct.pack_into("<HH", image, 42, 0x126, 0x127)
    image[56] = 0
    image[80] = 0x94
    struct.pack_into("<HH", image, 82, 0x128, 0x129)
    image[96] = 1
    image[120] = 0x9E
    image[136] = 9
    assert read_recbf_completion_stage_subtypes(image, 0x1000, 0x1000) == {
        0: (0x126, 0x127), 1: (0x128, 0x129),
    }
    for damaged, bound, expected in ((image[:120], 4, "outside"), (image, 2, "terminator")):
        try:
            read_recbf_completion_stage_subtypes(
                damaged, 0x1000, 0x1000, max_entries=bound,
            )
        except ValueError as exc:
            assert expected in str(exc)
        else:
            raise AssertionError("bounded completion-stage scan must fail closed")
    image[96] = 0
    try:
        read_recbf_completion_stage_subtypes(image, 0x1000, 0x1000)
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("duplicate completion-stage selector must fail closed")


def test_preview_1159_message_row_independent_fixture() -> None:
    # Literal 16-byte row plus an all-zero terminator; -1 is not a crop bit.
    image = bytes.fromhex(
        "5911000000000000ffffffff00000000"
        "00000000000000000000000000000000"
    )
    assert read_recbf_message_bit_routes(image, 0x2000, 0x2000) == [
        {"index": 0, "command": 0x1159, "subtype": 0,
         "selector": 0, "bit_id": 0xFFFFFFFF, "callback": 0}
    ]


def test_preview_1159_controller_row_independent_fixture() -> None:
    # Five two-byte cells in row 2, after two unrelated synthetic rows.
    image = bytearray(b"\xff" * 40)
    image[20:30] = bytes.fromhex("04ff 0501 0301 0301 0301")
    row = read_recbf_action_row(image, 0x2000, 0x2000, 5, 2)
    assert row == [[4, 255], [5, 1], [3, 1], [3, 1], [3, 1]]
    assert all(callback != 2 for callback, _ in row)


def test_gfx_short_crop_message_row_independent_fixture() -> None:
    image = bytearray(32)
    struct.pack_into("<HHB3xII", image, 0, 0x9240, 0x21, 46, 114, 0)
    assert read_recbf_message_bit_routes(image, 0x2000, 0x2000) == [
        {"index": 0, "command": 0x9240, "subtype": 0x21, "selector": 46, "bit_id": 114, "callback": 0},
    ]


def test_recbf_script_table_fixture_and_boundary() -> None:
    image = bytearray(80)
    struct.pack_into("<II", image, 0, 0, 0x1010)
    struct.pack_into("<II", image, 8, 1, 0x1020)
    image[16:20] = b"\x15\x17\x9d\x9e"
    image[32:35] = b"\x16\x9d\x9e"
    assert read_recbf_script_table(image, 0x1000, 0x1000, 2, 0x9E) == {
        0: b"\x15\x17\x9d\x9e", 1: b"\x16\x9d\x9e",
    }
    image[19] = 0x7C
    image[34] = 0x7C
    assert read_recbf_script_table(image, 0x1000, 0x1000, 2, 0x7C) == {
        0: b"\x15\x17\x9d\x7c", 1: b"\x16\x9d\x7c",
    }
    image[4] = 0x20
    try:
        read_recbf_script_table(image, 0x1000, 0x1000, 2, 0x9E)
    except ValueError as exc:
        assert "boundary" in str(exc)
    else:
        raise AssertionError("changed script-table boundary must fail closed")


def test_recbf_script_order_independent_fixture() -> None:
    verify_recbf_script_order(bytes.fromhex("15 1f 27 9c 9e"), (0x15, 0x27))
    verify_recbf_script_order(bytes.fromhex("27 3c 3d 9d 9e"), (0x27, 0x3C, 0x3D))
    for script, commands in (
        (bytes.fromhex("27 15 9e"), (0x15, 0x27)),
        (bytes.fromhex("15 9e"), (0x15, 0x27)),
        (bytes.fromhex("15 27 27 9e"), (0x15, 0x27)),
    ):
        try:
            verify_recbf_script_order(script, commands)
        except ValueError as exc:
            assert "Recbf script" in str(exc)
        else:
            raise AssertionError("missing, reordered, or repeated commands must fail closed")


def test_long_script_prerequisite_and_compression_order_independent_fixture() -> None:
    mode35 = bytes.fromhex("04 0e 15 27 9c 9e")
    mode37 = bytes.fromhex("04 0e 15 9c 9e")
    mode36 = bytes.fromhex("04 76 0e 9c 9e")
    verify_recbf_script_order(mode35, (0x0E, 0x15, 0x27, 0x9C))
    verify_recbf_script_order(mode37, (0x0E, 0x15, 0x9C))
    verify_recbf_script_order(mode36, (0x76, 0x0E, 0x9C))
    assert 0x27 not in mode37
    try:
        verify_recbf_script_order(mode37, (0x0E, 0x15, 0x27, 0x9C))
    except ValueError as exc:
        assert "0x27" in str(exc)
    else:
        raise AssertionError("mode 37 must not be mistaken for crop-to-compress")


def test_compression_result_slot_offsets_independent_vector() -> None:
    # The pinned ARM setup uses context + 0x4800 + 0xf4 + variant*32;
    # the initializer clears six 32-byte records up to (not including) 0x49b4.
    offsets = [0x48F4 + variant * 0x20 for variant in range(6)]
    assert offsets == [0x48F4, 0x4914, 0x4934, 0x4954, 0x4974, 0x4994]
    assert offsets[-1] + 0x20 == 0x49B4
    assert offsets[1] == 0x4914  # command 0x27 passes variant 1


def test_save_jpeg_buffer_record_layout_independent_vector() -> None:
    # Synthetic layout only: it checks address arithmetic, not camera output.
    record_stride = 368
    pair_stride = 8
    offsets = [(row, entry, 0x3E68 + row * record_stride + entry * pair_stride)
               for row, entry in ((0, 0), (0, 15), (1, 0), (1, 15))]
    assert offsets == [(0, 0, 0x3E68), (0, 15, 0x3EE0),
                       (1, 0, 0x3FD8), (1, 15, 0x4050)]
    assert 0x3E68 + 16 * pair_stride == 0x3EE8
    assert 0x3EF0 - 0x3EE8 == 8  # pathname follows the 16 pairs, with an 8-byte gap
    jpeg_like = b"\xff\xd8\x00\xff\xd9"
    assert jpeg_like[-2:] == b"\xff\xd9"
    assert int.from_bytes(jpeg_like[-2:], "big") == 0xFFD9


def test_exif_tag_buffer_handoff_independent_vectors() -> None:
    # Synthetic command streams and addresses, not proof of ordinary-still execution.
    verify_recbf_script_order(bytes.fromhex("36 27 35 3c 3d 9e"), (0x36, 0x27, 0x35, 0x3C, 0x3D))
    verify_recbf_script_order(bytes.fromhex("15 27 35 9e"), (0x15, 0x27, 0x35))
    assert [0x3E60 + row * 368 for row in range(3)] == [0x3E60, 0x3FD0, 0x4140]
    assert [0x3E68 + row * 368 for row in range(3)] == [0x3E68, 0x3FD8, 0x4148]
    assert 0x3E68 - 0x3E60 == 8
    try:
        verify_recbf_script_order(bytes.fromhex("35 27 3c 9e"), (0x27, 0x35, 0x3C))
    except ValueError as exc:
        assert "order" in str(exc)
    else:
        raise AssertionError("EXIF tag before compression must not count as the observed order")


def test_crop_to_exif_command_order_independent_fixture() -> None:
    # These are synthetic streams, not evidence that a camera runs the modes.
    verify_recbf_script_order(bytes.fromhex("15 1f 30 29 27 9e"), (0x15, 0x30, 0x27))
    verify_recbf_script_order(bytes.fromhex("15 31 1a 32 9e"), (0x15, 0x31, 0x32))
    verify_recbf_script_order(bytes.fromhex("33 2a 30 3c 3d 9e"), (0x33, 0x30, 0x3C, 0x3D))
    try:
        verify_recbf_script_order(bytes.fromhex("30 15 27 9e"), (0x15, 0x30, 0x27))
    except ValueError as exc:
        assert "order" in str(exc)
    else:
        raise AssertionError("EXIF header before crop must not count as crop-to-EXIF")


def test_recbf_action_matrix_independent_fixture() -> None:
    # Two bytes per cell: callback index, then a signed post-callback code.
    # Positive codes select a follow-up; negative codes change the column.
    # Rows are classified events; columns are controller-state offsets.
    image = bytearray(b"HEAD" + bytes((3, 1)) * 12)
    image[4 + 2 * (1 * 4 + 1):4 + 2 * (1 * 4 + 1) + 2] = bytes((8, 1))
    image[4 + 2 * (2 * 4 + 3):4 + 2 * (2 * 4 + 3) + 2] = bytes((8, 2))
    assert read_recbf_action_hits(image, 0x1000, 0x1004, 3, 4, 8) == [
        {"event_row": 1, "state_column": 1, "post_callback_code": 1},
        {"event_row": 2, "state_column": 3, "post_callback_code": 2},
    ]
    try:
        read_recbf_action_hits(image[:-1], 0x1000, 0x1004, 3, 4, 8)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("truncated action matrix must fail closed")


def test_recbf_action_row_independent_fixture() -> None:
    image = b"HEAD" + bytes((3, 1, 4, 255, 7, 253, 8, 1))
    assert read_recbf_action_row(image, 0x1000, 0x1004, 2, 1) == [[7, 253], [8, 1]]
    try:
        read_recbf_action_row(image[:-1], 0x1000, 0x1004, 2, 1)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("truncated action row must fail closed")


def test_mode7_11b9_row_column0_independent_fixture() -> None:
    # Four two-byte cells per row. Row 1 selects callback 4 only at column 0.
    image = bytes.fromhex("02 01 03 01 03 01 03 01 04 01 03 01 03 01 03 01")
    assert read_recbf_action_row(image, 0x1000, 0x1000, 4, 1) == [
        [4, 1], [3, 1], [3, 1], [3, 1],
    ]


def test_nested_11b9_mode0_mode1_rows_independent_fixture() -> None:
    # Mode 0 row 15 selects callback 13 only in column 1.
    mode0 = bytes.fromhex("03 01 0d 01 03 01 03 01 03 01")
    assert read_recbf_action_row(mode0, 0x1000, 0x1000 - 15 * 10, 5, 15) == [
        [3, 1], [13, 1], [3, 1], [3, 1], [3, 1],
    ]
    # Mode 1 row 7 selects callback 7 only in column 0.
    mode1 = bytes.fromhex("07 01 03 01 03 01 03 01 03 01")
    assert read_recbf_action_row(mode1, 0x1000, 0x1000 - 7 * 10, 5, 7) == [
        [7, 1], [3, 1], [3, 1], [3, 1], [3, 1],
    ]


def test_recbf_record_pointer_fixture_fails_on_changed_word() -> None:
    image = bytearray(struct.pack("<II", 0x22095A0, 0x002A0015))
    verify_data_words(image, 0x2000, {0x2000: 0x22095A0, 0x2004: 0x002A0015})
    image[4] ^= 1
    try:
        verify_data_words(image, 0x2000, {0x2004: 0x002A0015})
    except ValueError as exc:
        assert "0x2004" in str(exc)
    else:
        raise AssertionError("changed Recbf record word must fail closed")


def test_aspect_dimension_grid_independent_vector() -> None:
    # Row-major 3x5: code 4 is the fifth column, not a fourth size level.
    rows = [[10, 11, 12, 13, 0], [20, 21, 22, 23, 0], [30, 31, 32, 33, 0]]
    image = b"HEAD" + struct.pack("<15I", *(value for row in rows for value in row))
    assert read_aspect_dimension_grid(image, 0x1000, 0x1004, 3, 5) == rows
    gfx_style_rows = [[1, 2, 3, 4, 11648, 6, 7, 0], [1, 2, 3, 4, 8256, 6, 7, 0], [1, 2, 3, 4, 4000, 6, 7, 0]]
    gfx_style_image = struct.pack("<24I", *(value for row in gfx_style_rows for value in row))
    assert read_aspect_dimension_grid(gfx_style_image, 0x2000, 0x2000, 3, 8) == gfx_style_rows
    try:
        read_aspect_dimension_grid(image, 0x1000, 0x1004, 4, 5)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("truncated dimension grid must fail closed")


def test_vg_geometry_record_independent_fixture() -> None:
    # 17 records/family and a 32-byte stride; only family 0 is cropped.
    image = bytearray(3 * 17 * 32)
    cropped = (0, 0, 1024, 768, 0, 195, 1024, 378, 1024, 768, 1600, 0)
    wide = (0, 0, 900, 600, 0, 47, 900, 506, 900, 600, 900, 0)
    uncropped = (0, 0, 900, 600, 0, 0, 900, 600, 900, 600, 900, 0)
    struct.pack_into("<12H", image, 2 * 32, *wide)
    struct.pack_into("<12H", image, 4 * 32, *cropped)
    struct.pack_into("<12H", image, (17 + 4) * 32, *uncropped)
    assert read_vg_geometry_record(image, 0x1000, 0x1000, 0, 4) == {
        "outer": [0, 0, 1024, 768],
        "inner": [0, 195, 1024, 378],
        "source": [1024, 768, 1600, 0],
    }
    assert read_vg_geometry_record(image, 0x1000, 0x1000, 0, 2) == {
        "outer": [0, 0, 900, 600],
        "inner": [0, 47, 900, 506],
        "source": [900, 600, 900, 0],
    }
    family_one = read_vg_geometry_record(image, 0x1000, 0x1000, 1, 4)
    assert family_one["outer"] == family_one["inner"] == [0, 0, 900, 600]
    for family, row in ((3, 4), (0, 17)):
        try:
            read_vg_geometry_record(image, 0x1000, 0x1000, family, row)
        except ValueError as exc:
            assert "outside" in str(exc)
        else:
            raise AssertionError("invalid VG geometry index must fail closed")


def test_vg_channel_route_independent_fixture() -> None:
    image = bytearray(80)
    image[0] = 0
    image[16] = 1
    image[32] = 2
    image[64:70] = bytes((7, 1, 8, 1, 9, 0))
    assert read_vg_channel_routes(image, 0x1000, 0x1000, 0x1040) == [
        {"descriptor_id": 0, "context_index": 1},
        {"descriptor_id": 1, "context_index": 1},
        {"descriptor_id": 2, "context_index": 0},
    ]
    image[32] = 20
    try:
        read_vg_channel_routes(image, 0x1000, 0x1000, 0x1040)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("out-of-range context map must fail closed")


def test_crop_ratio_jump_target_independent_fixture() -> None:
    # ARM helper branches through seven absolute addresses beginning at +0x18.
    image = bytearray(0x40)
    struct.pack_into("<7I", image, 0x18, 0x2010, 0x2020, 0x2030, 0x2040, 0x2050, 0x2060, 0x2070)
    assert read_crop_ratio_jump_target(image, 0x1000, 0x1000, 4) == 0x2040
    assert read_crop_ratio_jump_target(image, 0x1000, 0x1000, 7) == 0x2070
    for code in (0, 8):
        try:
            read_crop_ratio_jump_target(image, 0x1000, 0x1000, code)
        except ValueError as exc:
            assert "outside seven-way" in str(exc)
        else:
            raise AssertionError("invalid ratio aspect code must fail closed")
    try:
        read_crop_ratio_jump_target(image[:0x20], 0x1000, 0x1000, 4)
    except ValueError as exc:
        assert "outside primary" in str(exc)
    else:
        raise AssertionError("truncated ratio jump table must fail closed")


def test_crop_ratio_shared_default_vs_dedicated_code4_independent_fixture() -> None:
    # Synthetic X/GFX-shaped tables expose the aliasing that makes default
    # edits unsafe as an isolated code-4 modification.
    x_image = bytearray(0x40)
    gfx_image = bytearray(0x40)
    struct.pack_into("<7I", x_image, 0x18, 0x2010, 0x2020, 0x2030, 0x2040, 0x2040, 0x2040, 0x2070)
    struct.pack_into("<7I", gfx_image, 0x18, 0x3010, 0x3020, 0x3030, 0x3040, 0x3050, 0x3060, 0x3070)
    x_targets = [read_crop_ratio_jump_target(x_image, 0x1000, 0x1000, code) for code in range(1, 8)]
    gfx_targets = [read_crop_ratio_jump_target(gfx_image, 0x1000, 0x1000, code) for code in range(1, 8)]
    assert [code for code, target in enumerate(x_targets, 1) if code != 4 and target == x_targets[3]] == [5, 6]
    assert [code for code, target in enumerate(gfx_targets, 1) if code != 4 and target == gfx_targets[3]] == []


def test_arm_unconditional_b_independent_gfx_vector_and_bounds() -> None:
    # GFX's actual code-4 block at 0x01341b14 contains ea000007 and jumps
    # over seven ARM instruction words to the common multiply at 0x01341b38.
    assert encode_arm_unconditional_b(0x1341B14, 0x1341B38) == 0xEA000007
    assert encode_arm_unconditional_b(0x1200, 0x11F0) == 0xEAFFFFFA
    for source, target in ((0x1201, 0x11F0), (0x1200, 0x11F2),
                           (0x1200, 0x1200 + (1 << 25) + 8)):
        try:
            encode_arm_unconditional_b(source, target)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid ARM B displacement must fail closed")


def test_aligned_arm_cave_reference_scan_independent_fixture() -> None:
    image = bytearray(0x40)
    struct.pack_into("<I", image, 0, 0x2004)
    struct.pack_into("<I", image, 0x10, encode_arm_unconditional_b(0x1010, 0x2008))
    assert scan_aligned_arm_cave_references(image, 0x1000, 0x2000, 0x2010) == {
        "literal_word_addresses": [0x1000],
        "arm_b_bl_instruction_addresses": [0x1010],
    }
    image[0:4] = b"\x00" * 4
    image[0x10:0x14] = b"\x00" * 4
    assert scan_aligned_arm_cave_references(image, 0x1000, 0x2000, 0x2010) == {
        "literal_word_addresses": [], "arm_b_bl_instruction_addresses": [],
    }


def test_x100v_code4_ratio_stub_read_only_fixture() -> None:
    load, helper, stub = 0x1000, 0x1100, 0x1400
    default, common = 0x1134, 0x116C
    original_targets = [0x1140, 0x114C, 0x1164, default, default, default, 0x1158]
    image = bytearray(0x600)
    struct.pack_into("<7I", image, helper - load + 0x18, *original_targets)
    struct.pack_into("<I", image, default - load, 0xE3A02003)
    struct.pack_into("<I", image, default + 4 - load, 0xE3A0E004)
    struct.pack_into("<I", image, common - load, 0xE00C0E91)
    source = {
        "primary_load": load, "crop_ratio_helper": helper,
        "crop_ratio_code4_target": default,
        "crop_ratio_code4_stub_candidate": stub,
        "crop_ratio_code4_stub_pad_end": 0x1500,
        "crop_ratio_dispatch_targets_expected": original_targets,
    }
    original = bytes(image)
    plan = plan_x100v_code4_ratio_stub(original, source)
    assert bytes(image) == original
    assert [write["address"] for write in plan["writes"]] == [0x1124, 0x1400]
    assert [write["before_hex"] for write in plan["writes"]] == [
        "34110000", "000000000000000000000000",
    ]
    assert plan["stub_words"][:2] == ["0xe3a02018", "0xe3a0e041"]
    assert plan["unchanged_codes"] == [1, 2, 3, 5, 6, 7]
    assert plan["executable_mapping_verified"] is False
    patched = bytearray(original)
    for write in plan["writes"]:
        offset = write["partition_offset"]
        before = bytes.fromhex(write["before_hex"])
        after = bytes.fromhex(write["after_hex"])
        assert patched[offset:offset + len(before)] == before
        patched[offset:offset + len(before)] = after
    assert [read_crop_ratio_jump_target(patched, load, helper, code) for code in range(1, 8)] == [
        *original_targets[:3], stub, *original_targets[4:],
    ]
    assert patched[default - load:default + 8 - load] == original[default - load:default + 8 - load]
    branch_word = struct.unpack_from("<I", patched, stub + 8 - load)[0]
    signed_words = branch_word & 0xFFFFFF
    if signed_words & 0x800000:
        signed_words -= 0x1000000
    assert stub + 8 + 8 + signed_words * 4 == common
    assert patched[stub - load:stub + 8 - load] == bytes.fromhex("1820a0e341e0a0e3")
    image[stub - load + 80] = 1
    try:
        plan_x100v_code4_ratio_stub(bytes(image), source)
    except ValueError as exc:
        assert "occupied" in str(exc)
    else:
        raise AssertionError("occupied candidate padding must fail closed")
    image[stub - load + 80] = 0
    struct.pack_into("<I", image, helper - load + 0x24, 0x114C)
    try:
        plan_x100v_code4_ratio_stub(bytes(image), source)
    except ValueError as exc:
        assert "dispatch" in str(exc)
    else:
        raise AssertionError("changed code-4 dispatch must fail closed")
