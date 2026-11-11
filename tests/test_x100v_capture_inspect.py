import struct

import pytest

from tools.x100v_capture_inspect import (
    classify,
    crop_centered_on_control,
    inspect_jpeg,
    jpeg_sof_and_exif,
    raf_header,
    xtrans_aligned_match,
    xpan_pair_gate,
    xpan_pair_gates,
)


def exif_segment(model: bytes, software: bytes) -> bytes:
    """Little-endian TIFF: IFD0 with Model/Software, EXIF IFD with pixel size."""
    entries0 = [(0x0110, 2, len(model) + 1, None), (0x0131, 2, len(software) + 1, None), (0x8769, 4, 1, None)]
    ifd0 = 8
    data_at = ifd0 + 2 + 12 * len(entries0) + 4
    exif_ifd = data_at + len(model) + 1 + len(software) + 1
    tiff = bytearray(b"II*\0" + struct.pack("<I", ifd0))
    tiff += struct.pack("<H", len(entries0))
    tiff += struct.pack("<HHII", 0x0110, 2, len(model) + 1, data_at)
    tiff += struct.pack("<HHII", 0x0131, 2, len(software) + 1, data_at + len(model) + 1)
    tiff += struct.pack("<HHII", 0x8769, 4, 1, exif_ifd)
    tiff += struct.pack("<I", 0) + model + b"\0" + software + b"\0"
    tiff += struct.pack("<H", 2) + struct.pack("<HHII", 0xA002, 4, 1, 6240) + struct.pack("<HHII", 0xA003, 4, 1, 2304)
    tiff += struct.pack("<I", 0)
    body = b"Exif\0\0" + bytes(tiff)
    return b"\xff\xe1" + struct.pack(">H", len(body) + 2) + body


def jpeg(width: int, height: int, exif: bytes = b"") -> bytes:
    sof = b"\x08" + struct.pack(">HH", height, width) + b"\x01\x01\x11\x00"
    return b"\xff\xd8" + exif + b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof + b"\xff\xda\x00\x02\xff\xd9"


def test_own_jpeg_parser_reads_sof_and_nested_exif():
    info = jpeg_sof_and_exif(jpeg(6240, 2304, exif_segment(b"X100V", b"Digital Camera X100V Ver3.01")))
    assert info["sof"] == (6240, 2304)
    assert info["exif"] == {"model": "X100V", "software": "Digital Camera X100V Ver3.01",
                            "pixel_x": 6240, "pixel_y": 2304}


def test_inspect_jpeg_cross_checks_with_pillow(tmp_path):
    from PIL import Image

    path = tmp_path / "xpan.jpg"
    Image.new("RGB", (4416, 1628)).save(path)
    report = inspect_jpeg(path)
    assert report["routes_agree"] and report["size_class"] == "M"
    assert report["aspect"] == round(4416 / 1628, 4)


def raf(records: dict, embedded: bytes) -> bytes:
    head = bytearray(0x94)
    head[:16] = b"FUJIFILMCCD-RAW "
    head[0x1C:0x21] = b"X100V"
    head[0x3C:0x40] = b"0301"
    cfa_hdr = struct.pack(">I", len(records)) + b"".join(
        struct.pack(">HHHH", tag, 4, *value) for tag, value in records.items())
    jpeg_off = len(head)
    hdr_off = jpeg_off + len(embedded)
    struct.pack_into(">6I", head, 0x54, jpeg_off, len(embedded), hdr_off, len(cfa_hdr), hdr_off + len(cfa_hdr), 1234)
    return bytes(head) + embedded + cfa_hdr


def test_own_raf_parser_reads_stock_records():
    info = raf_header(raf({0x100: (4182, 6384), 0x110: (13, 6), 0x111: (4160, 6240), 0x115: (2, 3)},
                          jpeg(4416, 2944)))
    assert info["model"] == "X100V" and info["firmware"] == "0301"
    assert info["embedded_jpeg"] == (4416, 2944)
    assert info["cropped_size"] == (4160, 6240) and info["crop_top_left"] == (13, 6)
    assert info["cfa_bytes"] == 1234


def test_raf_header_exposes_embedded_jpeg_exif_and_bounds():
    embedded = jpeg(4416, 2944, exif_segment(b"X100V", b"Digital Camera X100V Ver3.01"))
    info = raf_header(raf({0x115: (24, 65)}, embedded))
    assert info["embedded_jpeg"] == (4416, 2944)
    assert (info["embedded_jpeg_exif"]["pixel_x"], info["embedded_jpeg_exif"]["pixel_y"]) == (6240, 2304)
    assert (info["embedded_jpeg_offset"], info["embedded_jpeg_length"]) == (0x94, len(embedded))


def test_xpan_pair_gate_rejects_card5d_style_raf_preview_and_missing_metadata():
    jpg = {"file": "DSCF1.JPG", "own_sof": (6240, 2304), "routes_agree": True,
           "exif": {"pixel_x": 6240, "pixel_y": 2304}}
    control = {"own": {"model": "X100V", "raw_full_size": (4182, 6384),
                       "crop_top_left": (13, 6), "cropped_size": (4160, 6240),
                       "cfa_bytes": 100}, "libraw": {"raw": (6384, 4182)}}
    raw = {"file": "DSCF1.RAF", "own": {"aspect_ratio": (24, 65),
            "embedded_jpeg": (4416, 1632),
            "embedded_jpeg_exif": {"pixel_x": 4416, "pixel_y": 1632},
            "cropped_size": (2304, 6240), "crop_top_left": (941, 6),
            "model": "X100V", "raw_full_size": (4182, 6384), "cfa_bytes": 100},
           "embedded_jpeg_routes_agree": True,
           "libraw": {"raw": (6384, 4182)},
           "libraw_crop_aspect": round(6240 / 2304, 4), "crop_routes_agree": True}
    accepted = xpan_pair_gate(jpg, raw, control)
    assert accepted["pass"]
    assert "raw_inset_crops[0]" in accepted["scope"]
    assert "not aspect/user crop [1]" in accepted["scope"]
    assert not xpan_pair_gate(jpg, raw)["pass"]
    card5d = {**raw, "own": {**raw["own"], "embedded_jpeg": (4416, 2944),
                            "embedded_jpeg_exif": {"pixel_x": 4416, "pixel_y": 2944},
                            "cropped_size": (4160, 6240)},
              "libraw_crop_aspect": round(6240 / 4160, 4)}
    rejected = xpan_pair_gate(jpg, card5d, control)
    assert not rejected["pass"]
    assert not rejected["checks"]["raf_preview_6524"]
    assert not rejected["checks"]["raf_crop_metadata_6524"]
    assert not rejected["checks"]["raf_independent_reader_6524"]
    assert not xpan_pair_gate({**jpg, "exif": {}}, raw, control)["pass"]
    assert not xpan_pair_gate(jpg, {**raw, "embedded_jpeg_routes_agree": False}, control)["pass"]
    assert not xpan_pair_gate(jpg, {**raw, "libraw_crop_aspect": None}, control)["pass"]


def test_xpan_crop_center_gate_rejects_off_center_and_wrong_control():
    control = {"own": {"model": "X100V", "raw_full_size": (4182, 6384),
                       "crop_top_left": (13, 6), "cropped_size": (4160, 6240),
                       "cfa_bytes": 100}, "libraw": {"raw": (6384, 4182)}}
    raf = {"own": {"model": "X100V", "raw_full_size": (4182, 6384),
                   "crop_top_left": (941, 6), "cropped_size": (2304, 6240),
                   "cfa_bytes": 100}, "libraw": {"raw": (6384, 4182)}}
    assert crop_centered_on_control(raf, control)
    assert not crop_centered_on_control({**raf, "own": {**raf["own"], "crop_top_left": (13, 6)}}, control)
    assert not crop_centered_on_control({**raf, "own": {**raf["own"],
                                                  "crop_top_left": (941, 126),
                                                  "cropped_size": (2304, 6000)}}, control)
    assert not crop_centered_on_control(raf, {**control, "own": {**control["own"], "model": "GFX100"}})
    assert not crop_centered_on_control(raf, {**control, "own": {**control["own"], "cfa_bytes": 99}})


def test_xpan_pair_collection_fails_closed_on_missing_or_duplicate_files():
    jpg = {"file": "DSCF1.JPG"}
    raw = {"file": "DSCF1.RAF"}
    assert xpan_pair_gates([jpg])["DSCF1"] == {"pass": False, "missing": ["raf"]}
    assert xpan_pair_gates([raw])["DSCF1"] == {"pass": False, "missing": ["jpeg"]}
    assert xpan_pair_gates([jpg, jpg, raw])["DSCF1"] == {"pass": False, "duplicate": True}


def test_xtrans_alignment_rule_matches_stock_control_and_rejects_others():
    libraw = {"crop_margin": (6, 18), "crop": (6240, 4155)}
    assert xtrans_aligned_match((6240, 4160), (13, 6), libraw)
    assert not xtrans_aligned_match((6240, 4160), (12, 6), libraw)
    assert not xtrans_aligned_match((6240, 2304), (13, 6), libraw)
    assert xtrans_aligned_match((6240, 2304), (941, 6), {"crop_margin": (6, 942), "crop": (6240, 2303)})


@pytest.mark.parametrize("cfa,raw,expected", [
    (100, (6384, 4182), "soft crop"),
    (60, (6384, 2400), "physically reduced"),
])
def test_classification_compares_sensor_extent_with_control(cfa, raw, expected):
    control = {"own": {"cfa_bytes": 100}, "libraw": {"raw": (6384, 4182)}}
    xpan = {"crop_aspect": round(6240 / 2304, 4), "own": {"cfa_bytes": cfa}, "libraw": {"raw": raw}}
    assert expected in classify(xpan, control)
    assert classify({**xpan, "crop_aspect": 1.5}, control) == "not 65:24"
