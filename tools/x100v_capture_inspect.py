"""Read-only JPEG/RAF inspection for X100V 65:24 capture acceptance.

Each file is read by two routes: parsers written here (JPEG SOF/EXIF, RAF
header and CFA records) and third-party libraries (Pillow for JPEG pixels,
LibRaw through rawpy for RAF sensor data and the standard image area).
rawpy.sizes exposes LibRaw raw_inset_crops[0], not the aspect/user crop [1];
its full-height result alone cannot reject a camera-native soft RAW crop.
Disagreement between routes is reported, never resolved silently.

Classification separates a metadata-only ("soft") RAF crop from a physically
cropped mosaic by comparing sensor extent with a stock 3:2 control capture.
Nothing here writes to a camera or card.
"""

from __future__ import annotations

import argparse
import io
import json
import struct
from pathlib import Path

TARGET = 65 / 24
STOCK_32 = 3 / 2
# Ratio-helper output (round down to 4) and enabled size rows (round to 8)
# disagree only for M; both are accepted and reported.
XPAN_JPEG_SIZES = {"L": [(6240, 2304)], "M": [(4416, 1628), (4416, 1632)], "S": [(3120, 1152)]}
RAF_TAGS = {0x100: "raw_full_size", 0x110: "crop_top_left", 0x111: "cropped_size",
            0x115: "aspect_ratio", 0x121: "raw_size"}


def jpeg_sof_and_exif(data: bytes) -> dict:
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    out: dict = {}
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            raise ValueError(f"bad JPEG marker at {i:#x}")
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seg = struct.unpack(">H", data[i + 2:i + 4])[0]
        body = data[i + 4:i + 2 + seg]
        if marker == 0xE1 and body[:6] == b"Exif\0\0" and "exif" not in out:
            out["exif"] = tiff_tags(body[6:])
        if marker in (0xC0, 0xC1, 0xC2):
            height, width = struct.unpack(">HH", body[1:5])
            out["sof"] = (width, height)
            return out
        if marker == 0xDA:
            break
        i += 2 + seg
    raise ValueError("no SOF marker before scan")


def tiff_tags(tiff: bytes) -> dict:
    endian = {b"II": "<", b"MM": ">"}[tiff[:2]]
    wanted = {0x010F: "make", 0x0110: "model", 0x0131: "software",
              0xA002: "pixel_x", 0xA003: "pixel_y", 0x0112: "orientation"}
    tags: dict = {}

    def walk(offset: int) -> None:
        count = struct.unpack_from(endian + "H", tiff, offset)[0]
        for k in range(count):
            tag, typ, n, val = struct.unpack_from(endian + "HHI4s", tiff, offset + 2 + 12 * k)
            if tag == 0x8769:
                walk(struct.unpack(endian + "I", val)[0])
            elif tag in wanted:
                if typ == 2:
                    raw = val if n <= 4 else tiff[struct.unpack(endian + "I", val)[0]:][:n]
                    tags[wanted[tag]] = raw.split(b"\0")[0].decode(errors="replace").strip()
                elif typ == 3:
                    tags[wanted[tag]] = struct.unpack(endian + "H", val[:2])[0]
                elif typ == 4:
                    tags[wanted[tag]] = struct.unpack(endian + "I", val)[0]

    walk(struct.unpack(endian + "I", tiff[4:8])[0])
    return tags


def raf_header(data: bytes) -> dict:
    if data[:16] != b"FUJIFILMCCD-RAW ":
        raise ValueError("not a RAF")
    jpeg_off, jpeg_len, cfa_hdr_off, cfa_hdr_len, cfa_off, cfa_len = struct.unpack(">6I", data[0x54:0x6C])
    records: dict = {}
    count = struct.unpack(">I", data[cfa_hdr_off:cfa_hdr_off + 4])[0]
    pos = cfa_hdr_off + 4
    for _ in range(count):
        tag, size = struct.unpack(">HH", data[pos:pos + 4])
        if tag in RAF_TAGS and size == 4:
            records[RAF_TAGS[tag]] = struct.unpack(">HH", data[pos + 4:pos + 8])
        pos += 4 + size
    embedded = jpeg_sof_and_exif(data[jpeg_off:jpeg_off + jpeg_len])
    return {
        "model": data[0x1C:0x3C].split(b"\0")[0].decode(),
        "firmware": data[0x3C:0x40].decode(),
        "embedded_jpeg": embedded.get("sof"),
        "embedded_jpeg_exif": embedded.get("exif", {}),
        "embedded_jpeg_offset": jpeg_off,
        "embedded_jpeg_length": jpeg_len,
        "cfa_bytes": cfa_len,
        **records,
    }


def ratio(size) -> float | None:
    return size[0] / size[1] if size and size[1] else None


def inspect_jpeg(path: Path) -> dict:
    from PIL import Image

    own = jpeg_sof_and_exif(path.read_bytes())
    with Image.open(path) as im:
        im.load()
        third = im.size
    sof = own["sof"]
    return {
        "file": path.name, "own_sof": sof, "pillow_decoded": third, "exif": own.get("exif", {}),
        "routes_agree": tuple(third) == tuple(sof),
        "aspect": round(ratio(sof), 4),
        "size_class": next((k for k, v in XPAN_JPEG_SIZES.items() if tuple(sof) in v), None),
    }


def inspect_raf(path: Path) -> dict:
    import rawpy
    from PIL import Image

    data = path.read_bytes()
    own = raf_header(data)
    start, end = own["embedded_jpeg_offset"], own["embedded_jpeg_offset"] + own["embedded_jpeg_length"]
    with Image.open(io.BytesIO(data[start:end])) as image:
        image.load()
        embedded_decoded = image.size
    with rawpy.imread(str(path)) as raw:
        s = raw.sizes
        third = {"raw": (s.raw_width, s.raw_height), "visible": (s.width, s.height),
                 "crop": (s.crop_width, s.crop_height), "crop_margin": (s.crop_left_margin, s.crop_top_margin),
                 "decoded_shape": tuple(raw.raw_image_visible.shape[::-1]),
                 "crop_scope": "LibRaw raw_inset_crops[0]; rawpy does not expose aspect/user crop [1]"}
    cropped, top_left = own.get("cropped_size"), own.get("crop_top_left")
    own_crop = (cropped[1], cropped[0]) if cropped else None  # stored height, width
    return {
        "file": path.name, "own": own, "libraw": third,
        "embedded_jpeg_pillow_decoded": embedded_decoded,
        "embedded_jpeg_routes_agree": tuple(own["embedded_jpeg"]) == tuple(embedded_decoded),
        "crop_routes_agree": xtrans_aligned_match(own_crop, top_left, third) if own_crop and top_left else None,
        "crop_aspect": round(ratio(own_crop), 4) if own_crop else None,
        "libraw_crop_aspect": round(ratio(third["crop"]), 4) if third["crop"][1] else None,
    }


def crop_centered_on_control(raf: dict, control: dict | None) -> bool:
    """Check the stored RAF rectangle against the same body's stock 3:2 area.

    This proves metadata geometry only, not pixel-level scene alignment.
    """
    if control is None:
        return False
    own, baseline = raf.get("own") or {}, control.get("own") or {}
    crop, origin = own.get("cropped_size"), own.get("crop_top_left")
    full, full_origin = baseline.get("cropped_size"), baseline.get("crop_top_left")
    if not all((crop, origin, full, full_origin)):
        return False
    if (own.get("model") != baseline.get("model")
            or not own.get("model")
            or own.get("raw_full_size") != baseline.get("raw_full_size")
            or not own.get("raw_full_size")
            or own.get("cfa_bytes") != baseline.get("cfa_bytes")
            or (raf.get("libraw") or {}).get("raw") != (control.get("libraw") or {}).get("raw")):
        return False
    height, width = crop
    top, left = origin
    full_height, full_width = full
    full_top, full_left = full_origin
    if (min(height, width, full_height, full_width) <= 0
            or abs(full_width / full_height - STOCK_32) > 0.02
            or width != full_width or left != full_left
            or top < full_top or left < full_left
            or top + height > full_top + full_height
            or left + width > full_left + full_width):
        return False
    return (abs((top - full_top) - (full_top + full_height - top - height)) <= 1
            and abs((left - full_left) - (full_left + full_width - left - width)) <= 1)


def xpan_pair_gate(jpeg: dict, raf: dict, control: dict | None = None) -> dict:
    """Conservative explicit-area gate; not a general RAF soft-crop verdict.

    A same-stem pair is not same-scene proof. Native Fujifilm RAF soft crops
    can leave raw_inset_crops[0] full-height; editor/user-crop evidence is
    still required for the feature even if this gate passes.
    """
    size = tuple(jpeg.get("own_sof") or ())
    own = raf.get("own") or {}
    preview = tuple(own.get("embedded_jpeg") or ())
    preview_exif = own.get("embedded_jpeg_exif") or {}
    crop = own.get("cropped_size")
    crop_wh = (crop[1], crop[0]) if crop else None
    checks = {
        "same_stem": bool(jpeg.get("file") and raf.get("file"))
        and Path(jpeg["file"]).stem == Path(raf["file"]).stem,
        "jpeg_independent_decode": bool(jpeg.get("routes_agree")),
        "jpeg_6524_size": size in [tuple(s) for sizes in XPAN_JPEG_SIZES.values() for s in sizes],
        "jpeg_exif_matches_pixels": len(size) == 2
        and (jpeg.get("exif") or {}).get("pixel_x") == size[0]
        and (jpeg.get("exif") or {}).get("pixel_y") == (size[1] if len(size) == 2 else None),
        "raf_aspect_tag_2465": tuple(own.get("aspect_ratio") or ()) == (24, 65),
        "raf_preview_independent_decode": bool(raf.get("embedded_jpeg_routes_agree")),
        "raf_preview_6524": bool(preview and abs(ratio(preview) - TARGET) < 0.02),
        "raf_preview_exif_matches_pixels": len(preview) == 2
        and preview_exif.get("pixel_x") == preview[0]
        and preview_exif.get("pixel_y") == (preview[1] if len(preview) == 2 else None),
        "raf_crop_metadata_6524": bool(crop_wh and abs(ratio(crop_wh) - TARGET) < 0.02),
        "raf_independent_reader_6524": abs((raf.get("libraw_crop_aspect") or 0) - TARGET) < 0.02,
        "raf_crop_routes_agree": raf.get("crop_routes_agree") is True,
        "raf_crop_centered_on_stock_control": crop_centered_on_control(raf, control),
    }
    return {
        "pass": all(checks.values()), "checks": checks,
        "scope": "conservative explicit-area gate; rawpy crop is LibRaw raw_inset_crops[0], not aspect/user crop [1]",
    }


def xpan_pair_gates(files: list[dict], control: dict | None = None) -> dict[str, dict]:
    pairs: dict[str, dict[str, dict]] = {}
    duplicates: set[str] = set()
    for item in files:
        path = Path(item["file"])
        kind = "raf" if path.suffix.upper() == ".RAF" else "jpeg"
        pair = pairs.setdefault(path.stem, {})
        if kind in pair:
            duplicates.add(path.stem)
        pair[kind] = item
    return {
        stem: {"pass": False, "duplicate": True} if stem in duplicates else
        xpan_pair_gate(pair["jpeg"], pair["raf"], control) if set(pair) == {"jpeg", "raf"} else
        {"pass": False, "missing": sorted({"jpeg", "raf"} - set(pair))}
        for stem, pair in pairs.items()
    }


def xtrans_aligned_match(own_crop, own_top_left, libraw: dict) -> bool:
    """LibRaw moves the stored crop origin up to the next multiple of 6 (the
    X-Trans period) and shortens the crop by the same amount. Stock control:
    stored top 13, 6240x4160 becomes top 18, 6240x4155."""
    top, left = own_top_left
    lib_left, lib_top = libraw["crop_margin"]
    shift = (-top) % 6
    return (lib_left == left and lib_top == top + shift
            and libraw["crop"] == (own_crop[0], own_crop[1] - shift))


def classify(raf: dict, control: dict | None) -> str:
    aspect = raf["crop_aspect"]
    if aspect is None:
        return "no crop metadata"
    if abs(aspect - TARGET) > 0.02:
        return "not 65:24"
    if control is None:
        return "65:24 crop metadata; sensor extent not compared (no control)"
    same = raf["libraw"]["raw"] == control["libraw"]["raw"] and raf["own"]["cfa_bytes"] == control["own"]["cfa_bytes"]
    return "65:24 metadata crop over full sensor mosaic (soft crop)" if same else "65:24 physically reduced mosaic"


def centering(control_jpeg: Path, xpan_jpeg: Path, width: int = 480) -> dict:
    """Locate the 65:24 frame inside a same-scene 3:2 control by row correlation."""
    import numpy as np
    from PIL import Image

    def grey(path: Path, w: int) -> "np.ndarray":
        with Image.open(path) as im:
            h = round(im.height * w / im.width)
            return np.asarray(im.convert("L").resize((w, h)), dtype=np.float64)

    ctrl, xp = grey(control_jpeg, width), grey(xpan_jpeg, width)
    xp = (xp - xp.mean()) / (xp.std() or 1)
    scores = []
    for top in range(0, ctrl.shape[0] - xp.shape[0] + 1):
        band = ctrl[top:top + xp.shape[0]]
        band = (band - band.mean()) / (band.std() or 1)
        scores.append(float((band * xp).mean()))
    best = int(np.argmax(scores))
    expected = (ctrl.shape[0] - xp.shape[0]) / 2
    return {"best_top_row": best, "expected_centered_row": expected,
            "offset_rows_at_480px": best - expected, "correlation": round(max(scores), 4)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--control-raf", type=Path, help="stock 3:2 RAF of the same body")
    p.add_argument("--center", nargs=2, type=Path, metavar=("CONTROL_JPG", "XPAN_JPG"))
    p.add_argument("--require-matched-pairs", action="store_true",
                   help="fail closed unless each same-stem JPEG/RAF pair passes all file checks")
    a = p.parse_args()
    if a.require_matched_pairs and not a.control_raf:
        p.error("--require-matched-pairs requires --control-raf from the same body")
    control = inspect_raf(a.control_raf) if a.control_raf else None
    report = []
    for f in a.files:
        if f.suffix.upper() == ".RAF":
            r = inspect_raf(f)
            r["classification"] = classify(r, control)
            report.append(r)
        else:
            report.append(inspect_jpeg(f))
    out = {"control": control, "files": report}
    if a.center:
        out["centering"] = centering(*a.center)
    if a.require_matched_pairs:
        out["pair_gates"] = xpan_pair_gates(report, control)
    print(json.dumps(out, indent=2, default=list))
    if a.require_matched_pairs and (not out["pair_gates"] or not all(x["pass"] for x in out["pair_gates"].values())):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
