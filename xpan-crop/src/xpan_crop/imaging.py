"""JPEG crop, composition overlay and non-destructive sidecar output."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw

from .geometry import Rect, centered_crop


def crop_rect_for(image_size: tuple[int, int], ratio: tuple[int, int]) -> Rect:
    return centered_crop(image_size[0], image_size[1], *ratio)


def crop_jpeg(src: Path, dst: Path, ratio: tuple[int, int], quality: int = 95) -> Rect:
    """Write a cropped copy of a JPEG, keeping EXIF and the ICC profile."""
    if src.resolve() == dst.resolve():
        raise ValueError("refusing to overwrite the source file")
    with Image.open(src) as img:
        rect = crop_rect_for(img.size, ratio)
        extra = {}
        for key in ("exif", "icc_profile"):
            if key in img.info:
                extra[key] = img.info[key]
        img.crop(rect.box).save(dst, "JPEG", quality=quality, subsampling=0, **extra)
    return rect


def overlay_preview(src: Path, dst: Path, ratio: tuple[int, int]) -> Rect:
    """Dim everything outside the frame and outline it, for composing/review."""
    if src.resolve() == dst.resolve():
        raise ValueError("refusing to overwrite the source file")
    with Image.open(src) as img:
        base = img.convert("RGB")
    rect = crop_rect_for(base.size, ratio)
    dim = Image.new("RGB", base.size, (0, 0, 0))
    shaded = Image.blend(base, dim, 0.6)
    shaded.paste(base.crop(rect.box), (rect.x, rect.y))
    draw = ImageDraw.Draw(shaded)
    line = max(2, base.size[0] // 600)
    draw.rectangle(rect.box, outline=(255, 214, 0), width=line)
    shaded.save(dst, "JPEG", quality=90)
    return rect


def write_sidecar(src: Path, dst: Path, size: tuple[int, int], ratio: tuple[int, int]) -> Rect:
    """Record a crop rectangle without touching pixels (for RAF or any file)."""
    rect = crop_rect_for(size, ratio)
    payload = {
        "source": src.name,
        "image_size": {"width": size[0], "height": size[1]},
        "aspect": f"{ratio[0]}:{ratio[1]}",
        "crop": {"x": rect.x, "y": rect.y, "width": rect.width, "height": rect.height},
        "note": "Non-destructive crop rectangle; original pixels are untouched.",
    }
    dst.write_text(json.dumps(payload, indent=2) + "\n")
    return rect
