"""Read-only low-resolution same-shot RAF/JPEG field-of-view registration.

This checks scene alignment, not a RAF default-crop instruction or editor
behavior. It never writes image files or camera settings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from PIL import Image


def _gray(image: Image.Image, width: int) -> np.ndarray:
    height = round(image.height * width / image.width)
    return np.asarray(image.convert("L").resize((width, height), Image.Resampling.LANCZOS),
                      dtype=np.float64)


def edge_map(gray: np.ndarray) -> np.ndarray:
    """Contrast-insensitive local structure, with one-pixel boundary zeros."""
    dx = np.diff(gray, axis=1, prepend=gray[:, :1])
    dy = np.diff(gray, axis=0, prepend=gray[:1, :])
    return np.hypot(dx, dy)


def correlation(a: np.ndarray, b: np.ndarray) -> float:
    left, right = a - a.mean(), b - b.mean()
    denom = np.linalg.norm(left) * np.linalg.norm(right)
    return float(np.sum(left * right) / denom) if denom else 0.0


def align(raw_gray: np.ndarray, jpeg_gray: np.ndarray, max_dx: int = 4) -> dict:
    """Search vertical placement and a few pixels of horizontal offset."""
    if raw_gray.ndim != 2 or jpeg_gray.ndim != 2 or raw_gray.shape[0] < jpeg_gray.shape[0]:
        raise ValueError("expected 2D RAW field at least as tall as JPEG")
    if raw_gray.shape[1] != jpeg_gray.shape[1] or raw_gray.shape[1] <= 2 * max_dx:
        raise ValueError("images need equal, sufficiently wide fields")
    raw, jpeg = edge_map(raw_gray), edge_map(jpeg_gray)
    h, w = jpeg.shape
    matches = []
    for top in range(raw.shape[0] - h + 1):
        for dx in range(-max_dx, max_dx + 1):
            if dx < 0:
                r, j = raw[top:top + h, :w + dx], jpeg[:, -dx:]
            elif dx > 0:
                r, j = raw[top:top + h, dx:], jpeg[:, :w - dx]
            else:
                r, j = raw[top:top + h], jpeg
            matches.append((correlation(r, j), top, dx))
    score, top, dx = max(matches)
    outside = [s for s, y, _ in matches if abs(y - top) > 5]
    return {
        "top_px_at_analysis_width": top,
        "horizontal_shift_px": dx,
        "correlation": round(score, 5),
        "best_nonlocal_correlation": round(max(outside), 5) if outside else None,
        "analysis_width": w,
        "raw_height": raw.shape[0],
        "jpeg_height": h,
        "centered_top": (raw.shape[0] - h) / 2,
    }


def inspect(raf: Path, jpeg: Path, width: int = 480) -> dict:
    import rawpy

    with rawpy.imread(str(raf)) as source:
        developed = source.postprocess(half_size=True, output_bps=8,
                                       no_auto_bright=True, use_camera_wb=True)
    raw_gray = _gray(Image.fromarray(developed), width)
    with Image.open(jpeg) as source:
        jpeg_gray = _gray(source, width)
    return {
        "raf": raf.name,
        "raf_sha256": hashlib.sha256(raf.read_bytes()).hexdigest(),
        "jpeg": jpeg.name,
        "jpeg_sha256": hashlib.sha256(jpeg.read_bytes()).hexdigest(),
        "scope": "scene-content registration only; not RAW default crop or editor proof",
        **align(raw_gray, jpeg_gray),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("raf", type=Path)
    parser.add_argument("jpeg", type=Path)
    parser.add_argument("--width", type=int, default=480)
    args = parser.parse_args()
    print(json.dumps(inspect(args.raf, args.jpeg, args.width), indent=2))


if __name__ == "__main__":
    main()
