"""Pure geometry for centered fixed-aspect crops. Nothing here touches files."""

from __future__ import annotations

from dataclasses import asdict, dataclass

X100V_WIDTH = 6240
X100V_HEIGHT = 4160


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    width: int
    height: int

    @property
    def box(self) -> tuple[int, int, int, int]:
        """(left, upper, right, lower), the form Pillow expects."""
        return (self.x, self.y, self.x + self.width, self.y + self.height)


def parse_ratio(text: str) -> tuple[int, int]:
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError("ratio must be WIDTH:HEIGHT, e.g. 65:24")
    w, h = int(parts[0]), int(parts[1])
    if w <= 0 or h <= 0:
        raise ValueError("ratio terms must be positive")
    return w, h


def centered_crop(width: int, height: int, ratio_w: int, ratio_h: int) -> Rect:
    """Largest centered integer-pixel rectangle at an exact ratio."""
    if min(width, height, ratio_w, ratio_h) <= 0:
        raise ValueError("dimensions and ratio must be positive")
    if width * ratio_h >= height * ratio_w:
        crop_h = height
        crop_w = height * ratio_w // ratio_h
    else:
        crop_w = width
        crop_h = width * ratio_h // ratio_w
    return Rect((width - crop_w) // 2, (height - crop_h) // 2, crop_w, crop_h)


def x100v_model(ratio_w: int = 65, ratio_h: int = 24) -> dict:
    """Reference rectangles for a full-resolution X100V frame."""
    crop = centered_crop(X100V_WIDTH, X100V_HEIGHT, ratio_w, ratio_h)
    return {
        "sensor": asdict(Rect(0, 0, X100V_WIDTH, X100V_HEIGHT)),
        "aspect": f"{ratio_w}:{ratio_h}",
        "crop": asdict(crop),
        "pixels_discarded_fraction": round(1 - crop.width * crop.height / (X100V_WIDTH * X100V_HEIGHT), 4),
    }
