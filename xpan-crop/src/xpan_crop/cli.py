from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image

from .geometry import parse_ratio, x100v_model
from .imaging import crop_jpeg, overlay_preview, write_sidecar

JPEG_SUFFIXES = {".jpg", ".jpeg"}


def _expand(paths: list[Path]) -> list[Path]:
    """Directories contribute their files (non-recursive, sorted)."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.is_file() and not p.name.startswith(".")))
        else:
            files.append(path)
    return files


def _outputs(files: list[Path], out_dir: Path, suffix: str, ext: str | None = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    for src in _expand(files):
        yield src, out_dir / f"{src.stem}{suffix}{ext or src.suffix}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="xpan-crop", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("model", help="print reference rectangles for a full X100V frame")
    m.add_argument("--ratio", default="65:24")

    for name, helptext in (("crop", "write cropped JPEG copies"),
                           ("preview", "write composition overlay JPEGs"),
                           ("sidecar", "write crop-rectangle JSON; works for RAF too")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("files", nargs="+", type=Path)
        s.add_argument("--ratio", default="65:24")
        s.add_argument("--out", type=Path, default=Path("out"))
        if name == "sidecar":
            s.add_argument("--size", help="WIDTHxHEIGHT; required for non-JPEG files, e.g. 6240x4160")

    args = p.parse_args(argv)
    try:
        ratio = parse_ratio(args.ratio)
        if args.cmd == "model":
            print(json.dumps(x100v_model(*ratio), indent=2))
            return 0
        if args.cmd == "crop":
            for src, dst in _outputs(args.files, args.out, f"_{ratio[0]}x{ratio[1]}"):
                if src.suffix.lower() not in JPEG_SUFFIXES:
                    p.error(f"{src.name}: crop handles JPEG only; use 'sidecar' for RAF")
                print(src.name, crop_jpeg(src, dst, ratio))
        elif args.cmd == "preview":
            for src, dst in _outputs(args.files, args.out, "_frame", ".jpg"):
                print(src.name, overlay_preview(src, dst, ratio))
        else:
            for src, dst in _outputs(args.files, args.out, "_xpan", ".json"):
                if args.size:
                    w, h = (int(v) for v in args.size.lower().split("x"))
                elif src.suffix.lower() in JPEG_SUFFIXES:
                    with Image.open(src) as img:
                        w, h = img.size
                else:
                    p.error(f"{src.name}: pass --size WIDTHxHEIGHT for non-JPEG files")
                print(src.name, write_sidecar(src, dst, (w, h), ratio))
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
