# xpan-crop

A small tool for framing and cropping Fujifilm X100V files to 65:24 (XPan) after capture.

- `xpan-crop model` prints the centered 65:24 rectangle for a full 6240×4160 frame (6240×2304, offset y=928).
- `xpan-crop crop *.jpg` (or a folder) writes cropped JPEG copies. EXIF and the ICC profile are kept, and the source is never overwritten.
- `xpan-crop preview *.jpg` writes copies with the outside of the frame dimmed, for reviewing or planning a composition.
- `xpan-crop sidecar *.RAF --size 6240x4160` writes a JSON crop rectangle for files it can't read, such as RAF. Nothing is modified.

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/xpan-crop crop example.JPG --out out
```

The geometry is exact and integer-based. The camera's own 16:9 JPEGs differ from the exact crop by a couple of rows because of encoder alignment, so expect a similar small difference from any in-camera mode.

This tool works on files after capture. It does not read or modify camera firmware.

## Framing simulator

`simulator/index.html` is a self-contained page (open it in a browser, no install). It shows the 65:24 frame as seen on the LCD/EVF, as an OVF bright-frame guide, as the saved JPEG, and as a RAF with a reversible crop. Load your own photo or use the built-in test scene. It models geometry only and does not run camera firmware.
