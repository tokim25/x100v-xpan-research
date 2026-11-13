# X100V OVF bright-frame research

The X100V's solid optical-viewfinder frame is separate from its corner marks. A series of SD-boot experiments ruled out the overlay icon selection, a vector bright-frame resource, three VG aspect rectangles and the shared window-fit path as controls for that solid line on this camera.

The remaining path reads a calibrated frame rectangle, applies an aspect-dependent height factor, then applies focus-distance parallax correction before drawing. For the existing 16:9 setting (aspect code 2), the height factor is stored as a little-endian float at `0x01e9e660` in the X100V 3.01 secondary image. The stock value is about 0.8455. Multiplying it by `128/195` gives about 0.5550, which produces the intended 65:24 frame height while retaining the stock factor's small calibration offset.

`tools/x100v_ovf_frame_scale_6524.py` verifies six nearby instruction words and the original float before producing a single four-byte write. The other tools in this update record the prior probes and their synthetic checks. These programs require a user-supplied official firmware image for source-bound work; this repository contains no Fujifilm firmware bytes or ready-made boot files.

In a physical X100V SD-boot test, the owner observed that the solid OVF frame changed to 65:24, shifted with focus distance and aligned with the always-visible corner marks. LCD and EVF remained 65:24. Five RAW+FINE captures at the existing `L 16:9` menu setting saved 65:24 JPEG and RAF pairs. The camera files and identifying metadata are kept private. The image-size setting was restored and normal no-card boot was confirmed.

This does not establish measured OVF alignment across focus distances, compressed RAW, in-camera playback, updater acceptance or internal-flash recovery. The camera has not been flashed.
