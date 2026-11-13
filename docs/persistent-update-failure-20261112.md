# X100V 3.01 persistent-update failure (owner report, 2026-11-12)

An experimental feature-only modified `FPUPDATE.DAT` derived from the
camera-tested 65:24 SD-boot writes completed in the X100V updater. The updater
instructed the owner to power off. On the next power-on, the camera showed no
response. The owner reached boot-ROM recovery with the usual two-button
SD-boot combination plus DISP/BACK, restored stock firmware, and confirmed
normal startup and shooting without a card. The displayed version was reported
as `3.01 b` verbatim.

The failed update file's SHA-256 was
`081e8c46646dbce87eedc483494da805e79116aa4aff7f8bf77a470c37a2b9a1`.
Do not use it. The exact failure cause is unknown. The detailed recovery card
contents and screen sequence have not been documented, and this recovery does
not guarantee that other flash failures can be repaired. The temporary SD-boot
65:24 observations remain separate evidence and do not qualify a persistent
firmware update.

This public note contains no firmware image, camera files, logs, settings, or
camera identifiers.
