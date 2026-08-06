# PoCs — DEF CON 34 badge

Reproduction material for the findings. Run only against a badge you own or are authorized to test. The whole point is clean proof for coordinated disclosure, not disrupting the con floor.

| # | File | Finding | What it does | Status | Needs |
|---|------|---------|--------------|--------|-------|
| 01 | 01_qr_header_crash_CONFIRMED.md | V1 | crash the vault by showing a QR | **CONFIRMED on hardware** | a badge + any QR generator |
| 02 | 02_factory_mode_qr.md | V4 | force any badge into factory test mode via QR | source-verified | a badge + QR generator |
| 03 | 03_console_usb_serial.md | C1, C2 | USB serial: dump kernel state; persistent brick (danger) | source-verified | USB cable + serial terminal |
| 04 | 04_gene_replay.md | V2 | replay a captured gene response unlimited times | source-verified | two badges or a captured QR |
| 05 | 05_kernel_ipc_panic_xous_app.md | K2 (and path to K1) | crash any Xous server from an unprivileged app | source-verified | Rust toolchain + xous build + sideload |

`gen_qr.sh` generates the QR PNGs for 01 and 02.

Confirmation cost ladder: 01 and 02 need nothing but a badge. 03 needs a USB cable. 05 is where you install the Rust toolchain and build a Xous app, and it is the one that live-confirms the kernel primitive that the whole chain rests on.
