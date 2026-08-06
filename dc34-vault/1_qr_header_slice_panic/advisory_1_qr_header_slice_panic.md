# Unchecked slice on scanned QR data causes a denial of service

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7` and every earlier commit that contains the QR handler; the code path is on by default and needs no configuration
**Severity:** Medium
**CWE:** CWE-1284 Improper Validation of Specified Quantity in Input → CWE-248 Uncaught Exception
**Auth required:** none
**Attacker:** proximate stranger with no credentials, able to display a QR code to the victim badge
**Parameter:** QR code payload (optical scan, arriving as `IpcString`)
**Trigger flow:** attacker QR code -> scanner -> `VaultOp::HandleQr` -> `base45::decode` -> `data[..DC34_HEADER.len()]` slice with no length guard
**Impact:** the vault process terminates, taking the FIDO2 authenticator, the password and TOTP manager and the badge UI down until reboot
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: Other, `bunnie/dc34-vault`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` (5.1 Medium); CWE-1284, CWE-248; no attachment, this finding is source verified

## Summary

The QR handler slices the decoded scan buffer to the length of a 16 byte header before checking
that the buffer is at least that long. Any QR code whose base45 payload decodes to fewer than 16
bytes panics the vault process. No credentials, no key material and no pairing are required, only
that the victim scans the code, which is the product's normal interaction.

## Severity

Medium. The precondition is only that the badge owner scans an attacker-supplied QR code, and the
DC34 light-gene game is built entirely around scanning codes shown by strangers, so the required
user action is the designed workflow rather than a barrier. The impact is availability of the
single process that provides the FIDO2 authenticator, the password and TOTP store and the badge
user interface. It is not a confidentiality or integrity break and it does not survive a reboot,
which is why it is filed Medium rather than High. The vendor declares no deployment posture, and
none is relevant: the boundary crossed here is optical, so no network placement could mitigate it.

## Root Cause

`src/main.rs:624` evaluates `data[..DC34_HEADER.len()] == DC34_HEADER` immediately after
`base45::decode` returns, where `data` is a `Vec<u8>` built from fully attacker-controlled QR
content. `DC34_HEADER` is declared `pub const DC34_HEADER: [u8; 16]` in `dc34-api/src/lib.rs:26`,
so the expression is `&data[..16]`. Rust's range slicing panics when the end index exceeds the
slice length. The guard that would have prevented this, `if data.len() < DC34_HEADER.len() +
size_of::<Nonce>()`, sits at `src/main.rs:626`, two lines later and nested inside the comparison
that already panicked. The length check was written for the nonce extraction that follows it and
was never extended to cover the header comparison itself.

## Impact

An attacker prints or displays a QR code encoding a short base45 string, for example the two
characters `00`, which decode to a single byte. When any badge scans it while in `GeneScan`,
`ResponseGene` or `ShowKey` mode, the slice panics. `panic = "abort"` is commented out in
`Cargo.toml:98`, so the panic unwinds out of `main`, which terminates the process either way. The
vault is the process that holds the FIDO2 credential store, the password and TOTP manager and the
badge interface, so all three stop until the device is power cycled. Stored data in the PDDB is not
lost. A single code shown on a screen or a sticker placed where attendees are invited to scan it
affects every badge that scans it, so one artifact scales to as many victims as read it.

## Solution

Check the buffer length before the header comparison, for example
`if data.len() >= DC34_HEADER.len() && data[..DC34_HEADER.len()] == DC34_HEADER`, or replace the
slice with `data.starts_with(&DC34_HEADER)`, which is total and needs no guard. Then hoist the
existing `data.len() < DC34_HEADER.len() + size_of::<Nonce>()` check so that both branches of the
QR handler validate length before any indexing.

## Reproduction Steps

Environment: DEF CON 34 badge running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec`, mated to the badge carrier so the
device is in conference mode.

1. Generate a QR code encoding the exact two character string `00`. Any QR generator will do; the
   payload must be valid base45 that decodes to fewer than 16 bytes, and `00` decodes to one byte.
   Display it on a phone screen or print it.
2. On the victim badge, press the left or right button. The badge shows its nonce QR code and
   enters the key display state.
3. Press the fire button to begin scanning.
4. Point the badge camera at the QR code from step 1.
5. The vault application terminates. The badge screen stops updating and the LED pattern stops
   responding. The FIDO2 token no longer answers over USB and the password and TOTP menus are
   unreachable. On a debug build the log shows a panic reading
   `range end index 16 out of range for slice of length 1`.
6. Power cycle the badge to recover. Stored passwords, TOTP records and FIDO2 credentials are
   intact.

## Proof of Concept Code

No executable proof of concept is supplied. The target is firmware for the baochip bao1x SoC and
builds only for `riscv32imac-unknown-xous-elf`; there is no emulator, no container image and no
published artifact, so the finding is source verified rather than reproduced on hardware. Both
load-bearing facts are compile-time constants that can be read directly from the tree:
`DC34_HEADER` is `[u8; 16]` at `dc34-api/src/lib.rs:26`, and Rust range slicing panics when the end
index exceeds the slice length. The vulnerable expression is quoted in full under Affected Files.

## Affected Files

src/main.rs:624: slices `data[..DC34_HEADER.len()]` on the base45 decode of attacker-controlled QR content with no prior length check
src/main.rs:626: the length guard that would have prevented the panic is evaluated after the slice that panics
