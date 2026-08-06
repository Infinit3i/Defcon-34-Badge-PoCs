# Decrypted gene plaintext is sliced and indexed without a length check

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7` and every earlier commit carrying the gene decrypt path; on by default in conference mode
**Severity:** Low
**CWE:** CWE-1284 Improper Validation of Specified Quantity in Input → CWE-248 Uncaught Exception
**Auth required:** none, but possession of the population key `K = Ko || Kp` is required
**Attacker:** key holder, meaning anyone who has brute-forced `Ko` or received it under the vendor's disclosure schedule
**Parameter:** gene ciphertext QR payload (optical scan), specifically the plaintext length it decrypts to
**Trigger flow:** attacker encrypts a short plaintext under the population key and the victim's advertised nonce -> victim scans -> `aead.decrypt` succeeds -> `msg[..size_of::<Haploid>()]` slice with no length guard
**Impact:** the vault process terminates, taking the FIDO2 authenticator, the password and TOTP manager and the badge UI down until reboot
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: Other, `bunnie/dc34-vault`; CVSS 4.0 `CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` (4.1 Medium by the calculator, filed Low, see Severity); CWE-1284, CWE-248; no attachment, this finding is source verified

## Summary

Once a gene ciphertext authenticates, the resulting plaintext is sliced to nine bytes and indexed
at offset fifteen without checking its length. An attacker holding the population key can encrypt a
plaintext shorter than that, and the decrypt path panics after the AEAD tag has already been
accepted.

## Severity

Low, and the calculator's 4.1 Medium overstates it for one specific reason: this finding is
strictly dominated by finding 1, which reaches the same process termination with no key, no nonce
and no timing constraint. It grants an attacker no capability they do not already have. It is filed
separately because the defect is in a different function and the fix for finding 1 does not close
it, so a patch that addresses only the header comparison would leave this path intact.

The precondition is possession of `Ko`. The vendor treats that as an intended outcome and publishes
a schedule reducing the effective strength to 48 bits by day 4, which they estimate at about one
day on a single RTX 4090. The plaintext-length assumption is therefore not protected by anything
durable.

## Root Cause

`src/main.rs:695` calls `aead.decrypt(&nonce1, payload)`. On success the plaintext `msg` is a
`Vec<u8>` whose length is whatever the sender chose to encrypt. Two operations then assume a
minimum length that is never checked:

- `src/main.rs:699` evaluates `Haploid::deserialize(&msg[..size_of::<Haploid>()])`. `Haploid` is
  `#[repr(C)]` with nine `u8` fields at `dc34-api/src/lib.rs:231`, so the expression is `&msg[..9]`
  and panics for any plaintext shorter than nine bytes.
- `src/main.rs:702` evaluates `BadgeType::try_from(msg[15])`. The `.unwrap_or(BadgeType::None)`
  applied to the result handles an unrecognised discriminant, but it cannot help with the index
  itself, which panics for any plaintext shorter than sixteen bytes.

Honest peers always send sixteen bytes, because `get_padded_gamete` at `src/config.rs:337` builds a
fixed `[u8; 16]`. The code treats that producer-side invariant as though it were validated on the
consumer side. The AEAD tag proves the sender held the key; it says nothing about the length of what
they encrypted.

## Impact

An attacker who holds the population key observes a victim's advertised nonce, which is broadcast
in the clear as a QR code by design, encrypts a one byte plaintext under that nonce, and renders the
result as a QR code. When the victim scans it the tag verifies, the slice panics and the vault
process terminates. Recovery requires a power cycle. Stored PDDB data is unaffected.

## Solution

Check the plaintext length before both operations, rejecting anything shorter than sixteen bytes
with the existing "Gene failed to deserialize" path at `src/main.rs:794`. `Haploid::deserialize`
already returns `Option` and is already handled with `if let Some`, so passing it `msg.get(..9)`
and treating `None` as a deserialisation failure is sufficient for the first site; use `msg.get(15)`
for the second.

## Reproduction Steps

Environment: a DEF CON 34 badge running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec`, in conference mode with its light key
intact, plus the population key `K = Ko || Kp`.

1. On the victim badge, press the left or right button. It displays its nonce QR code. Read the
   nonce from that code: base45-decode the payload, discard the sixteen byte header and take the
   following twelve bytes.
2. On the attacker's machine, compute
   `AES-256-GCM-SIV(K, nonce, plaintext = [0x00], aad = [])` and concatenate the ciphertext and tag.
3. Base45-encode the result and render it as a QR code.
4. On the victim badge, press the fire button to begin scanning, then scan the code from step 3.
5. The tag verifies and the vault process terminates. The badge screen stops updating, the LED
   pattern freezes and the FIDO2 interface stops answering over USB. On a debug build the log shows
   a panic reading `range end index 9 out of range for slice of length 1`.
6. Power cycle the badge to recover.

## Proof of Concept Code

No executable proof of concept is supplied. The target is firmware for the baochip bao1x SoC and
builds only for `riscv32imac-unknown-xous-elf`, so the finding is source verified rather than
reproduced on hardware. Both length assumptions are compile-time constants readable from the tree:
`Haploid` is nine `u8` fields at `dc34-api/src/lib.rs:231`, and the literal index `15` is written
inline at `src/main.rs:702`.

## Affected Files

src/main.rs:699: slices the decrypted plaintext to `size_of::<Haploid>()`, nine bytes, with no length check
src/main.rs:702: indexes the decrypted plaintext at offset fifteen with no length check
src/config.rs:337: `get_padded_gamete` establishes the sixteen byte length as a producer-side invariant that the consumer never verifies
