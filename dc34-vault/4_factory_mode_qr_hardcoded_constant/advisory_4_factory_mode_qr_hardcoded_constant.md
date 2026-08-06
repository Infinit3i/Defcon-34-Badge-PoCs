# Factory test mode is entered by a QR code carrying a hardcoded public constant

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7` and every earlier commit carrying the `factory://` handler; on by default in conference mode
**Severity:** Low
**CWE:** CWE-798 Use of Hard-coded Credentials → CWE-306 Missing Authentication for Critical Function
**Auth required:** none
**Attacker:** proximate stranger with no credentials, able to display a QR code to the victim badge
**Parameter:** QR code payload, the `factory://` scheme string (optical scan)
**Trigger flow:** attacker QR code -> `VaultOp::HandleQr` -> base45 decode fails -> `split_once("://")` -> `data == FACTORY_STANDALONE_STRING` -> `VaultMode::StandAloneTest`
**Impact:** any badge can be forced out of conference mode into the factory standalone hardware test sequence by a stranger
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: Other, `bunnie/dc34-vault`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` (2.4 Low); CWE-798, CWE-306; no attachment, this finding is source verified

## Summary

A QR code containing `factory://factory-aae949f6969-lorem-ipsum-data` moves any badge into
`VaultMode::StandAloneTest`, the factory hardware test sequence. The string it is compared against
is a compile-time constant published in this open source repository, so it is not a secret and
provides no authentication.

## Severity

Low. The impact is a disruptive but recoverable mode change: the badge leaves the conference
interface and runs the factory test walkthrough, which prompts for jog, direction and flip inputs.
It exposes no stored data and does not persist across a reboot. It is filed as a finding rather
than a note because the check is written as though the string were a shared secret, and the
strength of that check is zero for anyone who has read the repository, which is public.

## Root Cause

`src/ux.rs:29` declares `pub const FACTORY_STANDALONE_STRING: &'static str =
"factory-aae949f6969-lorem-ipsum-data"`. The QR handler reaches the comparison on the path taken
when `base45::decode` rejects the scanned string, at `src/main.rs:819`, where the input is split on
`"://"` and dispatched by scheme. The `"factory"` arm at `src/main.rs:824` compares the remainder
against that constant and, on equality, assigns `VaultMode::StandAloneTest`. The same dispatch is
duplicated for other modes at `src/main.rs:858` to `src/main.rs:866`. The randomised-looking
substring `aae949f6969` suggests the value was intended to be hard to guess, but guessing is not
required: it ships in the source.

No additional gate stands behind the comparison. There is no button confirmation, no jig detection
and no check that the badge is detached from its carrier.

## Impact

An attacker prints the string as a QR code and shows it, or leaves it where attendees scan codes.
Any badge that scans it drops out of the conference experience into the factory test sequence. In a
setting where scanning unknown QR codes is the intended social interaction, this is trivially
distributed to many badges at once. The user can recover by completing or timing out the test
sequence, or by rebooting.

## Solution

Gate factory and test mode entry on a condition an attendee's badge cannot satisfy, for example
requiring the module to be detached from the badge carrier, or requiring a physical button
combination held during the scan. If a scanned trigger is retained, derive it from a per-device
secret rather than a shared compile-time constant, so that a code minted for one unit does not
work on another.

## Reproduction Steps

Environment: a DEF CON 34 badge running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec`, mated to the badge carrier so the
device is in conference mode.

1. Generate a QR code encoding the exact string `factory://factory-aae949f6969-lorem-ipsum-data`.
   Display it on a phone screen or print it.
2. On the victim badge, press the fire button to begin scanning.
3. Point the badge camera at the QR code from step 1.
4. The badge leaves the conference interface and displays the factory standalone test sequence,
   beginning with the jog press prompt.
5. Complete or time out the sequence, or reboot, to return to normal operation.

## Proof of Concept Code

No executable proof of concept is supplied. The target is firmware for the baochip bao1x SoC and
builds only for `riscv32imac-unknown-xous-elf`, so the finding is source verified rather than
reproduced on hardware. The trigger value is a literal in the tree and is quoted in full above.

## Affected Files

src/ux.rs:29: `FACTORY_STANDALONE_STRING` is a compile-time constant in a public repository and is used as though it were a secret
src/main.rs:824: entering `VaultMode::StandAloneTest` requires only string equality against that public constant
src/main.rs:864: the same unauthenticated dispatch is duplicated for the non-gene modes
