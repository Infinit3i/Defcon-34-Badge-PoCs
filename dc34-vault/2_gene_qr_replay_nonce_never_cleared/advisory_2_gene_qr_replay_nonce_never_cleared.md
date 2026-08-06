# Gene response codes are replayable because the recipient nonce is never retired

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7` and every earlier commit carrying the gene exchange protocol; on by default in conference mode
**Severity:** Medium
**CWE:** CWE-294 Authentication Bypass by Capture-replay → CWE-323 Reusing a Nonce, Key Pair in Encryption
**Auth required:** none
**Attacker:** any player, using only their own badge and a captured image of another badge's response code
**Parameter:** gene response QR payload (optical scan, ciphertext plus tag)
**Trigger flow:** recipient shows nonce QR -> donor responds with ciphertext under that nonce -> recipient decrypts and breeds -> `nonce_mine` retained -> recipient re-enters `GeneScan` from `Idle` and rescans the same ciphertext, decrypting successfully again
**Impact:** a single captured response code can be redeemed an unlimited number of times, each time producing a fresh randomised offspring, defeating the one-time-use property the design is built on
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: Other, `bunnie/dc34-vault`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` (2.4 Low by the calculator, filed Medium, see Severity); CWE-294, CWE-323; no attachment, this finding is source verified

## Summary

After a badge successfully decrypts a gene response, its own nonce is left in place. Returning to
the scanning state from idle does not generate a new one, and no protocol timeout exists to expire
it. The same response ciphertext therefore decrypts successfully every time it is rescanned, and
because syngamy re-randomises on each run, the attacker can reroll the offspring until they get the
pattern they want from a single captured code.

## Severity

Medium. The CVSS 4.0 calculator returns 2.4 Low for this vector, because CVSS has no vocabulary for
the integrity of a game economy and scores the impact only as a limited integrity effect. It is
filed Medium because the property that fails is not incidental: it is the specification. The vendor
writes that "the goal of the system is to make the QR codes one-time use" and states as
**Security proposition 2** that "an honest user cannot repeatedly scan a QR code and continue to
'breed' with the pattern, because the nonce is guaranteed to change on every round due to the
difference check on the nonce." Neither holds. The same section also relies on a bound that is
absent from the implementation: "This is solved by forcing the protocol to time-out within one
minute, thus bounding the response window to near real-time transactions."

This is not the brute-force path the vendor deliberately leaves open. It needs no knowledge of
`Ko`, no developer mode and no custom firmware. It works on stock signed firmware, which is exactly
the population the propositions are written about: "we can assume protocol integrity is enforced by
honest firmware running on honest devices."

## Root Cause

`nonce_mine` in `src/config.rs:63` is written only by `generate_my_nonce`, which is reached solely
through `nonce_data` at `src/config.rs:384` when a badge displays its own nonce QR. It is cleared
only by `clear_nonces` at `src/config.rs:391`, which has exactly one caller, `src/ux.rs:1707`, in
the `VaultMode::ResponseGene` key handler. That handler runs on the **donor** side, clearing the
nonce of the badge that answered, which never used it to decrypt anything.

On the **recipient** side, `src/main.rs:695` decrypts with `get_my_nonce()` and, on success, runs
syngamy and moves to `VaultMode::ConfirmGene` at `src/main.rs:771`. Nothing in that path, nor in
`VaultOp::KeepGene` or `VaultOp::RevertGene` at `src/main.rs:925` and `src/main.rs:931`, clears the
nonce. The transition back into scanning at `src/ux.rs:1683` sets `VaultMode::GeneScan` directly
without calling `nonce_data`, so the previous nonce survives into the next scan. The difference
check inside `generate_my_nonce` that Security proposition 2 rests on is real and correct, but it
only runs when a new nonce is generated, and the replay path never generates one.

The one-minute timeout is absent. The timeout values that do exist, at `src/config.rs:272` to
`src/config.rs:274`, assign `LONG_TIMEOUT` to `GeneScan`, `ResponseGene` and `ShowKey`, and
`LONG_TIMEOUT` is `8 * 60 * 60` seconds in the non-debug build at `src/config.rs:258`. These drive
screen blanking, not protocol expiry, and nothing consults them to invalidate a nonce.

## Impact

A player photographs a donor's response QR code during a legitimate exchange, or captures it from a
screen, a social media post or a shared image. Because their own nonce is unchanged, they can
return to the scanning state and rescan that image as many times as they like. Each redemption is
not a repeat of the same result: `get_egg` at `src/config.rs:349` calls `meiosis` and `mutate` with
fresh randomness on every invocation, so each rescan yields a different offspring from the same
captured gamete. The attacker rerolls until the desired pattern appears.

The effect is to remove scarcity from the game. One interaction with a rare donor, an Uber or Goon
badge for instance, becomes an unlimited supply of breeding attempts with that donor's genetic
material, without the donor being present or consenting again. The vendor's stated intent that
brute force should be the legitimate cheating route is undermined by a path that costs nothing.

The second Security proposition, "any copy of a QR code from a transaction in progress is unlikely
to be useful to any honest user", still holds against third parties: a posted ciphertext is bound
to the nonce of the badge it was produced for, and another player cannot choose their own nonce. The
break is confined to the original recipient, but for that recipient it is total and permanent.

## Solution

Call `clear_nonces()` on the recipient immediately after a successful decrypt in `src/main.rs`,
before syngamy runs, so the nonce is consumed by the first use whether or not the user later keeps
or reverts the gene. Implement the documented expiry by recording the instant the nonce was
generated and rejecting `get_my_nonce()` results older than sixty seconds.

## Reproduction Steps

Environment: two DEF CON 34 badges running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec`, both mated to badge carriers so they
are in conference mode, both with light keys intact and neither in developer mode.

1. On badge A, the recipient, press the left or right button. Badge A displays its nonce QR code,
   labelled `NCE`.
2. On badge B, the donor, press the fire button and scan badge A's nonce code. Badge B now displays
   its gene response QR code, labelled `DAT`.
3. Photograph badge B's response code with any camera. Keep the image.
4. On badge A, press the fire button and scan badge B's response code. Badge A accepts it, shows
   the confirmation menu and offers to keep the new pattern. Accept it. Badge A returns to idle.
5. Badge B is no longer needed and may be taken away.
6. On badge A, press the fire button again to re-enter scanning. Do **not** press left or right,
   which would display a new nonce.
7. Scan the photograph taken in step 3. Badge A accepts it again and offers a confirmation menu
   with a different resulting pattern.
8. Repeat step 7 as many times as desired. Each repetition succeeds and produces a different
   offspring from the same captured code. Expected behaviour per the design is that step 7 fails
   after the first redemption, and that the code expires sixty seconds after step 1.

## Proof of Concept Code

No executable proof of concept is supplied. The target is firmware for the baochip bao1x SoC and
builds only for `riscv32imac-unknown-xous-elf`, so the finding is source verified against the call
graph rather than reproduced on hardware. The claim rests on three facts readable in the tree:
`clear_nonces` has exactly one caller and it is on the donor path, the recipient success path does
not call it, and the idle to `GeneScan` transition at `src/ux.rs:1683` does not regenerate the
nonce.

## Affected Files

src/config.rs:391: `clear_nonces` is defined but has only one caller, on the donor side
src/ux.rs:1707: the only `clear_nonces` call site, in the donor's `ResponseGene` handler, clearing a nonce that was never used to decrypt
src/main.rs:695: the recipient decrypts with `get_my_nonce()` and never retires the nonce on success
src/ux.rs:1683: the idle to `GeneScan` transition re-enters scanning without generating a new nonce
src/config.rs:258: `LONG_TIMEOUT` is eight hours and drives screen blanking, so the documented one-minute protocol timeout is not implemented anywhere
