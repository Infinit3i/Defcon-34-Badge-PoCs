# Unbounded reassembly buffer in the CTAP HID vendor session

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7` and every earlier commit carrying `src/vendor_commands.rs`; reachable in the default build with no configuration
**Severity:** Medium
**CWE:** CWE-770 Allocation of Resources Without Limits or Throttling → CWE-400 Uncontrolled Resource Consumption
**Auth required:** none, and notably no user presence and no PIN
**Attacker:** malicious or compromised USB host to which the badge is attached
**Parameter:** CTAP HID vendor command payload, `more_data` flag in the `backup::Wire` CBOR record
**Trigger flow:** USB HID vendor frame -> `HidIterType::Vendor` -> `handle_vendor_data` -> `read_from_wire` -> `self.data.append(...)` with `more_data` set, repeated without limit
**Impact:** heap exhaustion on a constrained embedded device, terminating the process that holds the FIDO2 credential store, the password and TOTP manager and the badge UI
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: Other, `bunnie/dc34-vault`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` (5.1 Medium); CWE-770, CWE-400; no attachment, this finding is source verified

## Summary

The CTAP HID vendor command handler accumulates payload chunks into a `Vec<u8>` that has no size
cap and no chunk-count cap. A host that keeps setting the `more_data` flag grows that buffer until
the device runs out of memory. The accumulation happens before the `allow_host` consent gate, so no
user interaction and no PIN is required to reach it.

## Severity

Medium. The attacker persona is the USB host, which is the persona a hardware security token exists
to defend against: the token is expected to stay sound when plugged into a machine its owner does
not control. Availability is the only impact, and it is recoverable by reboot, which is why this is
not filed High. The finding is materially strengthened by the fact that it sits in front of the
consent check rather than behind it: the vendor backup and restore feature is effectively disabled
in this build, because `allow_host` is initialised `false` at `src/main.rs:122` and no `.store()`
to it exists anywhere in the tree, yet the reassembly loop that feeds it still runs for any host
that asks.

## Root Cause

`VendorSession::read_from_wire` at `src/vendor_commands.rs:44` performs
`self.data.append(&mut w.data.clone())` and then sets `self.finished = !w.more_data`. Nothing
bounds the accumulated length and nothing counts iterations. In `src/fido2.rs:64` the caller only
resets the session when `handle_vendor_data` returns `Ok(None)`, meaning the transfer declared
itself finished, or when it returns `Err`. A host that always sets `more_data` keeps `finished`
false, so `handle_vendor_data` returns `Ok(Some(CONTINUE_RESPONSE))` and the loop repeats
indefinitely with the buffer retained across iterations.

The ordering check that might have terminated a malformed stream is inert. `read_from_wire` tests
`if self.index != 0 && self.index <= w.index`, but `self.index` is never assigned anywhere in the
file; it is set to zero by `VendorSession::default()` and stays zero for the life of the session.
The first conjunct is therefore always false and the check can never fire, so out-of-order and
duplicated chunk indices are accepted silently in addition to being unbounded.

## Impact

Each CTAP HID message carries up to 7609 bytes of payload, so a host can add roughly that much to
the buffer per message with no upper bound on the number of messages. On the bao1x SoC this
exhausts available heap and the allocation failure terminates the vault process, taking the FIDO2
authenticator, the password and TOTP store and the badge interface with it. Recovery requires a
power cycle. Stored PDDB data is not affected.

The host needs no consent, no PIN, no user presence gesture and no prior pairing. It needs only
that the badge is plugged in, which is the normal state for a security token in use.

## Solution

Cap the reassembly buffer and the chunk count in `read_from_wire`, returning a session error once
either limit is passed, and size the cap from the largest legitimate backup payload. Assign
`self.index = w.index` after the ordering check so that the check actually enforces monotonic chunk
ordering. Consider refusing vendor data outright when `allow_host` is false, so that the parsing
and buffering surface is not exposed by a feature that cannot complete.

## Reproduction Steps

Environment: a DEF CON 34 badge running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec` and the `usb` feature, attached over
USB to a host running any CTAP HID library.

1. Enumerate the badge's FIDO HID interface on the host and allocate a CTAP HID channel with an
   `INIT` command.
2. Build a CBOR `backup::Wire` record with a full-size `data` field and the `more_data` field set
   to true.
3. Send it to the badge as a vendor command with command byte `0x71`. The badge answers with the
   continue response, four bytes, and retains the payload.
4. Repeat step 3 in a loop without ever sending a record with `more_data` false and without sending
   the reset command `0x74`.
5. The badge continues answering the continue response while its heap grows. After enough
   iterations the vault process terminates: the FIDO interface stops answering, the badge screen
   stops updating and the LED pattern freezes.
6. Power cycle the badge to recover.

## Proof of Concept Code

No executable proof of concept is supplied. The target is firmware for the baochip bao1x SoC and
builds only for `riscv32imac-unknown-xous-elf`, so the finding is source verified rather than
reproduced on hardware. The absence of any cap is readable directly: `read_from_wire` contains one
`append` and no length test, and `self.index` is never written.

## Affected Files

src/vendor_commands.rs:45: appends attacker-supplied chunks to `self.data` with no size or count limit
src/vendor_commands.rs:54: the ordering check reads `self.index`, which is never assigned, so the condition can never be true
src/fido2.rs:64: the session is reset only on a finished transfer or an error, so a stream that always sets `more_data` is retained indefinitely
