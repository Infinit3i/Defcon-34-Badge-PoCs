# IPC deserialiser pinned to an rkyv release with published archive-validation defects

**Product:** dc34-vault (DEF CON 34 badge `vault` application), commit `3d5cbf7`
**Affected versions:** commit `3d5cbf7`, whose `Cargo.lock` resolves rkyv to 0.8.15
**Severity:** Low
**CWE:** CWE-1104 Use of Unmaintained Third Party Components → CWE-416 Use After Free
**Auth required:** none at the Xous name server, which places no bound on who may connect
**Attacker:** a process on the badge able to connect to the vault server and send it a memory message
**Parameter:** rkyv archive bytes in a Xous shared memory page, consumed by `Buffer::to_original()`
**Trigger flow:** attacker process -> `xous::connect` to `SERVER_NAME_VAULT2` -> memory message -> `Buffer::from_memory_message` -> `to_original::<T, _>()` -> rkyv archive validation
**Impact:** memory unsafety in the process holding FIDO2 credentials, passwords and TOTP secrets, subject to the reachability caveat below
**Discovered:** 2026-08-06
**Status:** OPEN, unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com> (no SECURITY.md, private vulnerability reporting disabled)
**GHSA submission:** bunnie@kosagi.com (email only, the repository has GitHub private vulnerability reporting disabled). Ecosystem: crates.io, rkyv; CVSS 4.0 `CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` (1.8 Low); CWE-1104, CWE-416; no attachment, this finding is source verified

## Summary

Every inter-process message the vault accepts is deserialised with rkyv, and `Cargo.lock` pins
rkyv 0.8.15, which is inside the affected range of three published advisories including a
use-after-free reachable through crafted archives. The vault registers its Xous server with no
connection limit, so the name server does not restrict which processes may reach that deserialiser.

## Severity

Low, and the reason is a reachability caveat that should be stated before anything else. On a
production badge every process is part of the signed image, so there is no untrusted local process
to send the crafted archive. Reaching this requires code execution, and by the vendor's own design
obtaining code execution means entering developer mode, which wipes the keys. The finding is filed
because it is a genuine defect that costs one line to fix, because the connection limit makes the
name server a non-barrier rather than a barrier, and because the affected code sits on the single
boundary the vault cannot avoid crossing. It is not filed higher because no persona in the threat
model reaches it on a stock device.

## Root Cause

`Cargo.toml` requests `rkyv = "0.8.8"`, which is a caret requirement, and `Cargo.lock` resolves it
to 0.8.15. Three advisories cover that version:

- RUSTSEC-2026-0233, crafted archives can cause a use-after-free during deserialisation, introduced
  0.8.0-rc.1 and fixed in 0.8.17.
- RUSTSEC-2026-0234, insufficient archive validation causes out-of-bounds reads in archives
  containing hash tables, introduced 0.8.0-rc.1 and fixed in 0.8.17.
- RUSTSEC-2026-0235, insufficient archive validation causes out-of-bounds reads in archives
  containing `Rc` or `Arc`, introduced 0.7.0-pre.2 and fixed in 0.8.17.
- GHSA-vfvv-c25p-m7mm and RUSTSEC-2026-0122, panic-safety defects in `InlineVec::clear` and
  `SerVec::clear`, introduced 0.8.0 and fixed in 0.8.16.

The vault consumes archives at `src/main.rs:613`, `src/action_handler.rs:41`, `:50` and `:79`,
`src/env/xous/mod.rs:229`, `:478` and `:783`, and `src/ux/icontray.rs:28` and `:66`. Every one of
these takes the archive from a memory message sent by another process and calls
`to_original::<T, _>()`, and every one of them terminates in `.unwrap()` or `.expect()`, so a
rejected archive is itself a process-terminating condition.

The connection surface is not limited: `src/main.rs:104` calls
`xns.register_name(SERVER_NAME_VAULT2, None)`, and the `None` is the maximum connection count, so
the Xous name server does not cap how many processes may connect to the vault.

## Impact

A process able to send the vault a memory message can present a crafted rkyv archive to a
deserialiser with a published use-after-free and two published out-of-bounds reads. The affected
process holds the FIDO2 credential store, the password database and the TOTP secrets, so memory
unsafety there is the highest-value corruption target on the device. The reachability caveat in the
Severity section bounds this in practice on a stock badge.

## Solution

Raise the rkyv requirement to 0.8.17 or later, which closes all four advisories, and re-resolve
`Cargo.lock`. Give `register_name` an explicit maximum connection count equal to the number of
peers the vault genuinely serves, so the name server refuses connections beyond that set. Replace
the `.unwrap()` and `.expect()` calls on `to_original()` results with error handling that discards
the malformed message and continues, rather than terminating the process.

## Reproduction Steps

Environment: a DEF CON 34 badge running the `vault` application built from commit `3d5cbf7` for
`riscv32imac-unknown-xous-elf` with `--features board-baosec`.

1. Obtain the source tree at commit `3d5cbf7`.
2. Read the resolved dependency version: `grep -A2 'name = "rkyv"' Cargo.lock` reports
   `version = "0.8.15"`.
3. Query the advisory database for that version:
   `curl -s -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"rkyv","ecosystem":"crates.io"},"version":"0.8.15"}'`.
   The response lists RUSTSEC-2026-0233, RUSTSEC-2026-0234, RUSTSEC-2026-0235 and
   GHSA-vfvv-c25p-m7mm, none of which are fixed at or below 0.8.15.
4. Confirm the deserialiser is on the inter-process boundary:
   `grep -rn 'to_original' src/` lists nine call sites, each consuming a memory message from
   another process and each ending in `.unwrap()` or `.expect()`.
5. Confirm the connection surface is unbounded: `grep -n 'register_name' src/main.rs` shows
   `register_name(SERVER_NAME_VAULT2, None)`, where the second argument is the maximum connection
   count.

## Proof of Concept Code

No executable proof of concept is supplied. Demonstrating the rkyv defects requires a second
process on a badge, which per the Severity section requires developer mode and therefore a device
whose keys have already been wiped. The dependency claim is verifiable from the tree and from the
public advisory database using the commands in the Reproduction Steps.

## Affected Files

Cargo.lock: resolves rkyv to 0.8.15, inside the affected range of RUSTSEC-2026-0233, 0234, 0235 and GHSA-vfvv-c25p-m7mm
src/main.rs:104: `register_name(SERVER_NAME_VAULT2, None)` places no bound on which processes may connect to the vault
src/main.rs:613: deserialises an rkyv archive from a peer's memory message and unwraps the result
src/env/xous/mod.rs:783: deserialises a peer archive and terminates the process on failure via `.expect()`
src/ux/icontray.rs:28: deserialises a peer archive on a second server that also registers without a connection limit
