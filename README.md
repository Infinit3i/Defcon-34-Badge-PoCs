# DEF CON 34 badge — consolidated security findings

Authorized research against the open-source DEF CON 34 badge (baochip / betrusted-io / bunnie). All source is public and the badge is designed to be hacked. This folder consolidates findings from four repositories that make up the badge stack, plus the cross-layer chain analysis that ties them together.

## The stack (four repos audited)

- **baochip-1x** (silicon, taped out, unpatchable): the SoC. Holds the SCE, the security co-processor with the key store and the HMAC secure-boot check.
- **betrusted-io/xous-core** (`5d5bbbf`): the pure-Rust microkernel OS. Also ships on Precursor and other betrusted products, so its bugs reach beyond this badge.
- **bunnie/dc34-vault** (`3d5cbf7`): the token app. Secrets, FIDO2/CTAP, the QR "gene breeding" game, badge UI.
- **bunnie/dc34-console** (`bf64e03`): the USB serial REPL, power management, LEDs.

## Consolidated findings

| ID | Repo | Sev | Type (CWE) | Location | Status |
|----|------|-----|-----------|----------|--------|
| K1 | xous-core | High | Deserialization of untrusted data (CWE-502) | xous-ipc/src/buffer.rs:334 | source-verified |
| K2 | xous-core | Medium | Improper array index (CWE-129) | xous-ipc/src/buffer.rs:114 | source-verified |
| V1 | dc34-vault | Medium | Unchecked slice on untrusted input (CWE-1284) | src/main.rs:624 | **LIVE CONFIRMED on hardware** |
| V2 | dc34-vault | Medium | Capture-replay, un-retired nonce (CWE-294) | src/main.rs:695 | source-verified |
| V3 | dc34-vault | Medium | Unbounded allocation (CWE-770) | src/vendor_commands.rs:45 | source-verified |
| V4 | dc34-vault | Low | Hardcoded constant as authenticator (CWE-798) | src/main.rs:824 | **LIVE CONFIRMED on hardware** |
| V5 | dc34-vault | Low | Vulnerable component on IPC boundary (CWE-1104) | Cargo.lock (rkyv 0.8.15) | source-verified |
| V6 | dc34-vault | Low | Unchecked slice on decrypted input (CWE-1284) | src/main.rs:699 | source-verified |
| C1 | dc34-console | Medium | Missing auth for critical function (CWE-306) | src/cmds/test.rs:43 | source-verified |
| C2 | dc34-console | Low | Sensitive system info exposure (CWE-497) | src/cmds/test.rs:119 | source-verified |
| S1 | baochip-1x | candidate (High if confirmed) | Access-control bypass / OOB read (CWE-284 -> CWE-200) | crypto_top/rtl/sce_memc.sv:212, sce_dmachnl.sv:123 | source-verified, needs verilator |
| S2 | baochip-1x | candidate | Fail-open HMAC secure-boot verify (CWE-636) | crypto_top/rtl/combohasha.sv:480 | source-verified, needs sim/hardware |
| S3 | baochip-1x | candidate | Fuse/devmode security bypass | crypto_top/rtl/sce.sv:131 | source-verified |

`Severity: None` in the individual finding JSONs is the per-finding-in-isolation score. The point of this folder is that they are not isolated.

## Why this is one chain, not twelve tickets

The vault panics (V1, V6), the vault IPC-deserialization issue (V5), and the console offset issues are all the same systemic disease surfacing per-app: the Xous IPC buffer layer trusts sender-controlled offsets and lengths and does unchecked archive access. The root cause lives in the kernel (K1, K2), in `xous-ipc/src/buffer.rs`, which every Xous server uses.

The full escalation ladder:

```
proximate QR / USB input        (V1 LIVE CONFIRMED: a "00" QR crashes the vault)
  -> memory corruption in the vault   (V5 rkyv UAF/OOB, or the same unchecked path)
  -> kernel IPC primitive              (K1: corrupt ANY server from any unprivileged process)
  -> pivot to a server with SCE register access
  -> silicon SCE DMA key readout        (S1: first-beat pointer not bounds-checked)
  -> extract the master secrets the badge exists to protect
```

- **K2** alone: crash any service on the badge (systemic DoS, nothing restarts it).
- **K1**, if its corruption is driven to controlled write, gives code execution as any server, which reaches the secrets and the SCE.
- **S2** (fail-open secure boot) is the root-of-trust break: a glitch that skips the compare leaves the HMAC verdict at its default PASS, so unsigned firmware boots.

Individually Medium/Low. Chained, this is a local-code-execution-to-key-extraction path, gated only on demonstrating K1's corruption is controllable and S1's first-beat read fires.

## Confirmation status

- **V1 is live-confirmed on a real badge.** A QR of the two characters `00` panics and kills the vault process (FIDO2 stops answering, UI freezes, power-cycle recovers, data intact).
- **V4 is live-confirmed on a real badge.** A QR of `factory://factory-aae949f6969-lorem-ipsum-data` forces the badge out of the conference UI into the factory standalone test sequence.
- Everything else is source-verified. See `PoCs/` for how to confirm the rest.

## Highest-value items

1. **K1 (kernel IPC deserialization)** is the headline. It is patchable, it affects every Xous server, and it reaches other betrusted products (Precursor), not just this badge. This is the item to lead the disclosure with.
2. **C1 (bootwait)** is a persistent brick of any badge from an unauthenticated USB port, and it consumes a one-way counter that cannot be reset. Confirm the recovery path before reproducing.
3. **S1 + S2 (silicon)** are the crown jewels (key extraction, secure-boot bypass) but unpatchable and need a verilator sim or a fault-injection rig to confirm.

## Folder layout

```
Defcon-34-Badge-PoCs/
  README.md                 <- this file
  baochip-1x-silicon/       <- CANDIDATES.md + THREAT_MODEL.md + candidates.json (source-verified silicon)
  xous-core-kernel/         <- K1, K2 advisories + finding JSONs
  dc34-vault/               <- V1..V6 advisories + finding JSONs
  dc34-console/             <- C1, C2 advisories + finding JSONs
  PoCs/                     <- reproduction: QR payloads, generators, serial procedures, kernel app skeleton
```

## Disclosure

Single coordinated report to bunnie / betrusted-io. Software findings (K, V, C) are patchable and should carry CVE requests. The kernel IPC fix (validate `offset` against page length, use rkyv checked access, bound archive lengths in `xous-ipc`) closes K1, K2, and the app-level symptoms V1/V5/V6 at once. Silicon findings go as documentation plus firmware-mitigation and next-die-rev notes. Nothing here is weaponized beyond proving impact, and none of it should be run against a badge you do not own.
