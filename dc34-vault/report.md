# dc34-vault, commit 3d5cbf7

Audit of `bunnie/dc34-vault`, the DEF CON 34 badge `vault` application, at commit `3d5cbf7`
(2026-08-07, the only commit in the repository's visible history). Target platform is Xous on the
baochip bao1x SoC, `riscv32imac-unknown-xous-elf`.

**Critical: 0 · High: 0 · Medium: 3 · Low: 3**

| # | Finding | Severity | Component | Verified | Chain? |
|---|---------|----------|-----------|----------|--------|
| 1 | [Unchecked slice on scanned QR data causes a denial of service](1_qr_header_slice_panic/advisory_1_qr_header_slice_panic.md) | Medium | QR handler, `src/main.rs` | source verified | no |
| 2 | [Gene response codes are replayable because the recipient nonce is never retired](2_gene_qr_replay_nonce_never_cleared/advisory_2_gene_qr_replay_nonce_never_cleared.md) | Medium | gene exchange protocol, `src/config.rs` and `src/ux.rs` | source verified | no |
| 3 | [Unbounded reassembly buffer in the CTAP HID vendor session](3_vendor_session_unbounded_buffer/advisory_3_vendor_session_unbounded_buffer.md) | Medium | USB vendor commands, `src/vendor_commands.rs` | source verified | no |
| 4 | [Factory test mode is entered by a QR code carrying a hardcoded public constant](4_factory_mode_qr_hardcoded_constant/advisory_4_factory_mode_qr_hardcoded_constant.md) | Low | QR handler, `src/main.rs` and `src/ux.rs` | source verified | no |
| 5 | [IPC deserialiser pinned to an rkyv release with published archive-validation defects](5_rkyv_ipc_deserialization_vulnerable/advisory_5_rkyv_ipc_deserialization_vulnerable.md) | Low | dependencies and Xous IPC, `Cargo.lock` | source verified | no |
| 6 | [Decrypted gene plaintext is sliced and indexed without a length check](6_post_decrypt_slice_panics/advisory_6_post_decrypt_slice_panics.md) | Low | gene decrypt path, `src/main.rs` | source verified | no |

Every finding is **source verified**, not live confirmed. See Scope below for why, stated plainly:
there is no lab and there could not have been one.

## Scope

The audited tree is the default branch at `3d5cbf7`. There are no tags and no releases, so the
program folder is named for the commit.

**No lab was built, and no target-side reconnaissance ran.** The target is firmware for a custom
SoC. It builds only for `riscv32imac-unknown-xous-elf`, requires the `xous-core` toolchain and a
sibling checkout layout, and runs on baochip silicon in a DEF CON badge. There is no container
image, no emulator and no published artifact; the pre-flight recorded
`lab_up: skipped:no compose file in the tree and no published image resolved`. Consequently the
target-side half of `recon.sh` (nmap, httpx, whatweb, feroxbuster, katana, arjun, nuclei) did not
run, and neither did the HTTP fuzzer, the GraphQL and OpenAPI probes or the JS secret sweep. None of
those tools have anything to address on this target: it exposes no network listener of any kind.
Its attack surface is optical, USB and inter-process.

The pre-flight was also thin on the source side. `recon_src` failed with a missing `recon.sh`, and
semgrep, trivy, trufflehog, osv-scanner, checkov, hadolint, bandit and gosec were all absent from
the host. `npm_audit` correctly skipped, there being no JavaScript. Of 26 stages, 6 ran. The only
substantive source artifacts were `nuclei_src.json` (73 file-template hits, all
`credentials-disclosure-file` and framework-exception noise against a Rust tree, none relevant) and
`db_sinks` (3 hits, all in `src/bitmaps/pngtorust.py`, a build-time PNG converter that is not
shipped to the device). The dependency layer was therefore covered by hand against the OSV API
rather than by a scanner, which is where finding 5 came from.

The audit is accordingly a source audit. Every claim in every advisory is anchored to a file and
line, and each rests on facts readable in the tree: compile-time constant sizes, call-graph
reachability, and the presence or absence of a guard. Where an advisory asserts a runtime outcome,
the Reproduction Steps describe what an operator with a badge should observe, and the Proof of
Concept Code section says explicitly that no executable proof is supplied and why.

## Vendor-declared scope, and what it removes

`defcon-scheme.md` in the repository root is the vendor's own threat model and it is unusually
explicit. Quoted in `THREAT_MODEL.md` and applied throughout. Three whole classes are out of scope
because the vendor documents them as intended:

- **Brute-forcing `Ko`.** "Effectively, Ko is a 'flag' that is there to be captured." The vendor
  publishes a strength schedule dropping to 48 bits by day 4 and estimates one RTX 4090 day.
- **Recovering light-pattern data from a QR code.** "The scheme does nothing to protect the secrecy
  of the light pattern data."
- **Running arbitrary code after entering developer mode.** "Theres' nothing I can do (or want to
  do) to prevent that."

What the vendor does claim, and therefore what is filable, is the integrity of the exchange
protocol on stock firmware: "the goal of the system is to make the QR codes one-time use, and we can
assume protocol integrity is enforced by honest firmware running on honest devices." Finding 2 is
exactly a failure of that claim, and it is the finding most worth the vendor's attention because it
is the one their own specification says should not be possible.

There is no declared deployment posture. `POSTURE.md` returns `NONE-IN-REPO`, and beyond the tree
the repository has no `SECURITY.md`, GitHub private vulnerability reporting is disabled, `has_wiki`
is false and there is no docs site or separate wiki repository. All four off-repository locations
were checked. An unstated posture is not itself relevant here, because no finding depends on network
placement.

## Where the findings came from

Published advisories were empty in every feed: 0 GHSA, 0 NVD keyword hits, 0 OSV for the repository,
0 open issues, no wiki, no closed pull requests to dupe-check against. That is unsurprising for a
repository whose entire visible history is one commit dated the day before the audit. There was no
coverage map to build and no patched-component list to avoid, so the layer walk had nothing to
deprioritise.

The productive strategy was the vendor's own specification. `defcon-scheme.md` states four numbered
security properties, and checking each against the implementation produced finding 2 directly: the
nonce difference check the vendor relies on is real and correct, but the code path that matters
never reaches it, and the one-minute timeout the document treats as implemented does not exist
anywhere in the tree. Reading a vendor's security claims as a checklist beat every generic sweep on
this target.

The second productive strategy was mechanical: every slice and index expression applied to data
that crossed a trust boundary, checked for a preceding length guard. That produced findings 1 and 6.
Rust's bounds checking converts these into panics rather than memory corruption, so they are
availability defects, but on a single-process device that holds the credential store, the password
manager and the UI, availability is not a minor asset.

The dependency layer produced finding 5 by hand, since no scanner was installed. Findings 3 and 4
came from reading the two non-QR entry points, USB vendor commands and the plaintext QR scheme
dispatch.

## Candidates investigated and ruled out

- **Host exfiltration of the password and TOTP store over USB.** `handle_vendor_command` at
  `src/vendor_commands.rs:164` implements `COMMAND_BACKUP_TOTP_CODES` and
  `COMMAND_RESTORE_TOTP_CODES`, which read and write the entire password and TOTP database over
  CTAP HID. This looked like the highest-value finding on the target. It is closed: the gate
  `allow_host` is initialised `AtomicBool::new(false)` at `src/main.rs:122`, is passed to
  `fido2_handler` at `src/main.rs:195`, is read at `src/fido2.rs:80`, and **no `.store()` to it
  exists anywhere in the tree**. A grep for `\.store(` across `src/` returns hits on `action_active`
  and `animate` only. The handler therefore always takes the `else` branch and answers error 44.
  The `MenuReadoutMode` variant in `VaultOp` does not wire to it; the only `readout` symbol is
  `readout_mode` at `src/ux/framework.rs:850`, which toggles the keyboard composite function.
  This is a defence, not a defect, and it is worth the vendor knowing it holds. The reassembly code
  in front of it is still reachable, which is finding 3.
- **Nonce generation weakness.** `generate_my_nonce` at `src/config.rs:312` was checked against the
  scheme document's description. The loop correctly rejects a nonce equal to the header prefix and
  correctly rejects a repeat of the immediately previous value, matching the specification. The
  cipher is AES-GCM-SIV, which is nonce-misuse resistant, so the responder encrypting under an
  attacker-chosen nonce at `src/main.rs:641` does not leak key material. No finding.
- **Replay useful to a third party.** The vendor's second Security proposition, that a copied QR
  code is unlikely to help another honest user, was tested and **holds**. A response ciphertext is
  bound to the nonce of the badge it was minted for, and another player cannot choose their own
  nonce; the only path that sets it is displaying one's own nonce QR, which generates a fresh
  random value. Finding 2 is confined to the original recipient.
- **`Haploid::deserialize` type confusion.** Uses `bytemuck::try_from_bytes`, which requires an
  exact size and alignment match and returns `None` otherwise, handled by an `if let Some` with a
  clean failure path at `src/main.rs:794`. Sound. The defect at that site is the slice feeding it,
  not the deserialiser, which is finding 6.
- **`rand` 0.8.5 advisory.** RUSTSEC-2026-0097 and GHSA-cq8v-f236-94qc cover 0.8.5, but the
  unsoundness requires a custom logger that itself calls into `rand`. The logger here is the Xous
  `log-server`, which does not. Noted, not filed.
- **`aes-gcm-siv` 0.11.1, `qrcode` 0.12, `base45` 3.1.0, `bytemuck` 1.24.0.** All queried against
  OSV; all clean at the locked versions.

## Coverage gaps

- **The upstream OpenSK CTAP2 implementation was not audited in depth.** `src/ctap/` is roughly
  600 KB of Rust derived from Google OpenSK, including `mod.rs` at 154 KB, `data_formats.rs` at
  81 KB and `client_pin.rs` at 64 KB. It carries the PIN protocol, credential management, the
  large-blob store and the CBOR command parser, and it is the largest attack surface on the device
  by volume. It was read for structure and for the DC34-specific modifications only. A defect found
  there would in most cases be a Google OpenSK finding rather than a dc34-vault finding, and belongs
  in a separate audit against that upstream. Anyone continuing this work should start there.
- **`libraries/persistent_store`, `libraries/crypto` and `libraries/cbor`** are likewise upstream
  and were not audited. `persistent_store` is additionally pulled from `betrusted-io/xous-core` at a
  pinned revision for the main binary.
- **No dynamic analysis of any kind.** No fuzzing of the CBOR parser, the CTAP HID framing or the
  base45 decoder, all of which are natural fuzz targets and all of which sit directly on untrusted
  input. `libraries/cbor/fuzz/` ships a `cargo-fuzz` target that was not run. This is the single
  largest gap and it is a consequence of the target being unbuildable on this host.
- **No hardware.** Nothing was confirmed on a badge.
- **`dc34-console`, the sibling repository**, was not audited. It is the peer on the vault's IPC
  surface and holds the hard-coded `ImageLoad` discriminant. It has its own unconsumed pre-flight.

## Recon

The target-side sweep did not run and could not have; see Scope. The source-side sweep ran with 6
of 26 stages producing output, and its two substantive artifacts (`nuclei_src.json`, `db_sinks`)
contained nothing relevant to a Rust firmware target. The dependency layer was covered by hand
against the OSV API. Everything else in this report is manual source reading.

## A note on the master report

`gen_master.py` renders Critical and High findings only, so this program will not appear in
`MASTER_REPORT.md`. That is by design and not a parse failure: the highest severity here is Medium.
