# Findings index for xous-core 5d5bbbf

Critical: 0 · High: 1 · Medium: 1 · Low: 0

| # | Finding | Severity | Component | Auth | Verification | Chain? | Status | Advisory |
|---|---------|----------|-----------|------|--------------|--------|--------|----------|
| 1 | Unvalidated archived-data deserialization on every IPC receive path | High | `xous-ipc` `Buffer::to_original` / `as_flat`, plus two open-coded sites in PDDB | none beyond being a process | source-verified | no | OPEN | [advisory](1_unchecked_rkyv_archive_from_ipc/advisory_1_unchecked_rkyv_archive_from_ipc.md) |
| 2 | Sender-controlled message offset used as a slice bound, panicking the receiving server | Medium | `xous-ipc` `Buffer::from_memory_message`, PDDB bulk read | none beyond being a process | source-verified | no | OPEN | [advisory](2_sender_controlled_offset_panics_server/advisory_2_sender_controlled_offset_panics_server.md) |

Both findings are source-verified, not live-confirmed. See "Coverage gaps" below for why, and what was
done instead.

## Scope

Target: `betrusted-io/xous-core` at `5d5bbbfa95c0dcef26fe1fe9b496b7f6f31d191b` on branch `dev`, which
is the repository's default branch. 1469 Rust files. Xous is a microkernel operating system for the
Precursor and Baochip bao1x devices: a kernel owning the MMU and message passing, a name server, and
userspace servers for encrypted storage, key management, graphics, USB and networking.

Newest tag is `v0.10.2-beta1`, previous `v0.10.1`. The file both findings live in,
`xous-ipc/src/buffer.rs`, is byte-identical at those two tags and at the audited `dev` HEAD
(md5 `cd26dc1cb643c76b2f5ddfaa7e65e0f0`), so the audited state is the released state. The `xous-ipc`
crate declares version 0.10.10, and it is published to crates.io, so the advisories name that as the
affected package rather than only the repository.

One dependency is cited and was read at the version the target pins: `rkyv` 0.8.8, whose `access` and
`access_unchecked` pair is what finding 1 turns on.

**Vendor security policy: none.** No `SECURITY.md` in the root or `.github/`, no `security.txt` on
betrusted.io, xous.dev or bunniestudios.com, no homepage on the repository record, and the GitHub wiki
(cloned and read, 5 pages) carries no security page. Disclosure channel resolution is in `README.md`.

**Deployment posture: not applicable rather than undeclared.** The pre-flight's `POSTURE.md` returned
`NONE-IN-REPO`, and there is nothing here to put behind a proxy: this is a device operating system, so
the relevant boundary is process to process and the product itself is the thing enforcing it. Nothing
in the scope caps the severity of either finding by declaration.

**Published advisories: one, and it is not in the GitHub feed.** `GET /repos/betrusted-io/xous-core/
security-advisories` returns `[]` and the NVD keyword search for `xous` returns 0. OSV returns
RUSTSEC-2024-0431 / GHSA-gv7f-5qqh-vxfx against the `xous` crate on crates.io, "unsound usages of
`core::slice::from_raw_parts`" in `MemoryRange::as_slice`, fixed in 0.9.51. The tree pins 0.9.70 and
later, so it is fixed here. That advisory is the same broad class as finding 1 (unsound handling of
memory that crosses a process boundary) in a different function, which is why the run kept going in
that area rather than treating it as picked over.

**Shared-tool availability:** `tools/recon.sh`, `gen_master.py` and `VENDOR_RESPONSE_LOG.md` are all
absent from this `ZERO-DAY-REPORTS` tree, so no target-side sweep could run, no master report can be
regenerated on this host, and there is no prior-responsiveness signal for this vendor.

## Chain

No chain. Both findings sit on the same input path and share a root area, but neither enables the
other and combining them does not raise either severity. Finding 2 is the certain lower bound of what
that path yields; finding 1 is what it yields if the archived data is followed rather than merely
bounded.

## Where the findings came from

The advisory feed was empty on the repository, so there was no component coverage map to hunt the blank
cells of. What replaced it was the vendor's own issue tracker. Four searches on the tracker
(`unsound`, `memory safety`, `buffer in:title`, `rkyv`) returned issue #93, "Documenting transmutation
of MemoryMessages into data structures", open since 2021, written by the lead maintainer as an aid to
security audits and ending with "This process needs a good hard look, though, to make sure there are
no security exploits". That issue names the exact data path, walks it step by step with permalinks,
and its comment thread contains the other maintainer's note that `valid` and `offset` "were meant to be
advisory and untrusted, but perhaps we should get stronger guarantees on what they do". A vendor
document that says which surface is unaudited, and says so in the tracker rather than in a policy file,
is worth more than any grep, and reading it before the first layer is what scoped this run.

The expensive half was not finding the code, it was establishing what is certain versus what is
argued. Both findings live in a 366-line file, and the reachability question (can an unprivileged
process actually reach a server that parses this way) took the longer walk: the name server's hardcoded
well-known id in `api/xous-api-names/src/lib.rs:32`, the name server's own `connect()` handing out
server ids on a count rather than an identity, and PDDB registering with an unlimited count. That is
what makes the persona "any process" rather than "a process the owner granted something to".

## Candidates investigated and ruled out

**A time-of-check race on a lent page: ruled out by the kernel's design.** The obvious follow-up to
finding 1 is that the sender mutates the page while the receiver parses it. It cannot: `lend_memory`
in `kernel/src/services.rs` remaps the pages out of the sender's address space and into the receiver's,
so the sender has no mapping while the message is in flight. Issue #93 documents the same thing. This
is stated here because it would otherwise look like an omission from finding 1.

**RUSTSEC-2024-0431 in `MemoryRange::as_slice`: fixed, not re-filed.** Published against the `xous`
crate and fixed in 0.9.51; the tree pins 0.9.70 and later.

**The `valid` field: not separately filable.** `valid` is copied through the kernel exactly as `offset`
is and is equally untrusted, but `xous-ipc` never reads it, so there is no sink to reach. It is a
latent hazard for any future code that starts trusting it, which is where `SECURE_DESIGN.md` puts it.

**`Disconnect on Drop is unsound`, issue #482: known, open, and partially addressed.** The maintainer's
own analysis describes a race between a reference count reaching zero and the `disconnect()` that
follows, which can sever a connection another thread has just made. It is a real defect and it is the
vendor's own open issue, so it is not ours to file. A related commit, `8bc4809 remove disconnect idiom
from HAL API`, shows the cleanup is in progress.

**The `db_sinks` pre-flight lead: 722 records, none reachable from IPC.** The Vidar banned-function and
CERT rule pass ran over the C, C++, C# and Python files and reported 44 Critical and 153 High. Those
languages in this tree are build tooling, emulation helpers and the BIO assembler, not code that runs
on the device in the path of a message. The Rust that does run on the device has no SAST coverage in
the pre-flight at all, which is the coverage gap below rather than a clean result.

**The boot chain, USB, TLS and the network stack: not walked.** Real surfaces, out of budget for this
pass, and named here so the report is not read as covering them.

## Coverage gaps

**No live lab, and not for want of trying to find one.** This is an operating system for custom RISC-V
silicon. It builds only for `riscv32imac-unknown-xous-elf` and runs on Precursor or bao1x hardware or
under the Renode emulation the repository ships. This workstation has none of the three things that
could have changed that: `docker` and `podman` are absent (the pre-flight's own `lab_up` stage failed
with `[Errno 2] No such file or directory: 'docker'`), `cargo` and `rustc` are absent, and `renode` is
absent. So the findings could not be exercised and neither could anything else in the tree.

What that costs is specific and worth stating plainly. Finding 2's mechanism is certain from source,
because indexing a slice past its length is a panic in Rust and nothing on the path bounds the value.
Finding 1's mechanism is certain in the same way, but its *consequence* is argued from rkyv's stated
contract rather than demonstrated: what is proven is that hostile bytes reach an unchecked transmute at
a sender-chosen offset, not that a particular archived type yields a particular out-of-bounds read.
Both finding JSONs carry `exploitable: false` and both advisories say so in their Reproduction Steps.

What was done instead: each finding ships a script that fetches the vendors' own source at the pinned
refs and checks every link of its reachability chain, 15 checks for finding 1 and 11 for finding 2, all
passing. Those scripts prove reachability in the code that ships. They do not prove the runtime effect.

**No target-side recon, and no source-side sweep either.** `recon.sh` is absent from this host, which
the pre-flight recorded as `recon_src failed:exception`. Of the pre-flight's 26 stages, 6 ran: the
three advisory pulls, `nuclei_src`, `maps` and `db_sinks`. semgrep, trivy, trufflehog, osv-scanner,
checkov, hadolint, bandit, gosec and npm_audit all recorded `skipped: not installed`, and every
target-side stage recorded `skipped: no live lab`. There is no Rust SAST in the pre-flight's tool set
at all, so nothing mechanical looked at the 1469 files this target is actually written in. The surface
was enumerated by hand from the tracker, the kernel's syscall dispatcher and the name server.

**Five of six layers were not walked.** The threat model ranks the IPC boundary first and this pass
stayed there. On a 1469-file operating system that is a deliberate depth-over-breadth choice, not
coverage: the boot chain, the USB stack, TLS, the network stack, the PDDB's cryptography and the
graphics and window manager all remain unaudited by this run.

## Recon

No sweep form ran. `recon.sh` does not exist on this host, and there is no live target for its
target-side half. The pre-flight's `nuclei_src` stage did run over the source tree (672 KB of output);
it is a file-template pass over a repository with no web surface and produced nothing that bore on
either finding. The route map is one line and it is a Windows console handle in a Python build tool,
which is the right answer for an operating system.
