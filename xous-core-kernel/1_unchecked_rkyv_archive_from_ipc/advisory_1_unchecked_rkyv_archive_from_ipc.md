# Unvalidated archived-data deserialization on every IPC receive path

**Product:** xous-core, commit `5d5bbbfa95c0dcef26fe1fe9b496b7f6f31d191b` (branch `dev`), `xous-ipc` crate 0.10.10
**Affected versions:** `xous-ipc/src/buffer.rs` is byte-identical at `v0.10.1`, `v0.10.2-beta1` and the audited `dev` HEAD, so every current release is affected. No feature flag is involved; this is the default and only IPC path
**Severity:** High
**CWE:** CWE-502 Deserialization of Untrusted Data → CWE-125 Out-of-bounds Read
**Auth required:** none beyond being a process on the device
**Attacker:** a process already running on the device, with no privilege of its own
**Parameter:** the lent page's bytes plus `offset` (`MemoryMessage`, IPC)
**Trigger flow:** hostile process -> `Message::Borrow` with attacker bytes and attacker `offset` -> kernel `syscall.rs` copies `offset` through -> server calls `Buffer::from_memory_message` -> `to_original::<T>()` -> `rkyv::access_unchecked` at a sender-chosen root position -> `rkyv::deserialize` follows the archived type's relative pointers
**Impact:** a server's own address space is read through attacker-chosen relative pointers and lengths, including PDDB, which holds the decrypted keys for the device's encrypted store
**Discovered:** 2026-08-06
**Status:** OPEN — unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com>, the committer of the affected file. The project publishes no security policy, no `security.txt` on betrusted.io, xous.dev or bunniestudios.com, and its wiki carries no security page
**GHSA submission:** https://github.com/betrusted-io/xous-core/security/advisories/new. Ecosystem: crates.io, `xous-ipc`; CVSS 4.0 `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N` (6.9 Medium); CWE-502, CWE-125; attach `poc_1_unchecked_rkyv_archive_from_ipc.py`

## Summary

Every Xous server that accepts a memory message turns the sending process's bytes into a Rust value
with `rkyv::access_unchecked`, the unchecked half of rkyv's API, and the position it reads the archived
root from is derived from the message's `offset` field, which the sender also chooses. Nothing between
the sending syscall and the transmute validates either. rkyv's own documentation for that function
says the byte slice must already represent a valid archived type and points at `access` as the
validating alternative; `access` is not called anywhere in the tree.

The vendor's issue #93, open since 2021, documents this data path and asks for exactly this review
("This process needs a good hard look, though, to make sure there are no security exploits"), and its
maintainer comment notes that `valid` and `offset` "were meant to be advisory and untrusted, but
perhaps we should get stronger guarantees on what they do". That issue describes the mechanism; it does
not name the unchecked call or the fact that the sender selects the root position, and no fix has
landed. The published RUSTSEC-2024-0431 covers a different unsoundness in `xous`
(`MemoryRange::as_slice`) and was fixed in 0.9.51.

## Severity

High. The attacker persona is any process on the device, which needs no grant: the name server has a
hardcoded well-known id that every process connects to, and it hands out server ids permissively by
design, with `max_conns` counting connections rather than checking identity. PDDB, the encrypted
store, registers with an unlimited count and parses attacker bytes in its message loop before any of
its own access control is reached. What the bug defeats is the one boundary this operating system
builds and the whole product depends on: an application must not be able to reach a privileged
server's memory except through that server's API.

Filed a band above the CVSS 4.0 calculator's 6.9 Medium, and the reason is stated plainly so the vendor
can disagree with it: the calculator is dominated by `AV:L` and `PR:L`, which on a general-purpose
server would be a meaningful discount and on a single-user secure device is close to free, since the
persona is any code the owner was persuaded to run or any application whose own input handling failed.
Against that, the memory-safety consequence is source-argued rather than demonstrated. No Xous device
or emulator was available to this audit, so what is proven here is that hostile bytes reach an
unchecked transmute at a sender-chosen offset, not that a specific archived type yields a specific
read. Finding 2 in this folder is the same input path's certain lower bound: a panic.

The repository states no deployment posture and there is nothing to put a proxy in front of; this is
an operating system, so the boundary is process to process and the product itself is what enforces it.

## Root Cause

`xous-ipc/src/buffer.rs:328` `to_original` and `:316` `as_flat` both evaluate
`rkyv::access_unchecked::<U>(&self.slice[..self.used])`. `self.used` is assigned in
`from_memory_message` and `from_memory_message_mut` as `mem.offset.map_or(0, |v| v.get())`, taken
verbatim from the `MemoryMessage` the sender built, and `self.slice` spans the mapped pages. rkyv then
computes the root position as `size.saturating_sub(size_of::<T>())` over that slice, so the sender's
`offset` selects the byte position in its own page at which the receiving server interprets an archived
struct. `rkyv::deserialize` follows that struct's relative pointers and lengths.

The wrong assumption is that the serialized form arriving over IPC was produced by a cooperating peer
running the same `into_buf`. On this system the peer is another process, and the kernel deliberately
does not police the fields: `kernel/src/syscall.rs:113` copies `offset` and `valid` through unchanged
for all three message kinds, and `lend_memory` in `kernel/src/services.rs:1475` never receives them,
validating only that the region is non-zero and page-aligned.

## Impact

A process with no privilege beyond existing sends one page to any server it can name. Inside that
server, an archived type whose relative pointers and lengths the attacker chose is dereferenced and
then deserialized, so reads land wherever those pointers reach in the server's address space and
attacker-chosen lengths decide how much is copied. The value returned by `to_original` is the server's
own request struct, so the copied bytes flow onward into whatever that server does with a request, and
for types carrying a `String` or `Vec` the deserialized result is returned to the sender in a reply
buffer.

The servers this reaches are the ones that matter on this device: PDDB holds the decrypted basis keys
for the encrypted store, the keystore mediates root key material and the one-way counters that carry
secure boot state, and GAM arbitrates what the user sees. There are 356 `to_original` and `as_flat`
call sites across `services/`, 234 of which unwrap the result directly.

## Solution

Replace `rkyv::access_unchecked` with the validating `rkyv::access` in `Buffer::to_original` and
`Buffer::as_flat`, deriving `CheckBytes` for every type sent over IPC, and return an error rather than
panicking when validation fails. Apply the same change to the two open-coded sites in
`services/pddb/src/lib.rs:1272` and `services/pddb/src/main.rs:1917`. Validation cost is paid once per
message on a path that already copies the whole structure.

## Reproduction Steps

Environment: Precursor or Baochip bao1x hardware, or the Renode emulation the repository ships under
`emulation/`, running an image built from `betrusted-io/xous-core` at `v0.10.2-beta1` or later, target
`riscv32imac-unknown-xous-elf`. Two processes are needed: any unprivileged application, and any server
that accepts a memory message, for example the name server or PDDB.

1. Build and boot a stock image: `cargo xtask app-image` for Precursor, or the baochip target per
   `README-baochip.md`. No configuration change is required, and no feature flag needs enabling.
2. In an ordinary application, allocate one page with `xous::map_memory(None, None, 4096, MemoryFlags::R | MemoryFlags::W)`
   and fill it with bytes of your choosing rather than with an `rkyv` serialization.
3. Obtain a connection to a server the way any application does: `xous_names::XousNames::new()` and
   `request_connection_blocking("_xous-names_")`, or any server name registered with an unlimited
   connection count.
4. Send the page as a memory message, setting `offset` to a value you choose inside the page, for
   example `MemoryAddress::new(0x40)`, and an `id` the server routes to a handler that calls
   `to_original`. The `xous::Message::Borrow` constructor takes the `MemoryMessage` directly, so this
   needs no cooperation from `xous-ipc`.
5. The receiving server transmutes an archived value at byte `0x40-size_of::<Archived T>()` of the
   page you filled and then deserializes it. Watch the server's behaviour: with pointer fields chosen
   to reach outside the page, the read leaves the buffer.

Note on this audit's verification: the chain from the sending syscall to the unchecked transmute, the
sender's control of the root position, and the absence of any validating path in the tree were verified
in upstream source at the two pinned refs by the script below, which fetches the vendors' own bytes and
checks every link. Steps 1 to 5 were not executed, because no Xous device or emulator was available.
`exploitable` is `false` in the accompanying finding JSON.

## Proof of Concept Code

`poc_1_unchecked_rkyv_archive_from_ipc.py`

````python
#!/usr/bin/env python3
# Author: Infinit3i
#
# xous-core: every IPC receive path deserializes a sending process's bytes with
# rkyv::access_unchecked, so a hostile process chooses both the archived bytes and the position the
# receiving server reads them from.
#
# WHAT THIS SCRIPT IS. It walks the reachability chain across the two source trees the finding spans,
# xous-core at the audited commit and rkyv at the version xous-ipc pins, reading the vendors' own
# bytes. It fetches them itself over https, so it needs nothing set up beforehand. Every check is a
# substring or structural test against upstream source; nothing here re-implements, models or
# simulates any part of the product.
#
# WHAT THIS SCRIPT IS NOT. It is not the exploit. Xous builds only for riscv32imac-unknown-xous-elf
# and runs on Precursor or Baochip bao1x silicon, so exploiting this needs a device or an emulator
# and a second process on it. See the advisory's Reproduction Steps.
#
#   python3 poc_1_unchecked_rkyv_archive_from_ipc.py
#   python3 poc_1_unchecked_rkyv_archive_from_ipc.py --xous-src ./xous-core

import argparse
import hashlib
import os
import re
import sys
import tempfile
import urllib.request

XOUS_REF = "5d5bbbfa95c0dcef26fe1fe9b496b7f6f31d191b"
RKYV_REF = "0.8.8"
XOUS_RAW = "https://raw.githubusercontent.com/betrusted-io/xous-core/" + XOUS_REF
RKYV_RAW = "https://raw.githubusercontent.com/rkyv/rkyv/" + RKYV_REF

XOUS_FILES = [
    "xous-ipc/src/buffer.rs",
    "xous-ipc/Cargo.toml",
    "kernel/src/syscall.rs",
    "xous-rs/src/definitions.rs",
    "api/xous-api-names/src/lib.rs",
    "services/xous-names/src/main.rs",
    "services/pddb/src/main.rs",
    "Cargo.toml",
]
RKYV_FILES = ["rkyv/src/api/mod.rs"]

# the three releases the audited buffer.rs is byte-identical across
RELEASE_REFS = ["v0.10.1", "v0.10.2-beta1", XOUS_REF]

results = []


def check(label, ok, detail):
    results.append((label, bool(ok), detail))
    print("  [%s] %-48s %s" % ("PASS" if ok else "FAIL", label, detail))
    return bool(ok)


def fetch(base, rel, root):
    dest = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if not os.path.exists(dest):
        with urllib.request.urlopen(base + "/" + rel, timeout=30) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
    return dest


def load(root, base, files, label):
    out = {}
    for rel in files:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            if base is None:
                sys.exit("[!] %s missing from the tree you passed: %s" % (rel, root))
            path = fetch(base, rel, root)
        with open(path, "r", errors="replace") as f:
            out[rel] = f.read()
    print("[*] %s: %d file(s) from %s" % (label, len(out), root))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Verify that xous-ipc deserializes sender-controlled bytes with rkyv's unchecked "
                    "API, using upstream source at the pinned refs.")
    ap.add_argument("--xous-src", default=None,
                    help="local xous-core checkout at %s (default: fetch)" % XOUS_REF[:9])
    ap.add_argument("--rkyv-src", default=None,
                    help="local rkyv checkout at %s (default: fetch)" % RKYV_REF)
    args = ap.parse_args()

    tmp = None
    if args.xous_src is None or args.rkyv_src is None:
        tmp = tempfile.mkdtemp(prefix="xous-evidence-")
        print("[*] fetching pinned sources into %s" % tmp)

    xous = load(args.xous_src or os.path.join(tmp, "xous"),
                None if args.xous_src else XOUS_RAW, XOUS_FILES, "xous-core")
    rkyv = load(args.rkyv_src or os.path.join(tmp, "rkyv"),
                None if args.rkyv_src else RKYV_RAW, RKYV_FILES, "rkyv")

    buf = xous["xous-ipc/src/buffer.rs"]
    ipc_toml = xous["xous-ipc/Cargo.toml"]
    syscall = xous["kernel/src/syscall.rs"]
    defs = xous["xous-rs/src/definitions.rs"]
    names_api = xous["api/xous-api-names/src/lib.rs"]
    names_srv = xous["services/xous-names/src/main.rs"]
    pddb = xous["services/pddb/src/main.rs"]
    root_toml = xous["Cargo.toml"]
    api = rkyv["rkyv/src/api/mod.rs"]

    ok = True
    print("\n--- 1. the receive path deserializes without validation ---")
    ok &= check("to_original uses access_unchecked",
                "pub fn to_original<T, U>" in buf
                and buf.count("rkyv::access_unchecked::<U>(&self.slice[..self.used])") == 2,
                "as_flat and to_original, both on the same expression")
    ok &= check("rkyv pins 0.8.x in xous-ipc",
                re.search(r'rkyv\s*=\s*\{\s*version\s*=\s*"0\.8', ipc_toml) is not None,
                "xous-ipc/Cargo.toml")
    ok &= check("rkyv documents the unchecked contract",
                "This function does not check that the bytes are valid to access. Use" in api
                and "The byte slice must represent a valid archived type when accessed at the" in api,
                "access_unchecked's own doc comment names access() as the safe form")
    ok &= check("a checked API exists and is unused here",
                "pub unsafe fn access_unchecked" in api and "rkyv::access::<" not in buf,
                "rkyv::access is never called in buffer.rs")

    print("\n--- 2. the bytes and the read position both come from the sender ---")
    ok &= check("used is taken from the message offset",
                buf.count("used: mem.offset.map_or(0, |v| v.get())") == 2,
                "from_memory_message and from_memory_message_mut")
    ok &= check("offset is a bare NonZeroUsize",
                "pub type MemoryAddress = NonZeroUsize;" in defs
                and "pub type MemorySize = NonZeroUsize;" in defs,
                "no range, no relation to the mapped length")
    ok &= check("the kernel copies offset and valid through",
                syscall.count("offset: msg.offset,") >= 3 and syscall.count("valid: msg.valid,") >= 3,
                "3 message kinds, no validation on the way")
    m = re.search(r"pub fn root_position<T: Portable>\(size: usize\) -> usize \{\s*"
                  r"size\.saturating_sub\(size_of::<T>\(\)\)", api)
    ok &= check("root position is derived from that same length", m is not None,
                "root_position(size) = size - size_of::<Archived T>(), so offset picks it")
    ok &= check("rkyv's only bounds assertion is debug-only",
                "#[cfg(debug_assertions)]\nfn sanity_check_buffer" in api,
                "sanity_check_buffer, compiled out of release builds")
    ok &= check("xous-core builds release without debug assertions",
                "[profile.release]" in root_toml and "debug-assertions" not in root_toml,
                "profile.release does not re-enable them")

    print("\n--- 3. any process on the device can reach a server that does this ---")
    ok &= check("the name server has a hardcoded well-known id",
                'xous::connect(xous::SID::from_bytes(b"xous-name-server")' in names_api,
                "no grant needed to reach it")
    ok &= check("names hands out server ids permissively",
                "if None, unlimited connections allowed" in names_srv
                and "thus allowing a permissive policy inside" in names_srv,
                "max_conns is a count, not an identity check")
    ok &= check("PDDB registers with an unlimited count",
                "register_name(api::SERVER_NAME_PDDB, None)" in pddb,
                "the encrypted store accepts a connection from any process")
    ok &= check("PDDB open-codes the same unchecked access",
                "rkyv::access_unchecked::<ArchivedPddbDictRequest>(" in pddb,
                "not only through xous-ipc")

    print("\n--- 4. it is the same code in every current release ---")
    digests = {}
    for ref in RELEASE_REFS:
        url = "https://raw.githubusercontent.com/betrusted-io/xous-core/%s/xous-ipc/src/buffer.rs" % ref
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                digests[ref] = hashlib.md5(r.read()).hexdigest()
        except Exception as e:
            digests[ref] = "unreachable: %s" % e
    ok &= check("buffer.rs is identical across the release refs",
                len(set(digests.values())) == 1 and "unreachable" not in "".join(digests.values()),
                "%s = %s" % (", ".join(RELEASE_REFS[:2] + ["dev"]), list(digests.values())[0][:16]))

    print()
    bad = [r[0] for r in results if not r[1]]
    if bad:
        print("NOT CONFIRMED: %d link(s) did not verify: %s" % (len(bad), ", ".join(bad)))
        return 1
    print("SOURCE-VERIFIED: every link of the chain holds at xous-core %s / rkyv %s."
          % (XOUS_REF[:9], RKYV_REF))
    print("  A process sends a memory message to any server it can name. It owns every byte of the")
    print("  page and it owns `offset`, which becomes `used`, which selects both the slice bound and")
    print("  the root position rkyv transmutes at. No validation runs, in release builds not even an")
    print("  assertion, and the archived type's relative pointers and lengths are then followed by")
    print("  rkyv::deserialize inside the receiving server.")
    print()
    print("  exploitable=false in the finding JSON: no Xous device or emulator was available to this")
    print("  audit, so the memory-safety consequence is argued from rkyv's own stated contract rather")
    print("  than demonstrated. See the advisory's Severity section.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
````

Output at the audited refs:

````text
--- 1. the receive path deserializes without validation ---
  [PASS] to_original uses access_unchecked                as_flat and to_original, both on the same expression
  [PASS] rkyv pins 0.8.x in xous-ipc                      xous-ipc/Cargo.toml
  [PASS] rkyv documents the unchecked contract            access_unchecked's own doc comment names access() as the safe form
  [PASS] a checked API exists and is unused here          rkyv::access is never called in buffer.rs

--- 2. the bytes and the read position both come from the sender ---
  [PASS] used is taken from the message offset            from_memory_message and from_memory_message_mut
  [PASS] offset is a bare NonZeroUsize                    no range, no relation to the mapped length
  [PASS] the kernel copies offset and valid through       3 message kinds, no validation on the way
  [PASS] root position is derived from that same length   root_position(size) = size - size_of::<Archived T>(), so offset picks it
  [PASS] rkyv's only bounds assertion is debug-only       sanity_check_buffer, compiled out of release builds
  [PASS] xous-core builds release without debug assertions profile.release does not re-enable them

--- 3. any process on the device can reach a server that does this ---
  [PASS] the name server has a hardcoded well-known id    no grant needed to reach it
  [PASS] names hands out server ids permissively          max_conns is a count, not an identity check
  [PASS] PDDB registers with an unlimited count           the encrypted store accepts a connection from any process
  [PASS] PDDB open-codes the same unchecked access        not only through xous-ipc

--- 4. it is the same code in every current release ---
  [PASS] buffer.rs is identical across the release refs   v0.10.1, v0.10.2-beta1, dev = cd26dc1cb643c76b

SOURCE-VERIFIED: every link of the chain holds at xous-core 5d5bbbfa9 / rkyv 0.8.8.
````

## Affected Files

xous-core at `5d5bbbfa9`:

xous-ipc/src/buffer.rs:334: `to_original` calls `rkyv::access_unchecked` on a slice of sender-supplied bytes and then deserializes the result
xous-ipc/src/buffer.rs:321: `as_flat` does the same and hands back a reference into the sender's page
xous-ipc/src/buffer.rs:114: `used` is taken from `mem.offset` with no relation to the mapped length set on the line above
xous-ipc/src/buffer.rs:125: the same assignment in `from_memory_message_mut`
kernel/src/syscall.rs:113: `offset` and `valid` are copied into the delivered message unchanged, for all three memory-message kinds
services/pddb/src/main.rs:1917: the encrypted store open-codes the same unchecked access on its own bulk-read path
services/pddb/src/lib.rs:1272: and again on the key-record path
services/xous-names/src/main.rs:194: connections are handed out with no identity check, so any process reaches these servers

Referenced, not owned by this repository, at rkyv `0.8.8`:

rkyv/src/api/mod.rs:266: `access_unchecked`'s safety contract requires the bytes to already be a valid archive and names `access` as the validating alternative
rkyv/src/api/mod.rs:100: `root_position` derives the root from the slice length, which is what makes the sender's `offset` select it
rkyv/src/api/mod.rs:36: the only bounds assertion is `#[cfg(debug_assertions)]` and is absent from release builds
