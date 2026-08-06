# Sender-controlled message offset used as a slice bound, panicking the receiving server

**Product:** xous-core, commit `5d5bbbfa95c0dcef26fe1fe9b496b7f6f31d191b` (branch `dev`), `xous-ipc` crate 0.10.10
**Affected versions:** `xous-ipc/src/buffer.rs` is byte-identical at `v0.10.1`, `v0.10.2-beta1` and the audited `dev` HEAD, so every current release is affected. No feature flag is involved
**Severity:** Medium
**CWE:** CWE-129 Improper Validation of Array Index → CWE-248 Uncaught Exception
**Auth required:** none beyond being a process on the device
**Attacker:** a process already running on the device, with no privilege of its own
**Parameter:** `offset` (`MemoryMessage`, IPC)
**Trigger flow:** hostile process -> `Message::Borrow` with `offset` greater than the page length -> kernel `syscall.rs` copies `offset` through -> server calls `Buffer::from_memory_message` -> `used = offset` -> `&self.slice[..self.used]` -> panic -> server process terminates with nothing to restart it
**Impact:** any server reachable from the sending process dies until the device reboots; against the name server that is terminal for the whole system, since no process can resolve a server id afterwards
**Discovered:** 2026-08-06
**Status:** OPEN — unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com>, the committer of the affected file. The project publishes no security policy, no `security.txt` on betrusted.io, xous.dev or bunniestudios.com, and its wiki carries no security page
**GHSA submission:** https://github.com/betrusted-io/xous-core/security/advisories/new. Ecosystem: crates.io, `xous-ipc`; CVSS 4.0 `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` (6.8 Medium); CWE-129, CWE-248; attach `poc_2_sender_controlled_offset_panics_server.py`

## Summary

`Buffer::from_memory_message` sets the slice length from the pages the kernel mapped and the read
bound, `used`, from the `offset` field the sending process chose, on adjacent lines, and never compares
them. Six expressions in the same file index `self.slice[..self.used]`, so a process that lends one
page and sets `offset` past the end of it panics whichever server parses the message. Xous has no
supervisor: `grep -riE 'restart|respawn|supervis' kernel/src/` finds only a unit test, so the server
stays dead until the device reboots.

The vendor's issue #93 is where the intent behind these fields is recorded: its maintainer comment says
`valid` and `offset` "were meant to be advisory and untrusted, but perhaps we should get stronger
guarantees on what they do". That is an accurate description of the design and it is also the defect,
because the receiving side treats an untrusted value as a bound without ever bounding it. That issue
is open, describes the data path rather than this consequence, and no fix has landed. Finding 1 in this
folder is the memory-safety half of the same input path.

## Severity

Medium. The attacker persona is any process on the device, which needs no grant of any kind: the name
server has a hardcoded well-known id that every process connects to at startup, and it hands out
server ids permissively by design. The effect is availability only, with no disclosure and no code
execution, which is why it is not filed higher. Two things keep it from being lower. The name server
is universally reachable and is the service every other connection depends on, so killing it is not the
loss of one feature but of the system's ability to wire itself together, recoverable only by reboot.
And PDDB, the encrypted store, carries an extra panic on the same path: `range.offset.expect("Missing
offset in DictBulkRead request")` means a message with no `offset` at all kills it before the bound is
even reached.

The repository states no deployment posture and there is nothing to put a proxy in front of; this is an
operating system, so the boundary is process to process and the product itself is what enforces it.

## Root Cause

`xous-ipc/src/buffer.rs:113` builds `slice` as `from_raw_parts_mut(mem.buf.as_mut_ptr(), mem.buf.len())`
and the next line sets `used: mem.offset.map_or(0, |v| v.get())`. The two values come from unrelated
sources and no code between them establishes a relation. `as_flat`, `to_original` and the `AsRef`,
`AsMut`, `Deref` and `DerefMut` implementations then index `self.slice[..self.used]`, which is a
panicking operation in Rust whenever the bound exceeds the length.

Nothing upstream constrains the value. `MemoryAddress` is a bare `NonZeroUsize` in
`xous-rs/src/definitions.rs:4`, `kernel/src/syscall.rs:113` copies `offset` and `valid` into the
delivered message unchanged for all three memory-message kinds, and `lend_memory` in
`kernel/src/services.rs:1475` is not even passed them: it validates that the region is non-zero,
page-aligned and that the addresses are page-aligned, which is a statement about the pages rather than
about where inside them the receiver should read.

## Impact

One message from an unprivileged process terminates a server. Which server is the attacker's choice
among everything the name server will connect them to, which in the shipped image includes PDDB, the
keystore, the graphics and window manager, the power manager and the name server itself. Nothing
restarts any of them.

Killing the name server is the worst case and needs no privilege at all, because reaching it requires
no grant: after that, no process can resolve any server id, so no new connection can be made anywhere
in the system and the device is inert until it is power-cycled. Killing PDDB takes the encrypted store
offline together with every application that depends on it. Repeating the message after each reboot
makes the condition persistent in practice.

## Solution

In `Buffer::from_memory_message` and `from_memory_message_mut`, clamp the value taken from
`mem.offset` to the mapped length, `used: mem.offset.map_or(0, |v| v.get()).min(mem.buf.len())`, or
reject the message when it exceeds it. Apply the same bound in `services/pddb/src/main.rs:1917` and
replace its `.expect("Missing offset in DictBulkRead request")` with an error return, so an absent
`offset` is a rejected request rather than a dead service.

## Reproduction Steps

Environment: Precursor or Baochip bao1x hardware, or the Renode emulation the repository ships under
`emulation/`, running an image built from `betrusted-io/xous-core` at `v0.10.2-beta1` or later, target
`riscv32imac-unknown-xous-elf`. Two processes are needed: any unprivileged application, and any server
that accepts a memory message.

1. Build and boot a stock image: `cargo xtask app-image` for Precursor, or the baochip target per
   `README-baochip.md`. No configuration change is required.
2. Confirm the system is healthy: applications start, and the name server resolves connections.
3. In an ordinary application, allocate one page:
   `let page = xous::map_memory(None, None, 4096, MemoryFlags::R | MemoryFlags::W).unwrap();`
4. Connect to the name server the way every process does, with `xous::connect(xous::SID::from_bytes(b"xous-name-server").unwrap())`.
5. Send a memory message whose `offset` is larger than the page:
   `xous::send_message(cid, xous::Message::Borrow(xous::MemoryMessage { id: <an id the server parses>, buf: page, offset: xous::MemoryAddress::new(0x9999), valid: xous::MemorySize::new(4096) }))`
6. The name server panics while indexing the buffer. Observe that it does not come back: subsequent
   `XousNames::new()` calls from any process no longer resolve, and the condition persists until the
   device is power-cycled.
7. Repeat against PDDB for the second panic path by sending a message with `offset: None` to the bulk
   read opcode; the `.expect` there fires before any bound is checked.

Note on this audit's verification: the chain from the sending syscall to the slice bound, the absence
of any relation between the bound and the mapped length, and the absence of any supervisor were
verified in upstream source at the pinned commit by the script below, which fetches the vendor's own
bytes and checks every link. Steps 1 to 7 were not executed, because no Xous device or emulator was
available. `exploitable` is `false` in the accompanying finding JSON.

## Proof of Concept Code

`poc_2_sender_controlled_offset_panics_server.py`

````python
#!/usr/bin/env python3
# Author: Infinit3i
#
# xous-core: the `offset` field of an IPC memory message is used as a slice bound in the receiving
# server with no check against the mapped length, so any process can panic any server it can name.
#
# WHAT THIS SCRIPT IS. It walks the reachability chain in xous-core at the audited commit, reading
# the vendor's own bytes. It fetches them itself over https, so it needs nothing set up beforehand.
# Every check is a substring or structural test against upstream source; nothing here re-implements,
# models or simulates any part of the product.
#
# WHAT THIS SCRIPT IS NOT. It is not the exploit. Xous builds only for
# riscv32imac-unknown-xous-elf and runs on Precursor or Baochip bao1x silicon, so triggering this
# needs a device or an emulator and a second process on it. See the advisory's Reproduction Steps.
#
#   python3 poc_2_sender_controlled_offset_panics_server.py
#   python3 poc_2_sender_controlled_offset_panics_server.py --xous-src ./xous-core

import argparse
import os
import re
import sys
import tempfile
import urllib.request

XOUS_REF = "5d5bbbfa95c0dcef26fe1fe9b496b7f6f31d191b"
XOUS_RAW = "https://raw.githubusercontent.com/betrusted-io/xous-core/" + XOUS_REF

XOUS_FILES = [
    "xous-ipc/src/buffer.rs",
    "xous-rs/src/definitions.rs",
    "kernel/src/services.rs",
    "kernel/src/syscall.rs",
    "services/xous-names/src/main.rs",
    "services/pddb/src/main.rs",
]

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


def fn_body(src, sig):
    """Text of a function starting at `sig`, to its closing brace."""
    i = src.find(sig)
    if i < 0:
        return ""
    j = src.find("{", i)
    depth, k = 1, j + 1
    while k < len(src) and depth:
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
        k += 1
    return src[i:k]


def main():
    ap = argparse.ArgumentParser(
        description="Verify that a sending process controls a slice bound in the receiving server, "
                    "using upstream source at the pinned commit.")
    ap.add_argument("--xous-src", default=None,
                    help="local xous-core checkout at %s (default: fetch)" % XOUS_REF[:9])
    args = ap.parse_args()

    tmp = None
    if args.xous_src is None:
        tmp = tempfile.mkdtemp(prefix="xous-evidence-")
        print("[*] fetching pinned sources into %s" % tmp)

    xous = load(args.xous_src or os.path.join(tmp, "xous"),
                None if args.xous_src else XOUS_RAW, XOUS_FILES, "xous-core")

    buf = xous["xous-ipc/src/buffer.rs"]
    defs = xous["xous-rs/src/definitions.rs"]
    services = xous["kernel/src/services.rs"]
    syscall = xous["kernel/src/syscall.rs"]
    names = xous["services/xous-names/src/main.rs"]
    pddb = xous["services/pddb/src/main.rs"]

    ok = True
    print("\n--- 1. the bound and the length are set from unrelated sources ---")
    ctor = fn_body(buf, "pub unsafe fn from_memory_message(")
    ok &= check("slice length comes from the mapped pages",
                "core::slice::from_raw_parts_mut(mem.buf.as_mut_ptr(), mem.buf.len())" in ctor,
                "mem.buf.len()")
    ok &= check("used comes from the message offset",
                "used: mem.offset.map_or(0, |v| v.get())" in ctor,
                "mem.offset, no default cap")
    ok &= check("the constructor relates them nowhere",
                not re.search(r"\.min\(|\.max\(|if .*used.*>|assert", ctor),
                "no comparison of offset against len in either constructor")
    sites = len(re.findall(r"self\.slice\[\.\.self\.used\]", buf))
    ok &= check("used is then a slice bound",
                sites >= 6,
                "%d sites: as_flat, to_original, AsRef, AsMut, Deref, DerefMut. "
                "Rust panics when used > slice.len()" % sites)

    print("\n--- 2. the sender owns that value end to end ---")
    ok &= check("offset is a bare NonZeroUsize",
                "pub type MemoryAddress = NonZeroUsize;" in defs,
                "any non-zero usize is representable")
    ok &= check("the kernel copies it through unchanged",
                syscall.count("offset: msg.offset,") >= 3,
                "3 message kinds in the syscall dispatcher")
    lend = fn_body(services, "pub fn lend_memory(\n        &mut self,")
    ok &= check("the kernel's lend path never sees offset",
                lend and "offset" not in lend.split("{", 1)[0],
                "lend_memory takes (src_virt, dest_pid, dest_virt, len, mutable) only")
    ok &= check("what it does validate is the page geometry",
                "return Err(xous_kernel::Error::BadAlignment)" in lend
                and "len & 0xfff != 0" in lend,
                "len non-zero and page-aligned, addresses page-aligned")

    print("\n--- 3. the servers it reaches, and what a panic costs ---")
    ok &= check("the name server parses a memory message this way",
                "Buffer::from_memory_message_mut(mem)" in names
                and "to_original::<Registration, _>().unwrap()" in names,
                "reachable by every process through a hardcoded server id")
    ok &= check("PDDB open-codes the same bound",
                'range.offset.expect("Missing offset in DictBulkRead request").get()' in pddb,
                "two panics in one line: absent offset, and offset past the buffer")
    ok &= check("nothing restarts a server that dies",
                not re.search(r"fn (restart|respawn)_server\b", services)
                and "supervis" not in services.lower(),
                "no supervisor in the kernel's service layer")

    print()
    bad = [r[0] for r in results if not r[1]]
    if bad:
        print("NOT CONFIRMED: %d link(s) did not verify: %s" % (len(bad), ", ".join(bad)))
        return 1
    print("SOURCE-VERIFIED: every link of the chain holds at xous-core %s." % XOUS_REF[:9])
    print("  A process lends one page and sets offset past the end of it. The receiving server takes")
    print("  that value as `used`, indexes `&self.slice[..self.used]` and panics. Xous has no")
    print("  supervisor, so the server is gone until the device reboots. Against the name server that")
    print("  is terminal for the whole system: nothing can resolve a server id afterwards.")
    print()
    print("  exploitable=false in the finding JSON: no Xous device or emulator was available to this")
    print("  audit, so the panic was not observed on a running system.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
````

Output at the audited commit:

````text
--- 1. the bound and the length are set from unrelated sources ---
  [PASS] slice length comes from the mapped pages         mem.buf.len()
  [PASS] used comes from the message offset               mem.offset, no default cap
  [PASS] the constructor relates them nowhere             no comparison of offset against len in either constructor
  [PASS] used is then a slice bound                       6 sites: as_flat, to_original, AsRef, AsMut, Deref, DerefMut. Rust panics when used > slice.len()

--- 2. the sender owns that value end to end ---
  [PASS] offset is a bare NonZeroUsize                    any non-zero usize is representable
  [PASS] the kernel copies it through unchanged           3 message kinds in the syscall dispatcher
  [PASS] the kernel's lend path never sees offset         lend_memory takes (src_virt, dest_pid, dest_virt, len, mutable) only
  [PASS] what it does validate is the page geometry       len non-zero and page-aligned, addresses page-aligned

--- 3. the servers it reaches, and what a panic costs ---
  [PASS] the name server parses a memory message this way reachable by every process through a hardcoded server id
  [PASS] PDDB open-codes the same bound                   two panics in one line: absent offset, and offset past the buffer
  [PASS] nothing restarts a server that dies              no supervisor in the kernel's service layer

SOURCE-VERIFIED: every link of the chain holds at xous-core 5d5bbbfa9.
````

## Affected Files

xous-core at `5d5bbbfa9`:

xous-ipc/src/buffer.rs:113: `slice` is built from the mapped page length
xous-ipc/src/buffer.rs:114: `used` is taken from `mem.offset` on the next line, with no relation to it
xous-ipc/src/buffer.rs:125: the same pair in `from_memory_message_mut`
xous-ipc/src/buffer.rs:321: `as_flat` indexes `self.slice[..self.used]`
xous-ipc/src/buffer.rs:334: `to_original` does the same
xous-ipc/src/buffer.rs:342: `AsRef` does the same, as do `AsMut`, `Deref` and `DerefMut` on the three lines after it
kernel/src/syscall.rs:113: `offset` is copied into the delivered message unchanged
kernel/src/services.rs:1475: `lend_memory` validates page geometry and is never passed `offset`
services/pddb/src/main.rs:1917: the encrypted store uses `range.offset.expect(...)` directly as a slice bound, adding a second panic for an absent `offset`
services/xous-names/src/main.rs:370: the universally reachable name server parses a memory message this way
