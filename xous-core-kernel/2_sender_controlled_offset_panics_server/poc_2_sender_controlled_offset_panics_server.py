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
