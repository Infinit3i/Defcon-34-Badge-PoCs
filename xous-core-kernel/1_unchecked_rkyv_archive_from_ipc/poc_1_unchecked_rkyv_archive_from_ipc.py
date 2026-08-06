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
