#!/usr/bin/env python3
# Author: Infinit3i
#
# dc34-console: "test bootwait enable" is reachable from the unauthenticated USB serial console and
# permanently stops the badge from booting.
#
# WHAT THIS SCRIPT IS. It walks the reachability chain across the two source trees the finding spans,
# reading the vendor's own bytes at the exact commits the shipped firmware is built from. It fetches
# them itself over https, so it needs nothing set up beforehand. Every check below is a substring or
# structural test against upstream source; nothing here re-implements, models or simulates any part
# of the product.
#
# WHAT THIS SCRIPT IS NOT. It is not the exploit. The exploit is one line typed into the badge's USB
# serial console and it needs the physical badge, because the effect lands in ACRAM one-way counter
# offset 80 and is read by the boot1 bootloader. The exploit is written out in the advisory's
# Reproduction Steps. This script proves that the line reaches the counter in the firmware that ships.
#
#   python3 poc_1_ungated_bootwait_console_command.py
#   python3 poc_1_ungated_bootwait_console_command.py --console-src ./dc34-console --xous-src ./xous-core

import argparse
import os
import re
import sys
import tempfile
import urllib.request

CONSOLE_REF = "bf64e03f019532cca5055fcdbe51977d572e3630"
XOUS_REF = "616bf65f6e379165464f50b1e79ec42aff77a683"
CONSOLE_RAW = "https://raw.githubusercontent.com/bunnie/dc34-console/" + CONSOLE_REF
XOUS_RAW = "https://raw.githubusercontent.com/betrusted-io/xous-core/" + XOUS_REF

CONSOLE_FILES = ["build.sh", "src/main.rs", "src/cmds.rs", "src/cmds/test.rs"]
XOUS_FILES = [
    "services/usb-bao1x/src/lib.rs",
    "services/keystore/src/lib.rs",
    "services/keystore/src/platform/baosec/server.rs",
    "services/keystore/src/platform/baosec/store.rs",
    "libs/bao1x-api/src/offsets/common.rs",
    "libs/bao1x-hal/src/acram.rs",
    "bao1x-boot/boot1/src/main.rs",
]

# feature flags that gate the hazardous arms of test.rs. If build.sh enabled any of these, the
# finding would not ship.
GATING_FEATURES = ["hazardous-test", "misc-test", "qa-test", "owc-test", "factory-mismatch",
                   "factory-wipe", "wfi-stress-test"]

results = []


def check(label, ok, detail):
    results.append((label, bool(ok), detail))
    print("  [%s] %-46s %s" % ("PASS" if ok else "FAIL", label, detail))
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


def arm_is_gated(src, arm):
    """True when the match arm for `arm` in test.rs carries a #[cfg(feature = ...)] attribute."""
    lines = src.splitlines()
    pat = re.compile(r'^\s*"%s"\s*=>' % re.escape(arm))
    for i, line in enumerate(lines):
        if pat.match(line):
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            return j >= 0 and lines[j].strip().startswith("#[cfg(")
    return None  # arm not present at all


def main():
    ap = argparse.ArgumentParser(
        description="Verify that 'test bootwait' reaches the ACRAM one-way counter in shipped "
                    "dc34-console firmware, using upstream source at the pinned commits.")
    ap.add_argument("--console-src", default=None,
                    help="local dc34-console checkout at %s (default: fetch)" % CONSOLE_REF[:8])
    ap.add_argument("--xous-src", default=None,
                    help="local xous-core checkout at %s (default: fetch)" % XOUS_REF[:8])
    args = ap.parse_args()

    tmp = None
    if args.console_src is None or args.xous_src is None:
        tmp = tempfile.mkdtemp(prefix="dc34-evidence-")
        print("[*] fetching pinned sources into %s" % tmp)

    console = load(args.console_src or os.path.join(tmp, "console"),
                   None if args.console_src else CONSOLE_RAW, CONSOLE_FILES, "dc34-console")
    xous = load(args.xous_src or os.path.join(tmp, "xous"),
                None if args.xous_src else XOUS_RAW, XOUS_FILES, "xous-core")

    test_rs = console["src/cmds/test.rs"]
    build_sh = console["build.sh"]
    main_rs = console["src/main.rs"]
    usb_lib = xous["services/usb-bao1x/src/lib.rs"]
    ks_lib = xous["services/keystore/src/lib.rs"]
    ks_srv = xous["services/keystore/src/platform/baosec/server.rs"]
    ks_store = xous["services/keystore/src/platform/baosec/store.rs"]
    offsets = xous["libs/bao1x-api/src/offsets/common.rs"]
    acram = xous["libs/bao1x-hal/src/acram.rs"]
    boot1 = xous["bao1x-boot/boot1/src/main.rs"]

    print("\n--- 1. the command ships, ungated ---")
    ok = True
    enabled = re.findall(r"--features\s+([\w/-]+)", build_sh)
    ok &= check("build.sh feature set", enabled and
                not [f for f in enabled if f in GATING_FEATURES],
                ", ".join(enabled) + "  (no gating feature)")
    ok &= check("test.rs 'bootwait' arm exists", arm_is_gated(test_rs, "bootwait") is not None,
                "present in the dispatch table")
    ok &= check("test.rs 'bootwait' arm is UNGATED", arm_is_gated(test_rs, "bootwait") is False,
                "no #[cfg(feature = ...)] above it")
    ok &= check("sibling 'fakek0' arm IS gated", arm_is_gated(test_rs, "fakek0") is True,
                "misc-test, so the gate idiom is in use in this file")
    ok &= check("sibling 'k0check' arm IS gated", arm_is_gated(test_rs, "k0check") is True,
                "hazardous-test")
    ok &= check("bootwait arm calls keystore.bootwait", 'keystore.bootwait(Some(false))' in test_rs
                and 'keystore.bootwait(Some(true))' in test_rs,
                "both enable and disable are exposed")

    print("\n--- 2. the console it is reachable from has no authentication ---")
    ok &= check("main.rs enables serial console injection",
                "usb.serial_console_input_injection();" in main_rs,
                "unconditional, at startup")
    ok &= check("upstream calls that API dangerous",
                "Inject serial input over USB to the debug console. Dangerous!" in usb_lib,
                "vendor's own doc comment in usb-bao1x")
    ok &= check("no credential check in the dispatch path",
                not re.search(r"password|passphrase|authenticat|unlock", console["src/cmds.rs"], re.I),
                "cmds.rs dispatch has no auth of any kind")

    print("\n--- 3. it reaches a hardware one-way counter ---")
    ok &= check("keystore client sends Opcode::Bootwait", "Opcode::Bootwait.to_usize()" in ks_lib,
                "Keystore::bootwait")
    ok &= check("keystore server calls set_bootwait", "store.set_bootwait(" in ks_srv,
                "server.rs Opcode::Bootwait")
    ok &= check("set_bootwait increments the counter",
                "inc_coded::<bao1x_api::BootWaitCoding>().unwrap()" in ks_store,
                "unwrap() on the increment result")
    m = re.search(r"encode_oneway!\s*\{\s*#\[offset\s*=\s*(\d+)\]\s*pub enum BootWaitCoding",
                  offsets, re.S)
    ok &= check("BootWaitCoding one-way counter offset", m is not None and m.group(1) == "80",
                "offset %s, in the block that also holds board type, alt boot and developer mode"
                % (m.group(1) if m else "?"))

    print("\n--- 4. the counter is finite, and the increment path is unmetered ---")
    ok &= check("wear-out is documented in the increment", "only good for 10k increments" in acram,
                "comment on the IncFail path in inc_coded()")
    m = re.search(r"ONEWAY_MAX_VALUE:\s*u32\s*=\s*([\d_]+)", acram)
    ok &= check("ONEWAY_MAX_VALUE", m is not None,
                (m.group(1) if m else "?") + "  ('set by the wear-out limit of the underlying RRAM')")
    m = re.search(r"ONEWAY_MAX_DELTA:\s*u32\s*=\s*([\d_]+)", acram)
    ok &= check("ONEWAY_MAX_DELTA", m is not None,
                (m.group(1) if m else "?") + " increments per boot attempt is the stated policy")
    ok &= check("no rate limit on the console path",
                not re.search(r"delta|rate.?limit|throttl", ks_store.split("pub fn set_bootwait")[-1],
                              re.I),
                "set_bootwait neither counts nor caps how often it is called")

    print("\n--- 5. what the counter controls ---")
    ok &= check("boot1 only boots when bootwait is Disable",
                "if boot_wait == BootWaitCoding::Disable && current_key.is_none() {" in boot1,
                "try_boot() is inside that branch")
    ok &= check("boot1 announces the bypass when Enable",
                'crate::println!("Boot bypassed because bootwait was enabled");' in boot1,
                "falls through to the bootloader REPL and USB updater instead")

    print()
    bad = [r[0] for r in results if not r[1]]
    if bad:
        print("NOT CONFIRMED: %d link(s) of the chain did not verify: %s" % (len(bad), ", ".join(bad)))
        return 1
    print("SOURCE-VERIFIED: every link of the chain holds at dc34-console %s / xous-core %s."
          % (CONSOLE_REF[:8], XOUS_REF[:8]))
    print("  An unauthenticated USB serial peer types 'test bootwait enable' once. Counter 80 flips to")
    print("  Enable, and boot1 stops calling try_boot(). The badge does not boot again, across power")
    print("  cycles, and the application console that could flip it back never runs.")
    print("  Repeating the command burns one increment of a wear-limited ReRAM counter each time.")
    print()
    print("  exploitable=false in the finding JSON: the exploiting line was NOT run against a badge in")
    print("  this audit. No DC34 hardware was available. See the advisory's Reproduction Steps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
