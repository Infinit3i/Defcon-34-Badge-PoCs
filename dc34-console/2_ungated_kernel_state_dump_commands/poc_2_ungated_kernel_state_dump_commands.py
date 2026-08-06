#!/usr/bin/env python3
# Author: Infinit3i
#
# dc34-console: "test proc", "test freemem" and "test interrupts" dump kernel state to the
# unauthenticated USB serial console.
#
# WHAT THIS SCRIPT IS. It walks the reachability chain across the two source trees the finding spans,
# reading the vendor's own bytes at the exact commits the shipped firmware is built from. It fetches
# them itself over https. The interesting half is the second one: the three commands write their
# output with log::info! rather than returning it, so the finding only stands if the log is mirrored
# to the USB serial port the attacker is holding. That link is checked here in upstream source.
#
# WHAT THIS SCRIPT IS NOT. It is not the exploit. The exploit is three lines typed into the badge's
# USB serial console and it needs the physical badge. See the advisory's Reproduction Steps.
#
#   python3 poc_2_ungated_kernel_state_dump_commands.py
#   python3 poc_2_ungated_kernel_state_dump_commands.py --console-src ./dc34-console --xous-src ./xous-core

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

CONSOLE_FILES = ["build.sh", "src/main.rs", "src/cmds/test.rs"]
XOUS_FILES = ["services/usb-bao1x/src/lib.rs", "services/usb-bao1x/src/main.rs",
              "services/xous-log/src/main.rs"]

GATING_FEATURES = ["hazardous-test", "misc-test", "qa-test", "owc-test", "factory-mismatch",
                   "factory-wipe", "wfi-stress-test"]

# command -> (PlatformSpecific syscall number, what it returns)
DUMPS = {"proc": (2, "process listing"),
         "freemem": (1, "RAM usage map"),
         "interrupts": (3, "interrupt handler table")}

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
    lines = src.splitlines()
    pat = re.compile(r'^\s*"%s"\s*=>' % re.escape(arm))
    for i, line in enumerate(lines):
        if pat.match(line):
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            return j >= 0 and lines[j].strip().startswith("#[cfg(")
    return None


def arm_body(src, arm):
    """Text of the match arm, up to the next arm at the same indent."""
    m = re.search(r'^(\s*)"%s"\s*=>\s*\{' % re.escape(arm), src, re.M)
    if not m:
        return ""
    start = m.end()
    depth = 1
    i = start
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    return src[start:i]


def main():
    ap = argparse.ArgumentParser(
        description="Verify that the three kernel-state dump commands ship ungated and that their "
                    "output is mirrored to the USB serial console.")
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
    usb_main = xous["services/usb-bao1x/src/main.rs"]
    log_main = xous["services/xous-log/src/main.rs"]

    print("\n--- 1. the three commands ship, ungated ---")
    ok = True
    enabled = re.findall(r"--features\s+([\w/-]+)", build_sh)
    ok &= check("build.sh feature set", enabled and
                not [f for f in enabled if f in GATING_FEATURES],
                ", ".join(enabled) + "  (no gating feature)")
    for cmd, (num, what) in sorted(DUMPS.items()):
        body = arm_body(test_rs, cmd)
        ok &= check("'%s' arm is UNGATED" % cmd, arm_is_gated(test_rs, cmd) is False,
                    "no #[cfg(feature = ...)] above it")
        ok &= check("'%s' issues PlatformSpecific(%d)" % (cmd, num),
                    re.search(r"SysCall::PlatformSpecific\(\s*%d\s*," % num, body) is not None,
                    "raw syscall, returns the %s" % what)
        ok &= check("'%s' prints every returned line" % cmd,
                    "for line in page_buf.as_str().lines()" in body and "log::info!" in body,
                    "log::info! per line")

    print("\n--- 2. the vendor already calls this surface non-public ---")
    ok &= check("source says so, in each arm",
                test_rs.count("this routine is not meant for public") == 3,
                '"this routine is not meant for public consumption", 3 occurrences')

    print("\n--- 3. the output reaches the unauthenticated USB peer ---")
    ok &= check("main.rs enables serial console injection",
                "usb.serial_console_input_injection();" in main_rs,
                "unconditional, at startup")
    ok &= check("that hook mirrors the LOG to USB, not just input",
                "TryHookUsbMirror" in usb_main,
                "SerialHookConsole asks the log server for a USB mirror")
    ok &= check("log server implements the USB mirror",
                "TryHookUsbMirror" in log_main and b"_Xous USB device driver_".decode() in log_main,
                "connects the log sink to the USB device driver")

    print()
    bad = [r[0] for r in results if not r[1]]
    if bad:
        print("NOT CONFIRMED: %d link(s) of the chain did not verify: %s" % (len(bad), ", ".join(bad)))
        return 1
    print("SOURCE-VERIFIED: every link of the chain holds at dc34-console %s / xous-core %s."
          % (CONSOLE_REF[:8], XOUS_REF[:8]))
    print("  An unauthenticated USB serial peer types 'test proc', 'test freemem' and 'test")
    print("  interrupts'. The kernel's process table, RAM allocation map and interrupt handler table")
    print("  are written to the log, and the log is mirrored to the same USB serial port.")
    print()
    print("  exploitable=false in the finding JSON: the commands were NOT run against a badge in this")
    print("  audit. No DC34 hardware was available. See the advisory's Reproduction Steps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
