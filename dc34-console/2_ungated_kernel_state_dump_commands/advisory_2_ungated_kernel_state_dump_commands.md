# Kernel process, memory and interrupt state disclosed to an unauthenticated serial console

**Product:** dc34-console, commit `bf64e03f019532cca5055fcdbe51977d572e3630` (2026-07-30), built by the repository's `build.sh`
**Affected versions:** every build produced by `build.sh` at this commit. The repository publishes no tags or releases, so the audited commit is the shipping state of `main`. The three commands are present in the default build; no feature flag is needed to reach them
**Severity:** Low
**CWE:** CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere
**Auth required:** none
**Attacker:** unauthenticated USB peer, anyone who can plug a cable into a badge they do not own
**Parameter:** `proc`, `freemem`, `interrupts` (`test` command argument, USB serial console line)
**Trigger flow:** USB serial console -> `cmds.rs` dispatch -> `test.rs` `"proc"`, `"freemem"` or `"interrupts"` arm -> `xous::rsyscall(SysCall::PlatformSpecific(N, page_buf, ...))` -> `log::info!` per returned line -> log server USB mirror -> the attacker's terminal
**Impact:** the kernel's process table, RAM allocation map and interrupt handler table are printed to whoever holds the USB cable
**Discovered:** 2026-08-06
**Status:** OPEN — unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com>, the committer of the affected file. The project publishes no security policy, has GitHub private vulnerability reporting disabled, and has no wiki, docs site or `security.txt`
**GHSA submission:** bunnie@kosagi.com, email only because GitHub private advisory reporting is disabled on this repository. Ecosystem: Other, `bunnie/dc34-console`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (2.4 Low); CWE-497; attach `poc_2_ungated_kernel_state_dump_commands.py`

## Summary

Three `test` subcommands issue raw `PlatformSpecific` syscalls that return kernel internals, and print
every line of the result to the log. `test proc` returns the process listing, `test freemem` the RAM
usage map, and `test interrupts` the interrupt handler table. All three are compiled into the shipping
build with no feature gate, and all three are reachable from the USB serial console that the
application opens to any host with no authentication. Because that same console hook also mirrors the
log to the USB port, the output lands in the attacker's terminal rather than staying on a debug UART.
The source comments in all three arms state that the routine "is not meant for public consumption".

## Severity

Low. Exploitation needs physical access to a USB port on the victim's badge and no credential, and the
result is information rather than control: no secret material is returned by these three syscalls, and
the badge continues to operate normally. What it gives an attacker is the running process set, where
memory is allocated and which handlers are installed, which is reconnaissance for an attack on some
other part of the badge rather than an attack in itself. It is filed rather than dropped because the
vendor's own comments mark the surface as non-public, the exposure is unauthenticated, and the fix is a
one-line attribute already used elsewhere in the same file.

The repository declares no deployment posture. There is no `SECURITY.md`, no docs site, no GitHub wiki
and no homepage on the repository record.

## Root Cause

`src/cmds/test.rs` gates its hazardous arms individually with cargo features, but the `"proc"`,
`"freemem"` and `"interrupts"` arms at lines 119, 131 and 143 carry no gate, so they are compiled into
the build that `build.sh` produces. Each arm allocates a page, hands its pointer to
`xous::rsyscall(xous::SysCall::PlatformSpecific(n, page_buf.as_ptr(), 0, 0, 0, 0, 0))` with `n` of 2, 1
and 3 respectively, and then iterates `page_buf.as_str().lines()` emitting each with `log::info!`.

The assumption that makes this look harmless is that log output is a developer channel. It is not on
this product: `src/main.rs:42` calls `usb.serial_console_input_injection()`, and the upstream handler
for that request does not merely hook input. It asks the log server for `TryHookUsbMirror`, which
connects the log sink to the USB device driver, so from that point everything written with `log::info!`
is delivered to the USB host along with command replies.

## Impact

An unauthenticated USB peer learns the badge's running process table with process identifiers, the
kernel's RAM allocation map, and the table of installed interrupt handlers. None of this is secret
material on its own. It maps the attack surface of the rest of the system for whoever is holding the
cable, and it does so on a device the owner is likely to be carrying and handing to strangers.

## Solution

Gate the `"proc"`, `"freemem"` and `"interrupts"` arms in `src/cmds/test.rs` with
`#[cfg(feature = "hazardous-test")]`, matching the treatment already given to `k0check` in the same
file, so that they are not compiled into builds produced by `build.sh`.

## Reproduction Steps

Environment: a DC34 badge running firmware built from `bunnie/dc34-console` at commit `bf64e03`,
default `build.sh` feature set (`board-baosec`, `bao1x`, `oem-baosec-lite`, `utralib/bao1x`), paired
with `bunnie/dc34-api` and `betrusted-io/xous-core` at revision `616bf65f`. Attacker host: any machine
with a USB port and a serial terminal. No credentials and no pairing are required.

1. Connect the badge to the host with a USB cable. It enumerates and presents a serial console. Open it
   with any terminal, for example `screen /dev/ttyACM0 115200`.
2. Press Enter. The badge answers with its command list, which includes `test`.
3. Type `test proc` and press Enter. The badge prints `Process listing:` followed by one line per
   running process.
4. Type `test freemem` and press Enter. The badge prints `RAM usage:` followed by the kernel's
   allocation map.
5. Type `test interrupts` and press Enter. The badge prints `Interrupt handlers:` followed by the
   installed handler table.

Note on this audit's verification: the walk from the console line to the syscalls, and the fact that
their output is mirrored to the same USB port rather than to a private debug UART, was verified in
upstream source at the two pinned commits by the script below, which fetches the vendor's own bytes and
checks every link. Steps 1 to 5 were not executed against a badge, because no DC34 hardware was
available to this audit. `exploitable` is therefore `false` in the accompanying finding JSON.

## Proof of Concept Code

`poc_2_ungated_kernel_state_dump_commands.py`

````python
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
````

Output at the audited commits:

````text
--- 1. the three commands ship, ungated ---
  [PASS] build.sh feature set                           board-baosec, bao1x, oem-baosec-lite, utralib/bao1x  (no gating feature)
  [PASS] 'freemem' arm is UNGATED                       no #[cfg(feature = ...)] above it
  [PASS] 'freemem' issues PlatformSpecific(1)           raw syscall, returns the RAM usage map
  [PASS] 'freemem' prints every returned line           log::info! per line
  [PASS] 'interrupts' arm is UNGATED                    no #[cfg(feature = ...)] above it
  [PASS] 'interrupts' issues PlatformSpecific(3)        raw syscall, returns the interrupt handler table
  [PASS] 'interrupts' prints every returned line        log::info! per line
  [PASS] 'proc' arm is UNGATED                          no #[cfg(feature = ...)] above it
  [PASS] 'proc' issues PlatformSpecific(2)              raw syscall, returns the process listing
  [PASS] 'proc' prints every returned line              log::info! per line

--- 2. the vendor already calls this surface non-public ---
  [PASS] source says so, in each arm                    "this routine is not meant for public consumption", 3 occurrences

--- 3. the output reaches the unauthenticated USB peer ---
  [PASS] main.rs enables serial console injection       unconditional, at startup
  [PASS] that hook mirrors the LOG to USB, not just input SerialHookConsole asks the log server for a USB mirror
  [PASS] log server implements the USB mirror           connects the log sink to the USB device driver

SOURCE-VERIFIED: every link of the chain holds at dc34-console bf64e03f / xous-core 616bf65f.
````

## Affected Files

dc34-console at `bf64e03`:

src/cmds/test.rs:119: the `"proc"` arm is ungated and returns the kernel process listing through `SysCall::PlatformSpecific(2, ...)`
src/cmds/test.rs:131: the `"freemem"` arm is ungated and returns the kernel RAM allocation map through `SysCall::PlatformSpecific(1, ...)`
src/cmds/test.rs:143: the `"interrupts"` arm is ungated and returns the interrupt handler table through `SysCall::PlatformSpecific(3, ...)`
src/main.rs:42: `usb.serial_console_input_injection()` opens the console and, through the upstream handler, mirrors the log to USB, which is what delivers this output to the attacker

Referenced, not owned by this repository, at xous-core `616bf65f`:

services/usb-bao1x/src/main.rs:654: `Opcode::SerialHookConsole` requests `TryHookUsbMirror` from the log server, so the hook is not input-only
services/xous-log/src/main.rs:250: the log server implements that mirror by connecting its sink to the USB device driver
