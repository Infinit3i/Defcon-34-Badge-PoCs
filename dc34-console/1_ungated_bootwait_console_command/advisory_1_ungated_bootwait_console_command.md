# Unauthenticated persistent boot denial through an ungated debug console command

**Product:** dc34-console, commit `bf64e03f019532cca5055fcdbe51977d572e3630` (2026-07-30), built by the repository's `build.sh`
**Affected versions:** every build produced by `build.sh` at this commit. The repository publishes no tags or releases, so the audited commit is the shipping state of `main`. The command is present in the default build; no feature flag is needed to reach it
**Severity:** Medium
**CWE:** CWE-306 Missing Authentication for Critical Function → CWE-400 Uncontrolled Resource Consumption
**Auth required:** none
**Attacker:** unauthenticated USB peer, anyone who can plug a cable into a badge they do not own
**Parameter:** `bootwait enable` (`test` command argument, USB serial console line)
**Trigger flow:** USB serial console -> `shell.rs` keypress accumulator -> `cmds.rs` dispatch -> `test.rs` `"bootwait"` arm -> `Keystore::bootwait(Some(true))` -> keystore `Opcode::Bootwait` -> `set_bootwait()` -> `inc_coded::<BootWaitCoding>()` on ACRAM one-way counter 80
**Impact:** the badge stops booting its operating system, permanently and across power cycles, and each repetition consumes an increment of a wear-limited hardware one-way counter that also carries secure boot state
**Discovered:** 2026-08-06
**Status:** OPEN — unpatched, coordinated disclosure
**Vendor:** bunnie <bunnie@kosagi.com>, the committer of the affected file. The project publishes no security policy, has GitHub private vulnerability reporting disabled, and has no wiki, docs site or `security.txt`
**GHSA submission:** bunnie@kosagi.com, email only because GitHub private advisory reporting is disabled on this repository. Ecosystem: Other, `bunnie/dc34-console`; CVSS 4.0 `CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N` (5.2 Medium); CWE-306, CWE-400; attach `poc_1_ungated_bootwait_console_command.py`

## Summary

The DC34 badge presents a serial console to any USB host it is attached to, with no authentication and
no pairing step. One command on that console, `test bootwait enable`, flips one-way counter 80 in the
SoC's ACRAM to `BootWaitCoding::Enable`. The boot1 bootloader reads that counter on every power-up and
only calls `try_boot()` when it decodes to `Disable`, so from that moment the badge stops loading its
operating system and halts in the bootloader instead. The application console that could set the
counter back is part of the operating system, so it never runs again. Repeating the command is not
rate limited or counted, and each invocation consumes one increment of a monotonic ReRAM counter whose
own source documents it as good for about ten thousand increments.

An independent researcher publicly described the neighbouring `test k0` and `test jig` commands in
`bunnie/dc34-console` pull request #1 on 2026-08-06, and closed it the same day saying disclosure would
be coordinated separately. That report covers the shared root cause, an unprotected `test` subcommand,
but it does not name `bootwait`, and the fix it proposes leaves `bootwait` reachable.

## Severity

Medium. Exploitation needs physical access to a USB port on the victim's badge for a few seconds and
no credential of any kind, and the product is a conference badge that is carried in public, handled by
strangers and charged from shared power. The effect is availability only, with no disclosure of secrets
and no code execution, which is why this is not filed higher: the calculator returns 5.2 Medium and the
dominant term is the physical attack vector. Two factors argue against filing it lower. The effect
persists across power cycles and cannot be undone from the application, so recovery requires the owner
to know that the boot1 REPL or the USB updater exists and how to reach it. Separately, the counter this
writes lives in the same one-way array as board type, alternate boot selection, developer mode and OEM
mode, at offsets 80 to 86, and consuming its endurance is not reversible by any means.

The repository declares no deployment posture. There is no `SECURITY.md`, no docs site, no GitHub wiki
and no homepage on the repository record, so there is no vendor statement that the console is expected
to be reached only by the badge's owner. If such a statement exists elsewhere it would not change this
finding, because the console is documented for end users: the repository's own `README.md` points
users at `bunnie/dc34-image` to upload images to their badge, which drives this same console.

## Root Cause

`src/cmds/test.rs` dispatches `test` subcommands from a single `match` in which the hazardous arms are
individually gated by cargo features. `fakek0` is behind `misc-test`, `k0check` behind
`hazardous-test`, `transmute` and `bt` behind `qa-test`. The `"bootwait"` arm at line 43 carries no
gate, so it is compiled into the build that `build.sh` produces, which enables only `board-baosec`,
`bao1x`, `oem-baosec-lite` and `utralib/bao1x`. The arm passes the user's word straight through:
`enable` calls `keystore.bootwait(Some(true))` and `disable` calls `keystore.bootwait(Some(false))`.

The console those commands arrive on is opened unconditionally by `src/main.rs:42`, which calls
`usb.serial_console_input_injection()`. The upstream API for that call is documented in xous-core as
"Inject serial input over USB to the debug console. Dangerous! This will also override or discard any
existing hooked listeners." Nothing on the path from the USB endpoint to the `match` performs any
authentication.

On the far side, the keystore's `set_bootwait()` implements the change by incrementing a hardware
one-way counter until its parity matches the requested state, with no cap on how often a caller may ask
and no accounting against the platform's own `ONEWAY_MAX_DELTA` of 512 increments per boot attempt.
The wrong assumption is that a `test` subcommand is a developer-facing surface; on this product it is
an anonymous network-equivalent interface, because USB is the badge's only port and it is open.

## Impact

A single command from an unauthenticated USB peer leaves the victim's badge unable to boot. On the next
and every subsequent power-up, boot1 prints "Boot bypassed because bootwait was enabled" and falls
through to the bootloader's own REPL and USB updater rather than starting Xous, so the badge shows none
of its normal behaviour: no display application, no light patterns, no gene exchange, no console. The
owner has no in-product way to recover, because every path that could clear the flag lives in the
operating system that no longer starts.

Issued repeatedly, the same command wears out one-way counter 80. `inc_coded()` reports `IncFail` once
the ReRAM line stops advancing, and `set_bootwait()` calls `.unwrap()` on that result, so a worn counter
turns every subsequent bootwait operation into a panic inside the keystore server, which is a system
service. The counter cannot be repaired or reset by design.

## Solution

Gate the `"bootwait"` arm in `src/cmds/test.rs` with `#[cfg(feature = "hazardous-test")]`, matching the
treatment already given to `k0check` in the same file, so it is not compiled into builds produced by
`build.sh`. If the command must remain in production builds, require a per-boot confirmation that only
the badge holder can give, such as a physical key press on the badge itself, before it reaches
`Keystore::bootwait`.

## Reproduction Steps

Environment: a DC34 badge running firmware built from `bunnie/dc34-console` at commit `bf64e03`,
default `build.sh` feature set (`board-baosec`, `bao1x`, `oem-baosec-lite`, `utralib/bao1x`), paired
with `bunnie/dc34-api` and `betrusted-io/xous-core` at revision `616bf65f`. Attacker host: any machine
with a USB port and a serial terminal. No credentials, no pairing and no prior contact with the badge
are required.

1. Power on the badge and confirm it boots normally: the display application comes up and the LEDs run
   their pattern.
2. Connect the badge to the host with a USB cable. The badge enumerates and presents a serial console.
   Open it with any terminal, for example `screen /dev/ttyACM0 115200`.
3. Press Enter. The badge answers with the console's command list, which includes `test`. This confirms
   the console is live and accepted the line without asking for anything.
4. Type `test bootwait check` and press Enter. The badge answers `bootwait is false`, the normal state.
5. Type `test bootwait enable` and press Enter. The badge answers `bootwait enabled`.
6. Disconnect the cable and power cycle the badge.
7. The badge does not boot. Instead of the display application it stops in the bootloader, which prints
   `Boot bypassed because bootwait was enabled` on its own console. Repeating the power cycle repeats
   the same result: the state is stored in the SoC's one-way counter array, not in RAM or in the
   filesystem.
8. To observe the counter consumption, alternate `test bootwait disable` and `test bootwait enable`.
   Each command advances one-way counter 80 by one, and the counter's endurance is finite.

To restore a badge in this state, reach the bootloader's own REPL over the same serial port and clear
the flag there, or reflash through the bootloader's USB updater.

Note on this audit's verification: the walk from the console line to the one-way counter, and from the
counter to boot1's decision not to boot, was verified in upstream source at the two pinned commits by
the script below, which fetches the vendor's own bytes and checks every link. Steps 1 to 8 were not
executed against a badge, because no DC34 hardware was available to this audit. `exploitable` is
therefore `false` in the accompanying finding JSON.

## Proof of Concept Code

`poc_1_ungated_bootwait_console_command.py`

````python
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
````

Output at the audited commits:

````text
--- 1. the command ships, ungated ---
  [PASS] build.sh feature set                           board-baosec, bao1x, oem-baosec-lite, utralib/bao1x  (no gating feature)
  [PASS] test.rs 'bootwait' arm exists                  present in the dispatch table
  [PASS] test.rs 'bootwait' arm is UNGATED              no #[cfg(feature = ...)] above it
  [PASS] sibling 'fakek0' arm IS gated                  misc-test, so the gate idiom is in use in this file
  [PASS] sibling 'k0check' arm IS gated                 hazardous-test
  [PASS] bootwait arm calls keystore.bootwait           both enable and disable are exposed

--- 2. the console it is reachable from has no authentication ---
  [PASS] main.rs enables serial console injection       unconditional, at startup
  [PASS] upstream calls that API dangerous              vendor's own doc comment in usb-bao1x
  [PASS] no credential check in the dispatch path       cmds.rs dispatch has no auth of any kind

--- 3. it reaches a hardware one-way counter ---
  [PASS] keystore client sends Opcode::Bootwait         Keystore::bootwait
  [PASS] keystore server calls set_bootwait             server.rs Opcode::Bootwait
  [PASS] set_bootwait increments the counter            unwrap() on the increment result
  [PASS] BootWaitCoding one-way counter offset          offset 80, in the block that also holds board type, alt boot and developer mode

--- 4. the counter is finite, and the increment path is unmetered ---
  [PASS] wear-out is documented in the increment        comment on the IncFail path in inc_coded()
  [PASS] ONEWAY_MAX_VALUE                               10_0000  ('set by the wear-out limit of the underlying RRAM')
  [PASS] ONEWAY_MAX_DELTA                               512 increments per boot attempt is the stated policy
  [PASS] no rate limit on the console path              set_bootwait neither counts nor caps how often it is called

--- 5. what the counter controls ---
  [PASS] boot1 only boots when bootwait is Disable      try_boot() is inside that branch
  [PASS] boot1 announces the bypass when Enable         falls through to the bootloader REPL and USB updater instead

SOURCE-VERIFIED: every link of the chain holds at dc34-console bf64e03f / xous-core 616bf65f.
````

## Affected Files

dc34-console at `bf64e03`:

src/cmds/test.rs:43: the `"bootwait"` match arm carries no `#[cfg(feature = ...)]`, so it ships in the default build while its hazardous siblings in the same file are gated
src/cmds/test.rs:52: `keystore.bootwait(Some(true))` is called on the unvalidated word `enable` taken from the console line
src/cmds/test.rs:60: `keystore.bootwait(Some(false))` on `disable`, giving the attacker an unlimited toggle rather than a single one-way move
src/main.rs:42: `usb.serial_console_input_injection()` opens the console to any USB host unconditionally, with no pairing or unlock
src/cmds.rs:115: `dispatch()` performs no authentication or authorization before running a matched command
build.sh:1: the shipping build enables none of the feature flags that gate the hazardous commands

Referenced, not owned by this repository, at xous-core `616bf65f`:

services/keystore/src/platform/baosec/store.rs:373: `set_bootwait()` increments the one-way counter in a loop with no cap and `unwrap()`s the result, so a worn counter panics the keystore server
libs/bao1x-hal/src/acram.rs:221: `inc_coded()` returns `IncFail` on wear-out, with the comment that the line is only good for 10k increments
bao1x-boot/boot1/src/main.rs:178: `try_boot()` runs only when the counter decodes to `Disable`, which is what makes this persistent
