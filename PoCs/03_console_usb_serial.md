# PoC 03 — USB serial console: kernel state dump and persistent brick

Findings C2 (`dc34-console/src/cmds/test.rs:119`, CWE-497) and C1 (`test.rs:43`, CWE-306). Source-verified.

## Connect

Plug a USB cable into the badge and open the serial console:

```
ls /dev/ttyACM*            # find the device after plugging in
screen /dev/ttyACM0 115200 # or: minicom -D /dev/ttyACM0 -b 115200
```

Press Enter. The badge answers with its command list. No credentials, no pairing.

## C2 — kernel state dump (safe, info leak)

```
test proc          # kernel process table, one line per process
test freemem       # kernel RAM allocation map
test interrupts    # installed interrupt handler table
```

This is unauthenticated exposure of kernel internals to anyone with a cable. Useful recon for aiming a memory-corruption exploit (K1).

## Command discovery (do this)

Press Enter to print the full command list and record everything. The audit only enumerated two `test` subcommands. The full ungated command surface is where the next finding likely hides. Save the complete list.

## C1 — bootwait persistent brick — DANGER, read before running

```
test bootwait enable
```

Do not run this casually.

- It is persistent across power cycles. Afterwards boot1 prints `Boot bypassed because bootwait was enabled` and drops to the bootloader REPL instead of starting Xous: no display app, no lights, no FIDO2.
- Recovery requires reaching the boot1 REPL / USB updater and undoing it. It cannot be undone from the application.
- It writes a one-way counter in the same array as board-type / boot-select / devmode / OEM-mode (offsets 80-86). Consuming its endurance is not reversible by any means.

Only run this on a sacrificial badge, and confirm the boot1-REPL recovery path first. If you confirm it, capture the `Boot bypassed...` message. If you have one badge you care about, leave C1 source-verified.
