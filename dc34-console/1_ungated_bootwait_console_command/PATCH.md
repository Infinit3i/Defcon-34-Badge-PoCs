# What to patch — ungated `test bootwait` persistent boot DoS

Finding C1. Companion to `advisory_1_ungated_bootwait_console_command.md`. Four fixes, ordered from the one-line stopgap to the systemic hardening. Fix 1 alone closes the reported issue; Fixes 2 to 4 close the class it belongs to and are worth doing together.

## Fix 1 (primary, one line) — gate the `bootwait` arm out of shipping builds

`dc34-console/src/cmds/test.rs:43`. The `"bootwait"` arm ships with no `#[cfg(feature = ...)]`, while its hazardous siblings in the same file (`fakek0`, `k0check`, `transmute`, `bt`) are gated. Give it the same treatment `k0check` already has:

```diff
+       #[cfg(feature = "hazardous-test")]
        "bootwait" => {
            match args.next() {
                Some("enable")  => { keystore.bootwait(Some(true));  ... }
                Some("disable") => { keystore.bootwait(Some(false)); ... }
                Some("check")   => { ... }
                _ => { ... }
            }
        }
```

`build.sh` enables `board-baosec`, `bao1x`, `oem-baosec-lite`, `utralib/bao1x` and none of the `*-test` features, so gating the arm removes it from every shipped build. This is the minimal fix and it is what the advisory's Solution line refers to.

## Fix 2 (defense in depth) — the USB serial console is an anonymous control interface

`dc34-console/src/main.rs:42` calls `usb.serial_console_input_injection()` unconditionally, and `src/cmds.rs:dispatch()` runs matched commands with no authentication. On this product USB is the only port and it is always open, so every console command is reachable by anyone who plugs in a cable. Gating one arm does not change that for the next state-changing command someone adds.

Require physical presence before any state-changing console command runs: a confirmation button press on the badge itself, checked in `dispatch()` (or a one-time unlock per attach). Read-only commands can stay open; anything that writes device state should not be drivable by a silent USB host.

## Fix 3 (harden the primitive) — `set_bootwait` is an unmetered toggle that panics on wear-out

`xous-core/services/keystore/src/platform/baosec/store.rs:373` (referenced repo, not dc34-console). Two problems in the keystore primitive, independent of who calls it:

- It increments the one-way counter with no accounting against the platform's own `ONEWAY_MAX_DELTA` (512 per boot attempt), and `enable`/`disable` give an unlimited toggle, so a caller can burn the counter's ~10k-increment endurance. Cap the increments per boot and reject once the delta budget is spent.
- It calls `.unwrap()` on the `inc_coded()` result. Once the ReRAM line stops advancing, `inc_coded()` returns `IncFail`, and the `unwrap()` panics the keystore server, which is a system service. Return the error to the caller and keep the server alive instead of unwrapping.

Fixing the primitive means no console arm, present or future, can wear or crash the keystore through it.

## Fix 4 (recoverability) — make a bricked badge recoverable by its owner

Today the only recovery is reaching the boot1 REPL or the USB updater, which an ordinary owner will not know to do. Consider a physical recovery gesture read by boot1 (for example, hold a button at power-on to force `try_boot()` regardless of the bootwait counter), so an owner can undo the state without external tooling. This limits impact even if a bootwait-style command is ever reachable again.

## Where each fix lives

- Fixes 1 and 2: `bunnie/dc34-console`.
- Fixes 3 and 4: `betrusted-io/xous-core` (`services/keystore`, `bao1x-boot/boot1`).
