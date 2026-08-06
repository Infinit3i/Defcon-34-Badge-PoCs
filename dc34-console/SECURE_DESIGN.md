# Secure design notes for dc34-console

Systemic changes that would have removed whole classes of the problems in `report.md`, rather than
patches for the two findings. Each is tied to the findings it would have prevented.

## 1. Make the production command set an allow list, not a subtraction

Prevents findings 1 and 2, and the already-public `test k0` and `test jig`.

`src/cmds/test.rs` decides what ships by attaching `#[cfg(feature = ...)]` to individual match arms.
That is a subtraction: everything is in the shipping build until someone remembers to take it out, and
the cost of forgetting is silent. Four arms have been forgotten so far, in one file, and three of them
reach security state. The gating idiom itself is correct and already in use in the same file, which is
what makes the omissions provable, but the default is the wrong way round.

Invert it. Put the production commands behind an explicit list and the rest behind a single feature:

```rust
#[cfg(not(feature = "dev-console"))]
const PRODUCTION_VERBS: &[&str] = &["echo", "ver", "image", "bio"];
```

and have `dispatch()` refuse anything not in that list unless `dev-console` is set. A new debug command
then ships disabled by default and no future author has to remember an attribute. A single
`#[cfg(feature = "hazardous-test")]` wrapping the whole `test` command would achieve most of the same
thing with a one-line change.

## 2. Treat the USB serial console as an anonymous interface, because that is what it is

Prevents findings 1 and 2 at the boundary rather than per command.

`src/main.rs:42` calls `usb.serial_console_input_injection()` unconditionally, and the upstream API
documents that call as dangerous. On a badge, USB is the only port and it is open to anything the badge
is plugged into, so the console has the reach of an unauthenticated network service while being written
with the assumptions of a developer serial port. Nothing in the dispatch path distinguishes the owner
from a stranger, and nothing can, because the two send identical bytes.

Two options, either of which closes the class. Require a local confirmation on the badge itself, a key
press, for any command that writes persistent or hardware state, so the holder of the badge has to
consent to what the holder of the cable asked for. Or split the console: leave `image` and `bio` open,
since those are the documented end-user features, and put everything that touches the keystore, the
PDDB secrets or the boot configuration behind the confirmation.

## 3. Never let an unauthenticated caller spend a finite hardware resource

Prevents the second half of finding 1's impact.

The one-way counters are ReRAM lines with a stated endurance: `inc_coded()` says the line "is only good
for 10k increments", `ONEWAY_MAX_VALUE` is 100000, and the platform defines `ONEWAY_MAX_DELTA` as 512
increments per boot attempt. That last constant is a policy that nothing enforces on this path.
`set_bootwait()` increments without counting, and `test bootwait` calls it as often as a serial peer
asks.

Enforce `ONEWAY_MAX_DELTA` where the increments happen, in the keystore, so that any caller,
application code included, is capped per boot. That is one counter in the keystore's own state and it
converts an unbounded consumption of unreplaceable hardware into a bounded one.

## 4. Do not `unwrap()` on a hardware failure path in a system service

Prevents the panic that finding 1's wear-out case reaches.

`set_bootwait()` calls `inc_coded::<BootWaitCoding>().unwrap()`, and `inc_coded()` returns `IncFail`
precisely when the ReRAM line has worn out, which is a foreseeable end state rather than an impossible
one. The caller above it in `server.rs` then has `_ => panic!("Couldn't set bootwait")` for the same
condition. The keystore is a system service; a panic there takes key management down for every process
on the badge. Return the error to the caller and let the console print it.

## 5. Decide where log output goes before deciding what to log

Prevents finding 2, and any future instance of it.

The three dump commands write to `log::info!` rather than returning a value, which reads as a developer
channel. It is not one: the same call that opens the console asks the log server for
`TryHookUsbMirror`, so everything logged is delivered to the USB host. That coupling is invisible from
this repository, which is why three commands whose own comments say they are "not meant for public
consumption" print to a stranger's terminal.

Either make the mirror explicit and off by default, so that a build has to opt into publishing its log
over USB, or keep a separate sink for anything a command produces on purpose and treat `log::` as
published output everywhere in this application.

## 6. Bound every loop and buffer that an anonymous peer feeds

Covers the two design notes in `report.md` that were not filed.

`bio rx <iters> <timeout>` parses an unbounded `usize` iteration count and spins the console thread;
`src/shell.rs` accumulates keypresses into a `String` that is only cleared on a newline, so a peer that
never sends one grows it without limit. Neither survives a power cycle and neither is filed, but both
are the same reflex: input from the console is treated as coming from a developer who will not abuse
it. Cap the iteration count at something a human would type, and cap the input line at a length no real
command reaches.
