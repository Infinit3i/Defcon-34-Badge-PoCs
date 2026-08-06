# Findings index for dc34-console bf64e03

Critical: 0 · High: 0 · Medium: 1 · Low: 1

| # | Finding | Severity | Component | Auth | Verification | Chain? | Status | Advisory |
|---|---------|----------|-----------|------|--------------|--------|--------|----------|
| 1 | Unauthenticated persistent boot denial through an ungated debug console command | Medium | `test bootwait`, USB serial console | none | source-verified | no | OPEN | [advisory](1_ungated_bootwait_console_command/advisory_1_ungated_bootwait_console_command.md) |
| 2 | Kernel process, memory and interrupt state disclosed to an unauthenticated serial console | Low | `test proc` / `freemem` / `interrupts` | none | source-verified | no | OPEN | [advisory](2_ungated_kernel_state_dump_commands/advisory_2_ungated_kernel_state_dump_commands.md) |

Both findings are source-verified, not live-confirmed. See "Coverage gaps" below for why, and what was
done instead.

## Scope

Target: `bunnie/dc34-console` at `bf64e03f019532cca5055fcdbe51977d572e3630` (2026-07-30), the console
application for the DC34 badge. 33 files, roughly 250 KB, Rust, Xous user application for the bao1x
RISC-V SoC. Audited as built by the repository's own `build.sh`, features `board-baosec`, `bao1x`,
`oem-baosec-lite`, `utralib/bao1x`.

Two dependencies are cited in the findings and were read at their pinned revisions: `bunnie/dc34-api`,
a path dependency that is also a public repository, and `betrusted-io/xous-core` at
`616bf65f6e379165464f50b1e79ec42aff77a683`, which every `bao1x-*`, `keystore`, `usb-bao1x`, `pddb` and
`modals` dependency is pinned to in `Cargo.toml`. Neither is the subject of this report; xous-core is
cited because the boot behaviour and the one-way counter semantics that give finding 1 its impact live
there, and because the log mirroring that gives finding 2 its reach lives there.

**Vendor security policy: none.** No `SECURITY.md` in the root or `.github/`, GitHub private
vulnerability reporting disabled, `has_wiki` false, no homepage on the repository record, and no
`security.txt` on `bunniestudios.com`, `www.bunniestudios.com` or `baochip.com`. All four locations
that the disclosure ladder asks for were checked. Disclosure channel resolution is in `README.md`.

**Deployment posture: none declared.** The pre-flight's `POSTURE.md` returned `NONE-IN-REPO`, and the
four off-repository locations above are empty as well, so no vendor statement caps the severity of an
unauthenticated finding here. The product's own `README.md` points users at `bunnie/dc34-image` for
uploading images to their badge, which drives the same USB serial console both findings use, so the
console is an end-user interface rather than a hidden one.

**Published advisories: none.** GitHub Security Advisories 0, NVD keyword search 0, OSV 0. The
pre-flight's `ADVISORY_MAP.md` was checked for the query-mismatch failure mode where a generic
repository name returns another product's CVEs; here the result is genuinely empty rather than
mis-keyed.

## Chain

No chain. The two findings share a root cause, an ungated `test` subcommand on an unauthenticated
console, but neither enables the other and combining them does not raise the severity of either.
Finding 2 is reconnaissance that would help an attack on some other part of the badge; finding 1 does
not need it.

## Where the findings came from

The advisory feed was empty, so there was no coverage map to hunt the blank cells of. What replaced it
was the vendor's own gating idiom. `src/cmds/test.rs` gates its dangerous commands one arm at a time
with cargo features, `misc-test`, `qa-test`, `hazardous-test`, `factory-mismatch` and `factory-wipe`,
which makes the file self-documenting about what its author considers dangerous. Listing the arms with
no gate and then asking what each one reaches produced both findings and the duplicate below. That
took one read of the file and one read of `build.sh`. Every other layer was walked afterwards and
returned nothing filable.

The expensive half was not finding the commands, it was establishing what they reach. For finding 1
that meant following `Keystore::bootwait` through the keystore server into ACRAM and then finding the
consumer in the bootloader, four files across a second repository. For finding 2 it meant answering a
question that would have sunk the finding if the answer had gone the other way: the commands write to
the log rather than returning a value, so the disclosure only exists if the log reaches the USB port.
It does, through `TryHookUsbMirror`, but nothing in this repository says so.

## Candidates investigated and ruled out

**`test k0 <base64>` and `test jig`: real, and already public. Not filed.** Both are ungated in the
same file and both are serious: `test k0` overwrites the 32 byte `k0` shared secret used as the
AES-256-GCM-SIV key for gene exchange, and `dc34-api`'s `save_k0()` resets badge type and tour progress
as a side effect; `test jig` sends opcode 1025 to `_Vault2_` to force factory test mode. An independent
researcher, GitHub user `aconite33`, described both in `bunnie/dc34-console` pull request #1, opened
2026-08-06 17:37 UTC and closed by its own author 21 minutes later with "Closing, will coordinate
disclosure separately". The pull request body is public and includes a working reproduction against
badge serial `C4T4BH`. That is prior public disclosure by another party, so these are not ours to file.
Finding 1's advisory cites the overlap, and notes that the fix proposed in that pull request gates
`k0` and `jig` while leaving `bootwait` reachable.

**BIO program sandbox escape through DMA: ruled out by design.** `bio` accepts an arbitrary 3840 byte
program over the console and runs it on a BIO core, which is bus-master capable. The escape would be a
DMA to arbitrary memory. It does not exist here: the upstream API states that "DMA filtering is on by
default with no windows allowed" (`libs/bao1x-api/src/bio.rs:92`), and `BioLoader` never calls
`setup_dma_windows`, so no window is ever opened. The program's I/O reach is further bounded to four
SAO pins by `ALLOWED_PINS = [21, 22, 30, 31]` and a resource grant, and `check_pins()` is applied both
when the pin list is set from the console and when it is read back from the PDDB at startup. Not
tested on hardware; the ruling rests on the API contract and the absence of the call.

**BIO clock control: bounded.** `bio clk <n>` writes an arbitrary `u32` to the PDDB, but `reload()`
accepts it only when `0 < f <= 350_000_000`, which is the default, so there is no overclock path.

**`image` and `bio` chunk upload: correctly checked.** Both decode base64, require exactly 70 bytes,
verify a CRC-32 over the index and data, and bounds-check the index against the slot count before
indexing. `to_bitmap()` and `to_code()` are exact fits for their destination buffers. No arithmetic
here overflows: 32 chunks of 16 words is 512 words, 60 chunks of 64 bytes is 0xf00.

**`bio pin`: correctly checked.** `check_pins()` retains only the four allowed pins, sorts and dedups,
so the fixed `[0u8; 4]` it is copied into cannot be overrun however many pin arguments are supplied.

**Xous servers registered with unlimited connections.** Both `_Bao console application_`
(`src/shell.rs:28`) and `_dc34_pwr_mgr_` (`src/power.rs:172`) pass `None` as the connection limit, so
any process may connect and inject console keypresses or power operations. Not filed: every process in
the shipped image is vendor code, and the only attacker-supplied code path on the badge is a BIO
program, which is not a Xous process and cannot send messages. The console's own source comments that
this is deliberate policy for a user application.

**`test wfi`, `test deep`, `test time`, `test hw`, `test temp`.** Ungated and unauthenticated, but they
sleep, read a sensor or ask the power manager for a state the user can already reach with the badge's
own buttons. No filable impact.

## Design notes rather than findings

Recorded in `SECURE_DESIGN.md` and summarised here so the list of what was seen is complete. Two
console-thread denial of service paths exist and neither is filed, because both are recoverable by a
power cycle and need the same physical access as the findings above: `bio rx <iters> <timeout>` parses
an unbounded `usize` iteration count with no cap and spins the console thread, and `src/shell.rs`
accumulates keypresses into a `String` that is only cleared on a newline, so a peer that sends no
newline grows it without limit.

## Coverage gaps

**No live lab, and no partial one either.** This is firmware for custom silicon. It builds only for
`riscv32imac-unknown-xous-elf` and runs only on DC34 badge hardware, which was not available. The
`hosted-baosec` feature would build a host-side emulation, but it would not help: both findings land in
hardware state that hosted mode stubs out. Finding 1's effect is one-way counter 80 in ACRAM, read by
the boot1 bootloader, and hosted mode has neither. Finding 2's reach depends on the USB device driver
mirroring the log, which hosted mode replaces. A hosted build would have shown the console accepting
the commands and nothing about what they do, at a cost of standing up the whole Xous hosted stack. It
was not attempted, and that is a deliberate trade rather than an omission.

What was done instead: each finding ships a script that fetches the vendor's own source at the two
pinned commits and checks every link of its reachability chain, 17 checks for finding 1 and 15 for
finding 2, all passing. Those scripts prove reachability in the firmware that ships. They do not prove
the runtime effect, and both finding JSONs carry `exploitable: false` for that reason. The advisories
say so in their Reproduction Steps rather than leaving a reader to infer it.

**No target-side recon.** `recon.sh` could not run against a target because there is no target, and it
is absent from this host in any case: the pre-flight recorded `recon_src` as
`failed:exception [Errno 2] No such file or directory: ZERO-DAY-REPORTS/tools/recon.sh`. So no nmap,
httpx, feroxbuster, katana, arjun or nuclei output exists for this program, and none would have applied
to a USB serial console on a RISC-V badge. The `SURFACE.md` that a normal run consumes does not exist
here; the route table was built by hand from `src/cmds.rs:125` and the `match` in `src/cmds/test.rs`.

**Most of the pre-flight's static analysis did not run.** `semgrep`, `trivy`, `trufflehog`,
`osv-scanner`, `checkov`, `hadolint`, `bandit`, `gosec` and `npm_audit` all recorded
`skipped: not installed` or `skipped: no manifest`. There is no Rust SAST in the pre-flight's tool set
at all, so nothing mechanical looked at the language this target is written in. The `db_sinks` stage
did run and reported 145 matches over the C, C++ and Python files. Every one of them is in
`src/bio/include/fp_q12.h`, `fp_q16.h`, `ws2812.h` or `src/bio/biosao/main.c`: fixed-point CORDIC
tables, an LED strip driver and a sample buffer, all of them build-time helper sources for producing
BIO binaries rather than code the console executes. The rule that fires most, CERT `ARR30-C` and
`CTR50-CPP` on unchecked array subscripts, is indexing those constant tables with loop counters. None
of it is reachable from console input, because a program uploaded through `bio` replaces this code
wholesale rather than calling into it.

**`dc34-vault` and the gene exchange protocol are out of scope.** The console sends four raw opcodes to
`_Vault2_` (1024, 1025, 1027) and the vault is where `k0` is actually used. That is a separate
repository and, at the time of this audit, a separate pre-flight adopted by another session.

## Recon

No sweep form ran. See "Coverage gaps" above: there is no live target for the target-side pass, and the
source-side pass had already been run by the pre-flight with most of its tools missing. The surface was
enumerated by reading all 33 files in the repository, which is the whole tree, plus the dependency
files each finding cites.
