# Secure design notes for xous-core

Systemic changes that would have removed whole classes of the problems in `report.md`, rather than
patches for the two findings. Each is tied to the findings it would have prevented.

## 1. Make the IPC boundary a parsing boundary

Prevents findings 1 and 2, and every future instance of both.

Xous already treats process separation as a security property: the kernel owns the MMU, servers are
addressed by 128-bit ids, and connections are brokered. What it does not have is a place where bytes
crossing that boundary become values. `xous-ipc`'s `Buffer` is described in the vendor's own issue #93
as an implementation detail, and it is: 366 lines that every server reaches through, with no contract
about what a hostile sender may put in the page.

Give it one. A single `fn parse<T: CheckBytes>(msg: &MemoryMessage) -> Result<T, IpcError>` that
bounds the offset, validates the archive and returns an error, used by all 356 call sites, turns two
whole classes into a `Result` the server already has to handle. The alternative that is already
underway is `flatipc` (PRs #576, #582), which replaces the archived representation entirely; whichever
wins, the property to hold onto is that exactly one function is allowed to turn a message into a value.

## 2. Treat every field of a message as attacker input, including the ones documented as advisory

Prevents finding 2 directly, and the same defect in `valid` before anything starts reading it.

The maintainers already know `offset` and `valid` are untrusted: issue #93's comment says they "were
meant to be advisory and untrusted, but perhaps we should get stronger guarantees on what they do".
The gap is that "advisory" was implemented as "no guarantee", and the receiving side then used one of
them as a bound. `valid` is in the same position today and is only safe because nothing reads it, which
is not a property anyone maintains deliberately.

Two options, either of which closes it. Bound them in the kernel when the message is delivered, so no
receiver can see an `offset` past the mapped length, which is the one place the mapping's true size is
known for certain. Or bound them at the single parsing entry point from note 1, and make the raw
fields inaccessible to servers so nobody can reintroduce the pattern.

## 3. Never call an unchecked deserializer on data from another process

Prevents finding 1, and prevents it recurring the next time the serialization library changes.

The tree currently contains zero validated rkyv accesses and fourteen unchecked ones. That is not a
series of local decisions; it is the default that `into_buf`'s symmetry suggests, because the same
crate serializes and deserializes and it is easy to read the pair as a round trip. Over IPC it is not
a round trip: the two ends are different trust domains.

Make the unchecked call unavailable at this boundary. `rkyv::access` with `CheckBytes` derived on the
IPC types is the direct substitute, and the cost is paid once per message on a path that already
copies the whole structure into the receiver. If a specific hot path genuinely cannot afford
validation, it should be the exception with a comment naming the sender it trusts, rather than the
rule with no comment at all.

## 4. Decide what happens when a server dies, before something makes one die

Covers finding 2's impact and anything else that panics a server.

There is no supervisor: `grep -riE 'restart|respawn|supervis' kernel/src/` returns a unit test. Every
server is a single point of failure for whatever depends on it, and the name server is a single point
of failure for the whole system, because it is how any process reaches any other. A panic anywhere in
a message loop is therefore permanent until reboot.

Two directions, and they are complementary. Do not panic in a message loop: a server's dispatch should
return errors to callers rather than unwinding, and 234 of the 356 IPC parse sites currently
`.unwrap()`. And decide what the kernel does when a server process exits: today the answer is nothing,
which is defensible for an application and much less so for the name server.

## 5. Let a server say who may connect to it, not just how many

Reduces the persona for both findings from "any process" to "a process the system meant to allow".

`xous-names` brokers every connection, and its `max_conns` is a count. The code comment is explicit
that access control was moved into the servers themselves "thus allowing a permissive policy inside
xous-names", and the servers that matter most, PDDB and the keystore, register with `None`, meaning
unlimited. So the brokering step, the one place with a complete view of who is asking, does not use it.

The information needed is already there: the name server knows the requesting PID. An allow list per
registered name, or a capability handed to the processes that are supposed to have it, would make
"which processes can send PDDB a memory message" an answerable question. It does not fix findings 1 and
2, and it should not be sold as a fix for them, but it is the difference between a bug reachable by
anything on the device and a bug reachable by the two processes that were meant to talk to that server.

## 6. Put the unaudited-surface note somewhere a reader will find it

Issue #93 is the best security document this project has and it is an issue from 2021. It contains the
data-flow walkthrough, the permalinks, the two maintainers' disagreement about how strong the
guarantees should be, and an explicit request for review. Nothing in the repository points at it: there
is no `SECURITY.md`, no security section in the README, and the wiki does not mention it.

Moving that content into the Xous Book or a `SECURITY.md`, with the open questions kept as open
questions, would cost nothing and would put the project's own best statement of its threat model in
front of everyone who looks. The same file is the natural place for the reporting channel, which
currently has to be derived from `git log`.
