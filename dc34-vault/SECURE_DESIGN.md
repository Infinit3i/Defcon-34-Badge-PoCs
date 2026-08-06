# Secure design notes for dc34-vault

Systemic changes that would remove whole classes of the findings in `report.md`, rather than
patching each site. Ordered by how much they remove.

## 1. Treat every byte that crosses the optical boundary as hostile, and validate length once

Prevents findings 1 and 6, and would have prevented them together.

The QR handler currently validates length in three places, each written for the operation directly
below it, and each too late for the operation above it. `src/main.rs:626` guards the nonce
extraction but runs after the header comparison at `:624` has already sliced. `src/main.rs:668`
guards the ciphertext length but the plaintext that comes out of the decrypt at `:695` is then
sliced at `:699` and indexed at `:702` with no guard at all.

Parse the scanned buffer once, at the top of the handler, into a typed enum: a nonce message, a
gene response, a scheme string, or a rejection. Give each variant fixed-size fields, so that by the
time any handler runs the lengths are structural rather than assumed. Use total operations
throughout: `starts_with` instead of a slice comparison, `get(..n)` instead of `[..n]`, `get(i)`
instead of `[i]`. Rust makes the safe form as short as the unsafe one at every one of these sites.

The general rule this codebase breaks: **a producer-side invariant is not consumer-side
validation.** `get_padded_gamete` at `src/config.rs:337` really does always build sixteen bytes, and
the decrypt path really does rely on that, but the producer is on the other side of a boundary that
an attacker controls. An AEAD tag proves the sender held the key. It proves nothing about what they
chose to encrypt.

## 2. Make the nonce a single-use token with an expiry, enforced in one place

Prevents finding 2, and is the change the vendor's own specification already describes.

`nonce_mine` is currently a bare `Option<[u8; 12]>` that any code may read repeatedly and that only
one unrelated code path clears. The specification asks for two properties it does not have: consumed
on first successful use, and expired sixty seconds after issue.

Model it as a value that carries its own lifecycle rather than as a field plus a discipline. Store
the issue instant alongside the bytes, have the accessor return `None` past the deadline, and have
the accessor used by the decrypt path be a consuming one that takes the value out. Then no future
edit can reintroduce the replay by adding a state transition that forgets to call `clear_nonces()`,
which is exactly how the current defect arose: `clear_nonces` exists, is correct, and is simply
called from the one path that did not need it.

## 3. Bound every buffer that an external peer can grow

Prevents finding 3.

`VendorSession::data` grows by up to 7609 bytes per USB frame with no cap and no chunk count. The
reassembly loop should carry a maximum total size derived from the largest legitimate backup
payload, and a maximum chunk count, returning a session error past either.

Two related defects at the same site are worth fixing together. `self.index` is never assigned, so
the ordering check at `src/vendor_commands.rs:54` can never fire; assigning it makes the check real
and incidentally bounds duplicate chunks. And the reassembly runs in front of the `allow_host`
consent gate rather than behind it, so a feature that cannot complete still exposes its parser.
Refuse vendor data outright when `allow_host` is false, which in this build is always.

## 4. Give the Xous name server a connection limit to enforce

Reduces finding 5 and closes the general local-IPC surface.

`src/main.rs:104` registers the vault with `register_name(SERVER_NAME_VAULT2, None)`, and
`src/ux/icontray.rs:16` does the same for the icon tray. `None` is the maximum connection count, so
the name server has been asked not to restrict anything. The vault serves a known, small set of
peers. Naming that number turns the name server back into the access control it is meant to be, at
the cost of one argument.

This matters more than it looks on a device where every process is signed, because it is the
difference between a defence that holds if the signing assumption ever fails and one that does not
exist.

## 5. Stop terminating the process on malformed input

Reduces the blast radius of findings 1, 5 and 6, and of anything similar found later.

The vault is a single process that is simultaneously a FIDO2 authenticator, a password and TOTP
manager, and the badge user interface. Any panic anywhere in it takes all three down. The tree
reaches for `.unwrap()` and `.expect()` on values derived from untrusted input in many places:
nine `to_original()` call sites, `src/main.rs:612` on the memory message itself, and the
`ImageLoad` handler at `src/main.rs:998` to `:1004`, which chains `.expect()` on a PDDB get, an
`.expect()` on a read and two `.unwrap()` calls on a `bytemuck` cast.

A message that fails to parse should be dropped and logged, and the loop should continue. That is a
local change per site, but the design point is that the main event loop must be total: no input
should be able to end it. Consider also whether the credential store needs to share a process with
the badge game at all; splitting them would mean a defect in the QR handler could not take the
authenticator down.

## 6. Do not use compile-time constants from a public repository as secrets

Prevents finding 4.

`FACTORY_STANDALONE_STRING` at `src/ux.rs:29` is shaped like a secret and published like source.
Privileged mode transitions should require something an attendee's badge cannot present: a physical
button combination, detachment from the badge carrier, or a per-device value. A shared constant in
an open repository authenticates nobody.

## 7. Keep the dependency floor above the advisory line

Prevents finding 5 recurring.

`Cargo.toml` asks for `rkyv = "0.8.8"` and the lockfile resolved 0.8.15, which is below the 0.8.17
that closes the archive-validation advisories. Because rkyv sits on the inter-process boundary,
its floor should be raised deliberately rather than left to caret resolution. Running
`cargo audit` or `osv-scanner` in CI would have surfaced this: no such check exists in the
repository, and no CI workflow files were found in the tree at all.
