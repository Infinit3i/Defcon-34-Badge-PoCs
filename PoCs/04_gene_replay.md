# PoC 04 — gene response replay (game cheat)

Finding V2, `dc34-vault/src/main.rs:695`, CWE-294. Source-verified. Needs two badges, or one badge plus a captured photo of another badge's response QR.

## Why it works

In the QR "gene breeding" exchange, a badge that successfully decrypts a gene response keeps its nonce, and re-entering the scan state does not generate a new one. So the same captured response ciphertext can be redeemed an unlimited number of times, with a fresh randomized outcome each time. The nonce is never retired, which is the whole point of a nonce.

## Steps (two badges)

1. Do a normal gene exchange: recipient badge shows its nonce QR, donor badge responds with a ciphertext QR under that nonce.
2. Photograph the donor's response QR.
3. On the recipient, after it breeds, press fire from Idle to re-enter GeneScan. It does not mint a new nonce.
4. Rescan the same photographed response QR.
5. It decrypts again and breeds again, a fresh randomized outcome. Repeat as many times as you like.

## Demo value

This is the "cheat the badge game" proof: farm outcomes from a single captured response. Capture video of the repeated redemptions from one QR for the disclosure.
