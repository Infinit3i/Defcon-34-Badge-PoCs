# PoC 01 — QR header slice crash (vault DoS) — CONFIRMED on hardware

Finding V1, `dc34-vault/src/main.rs:624`, CWE-1284. Live-confirmed on a real DC34 badge.

## Payload

A QR code containing the two characters:

```
00
```

## Why it works

The vault does `data[..DC34_HEADER.len()] == DC34_HEADER` right after `base45::decode(qr)`, where `DC34_HEADER` is `[u8; 16]`. base45 `00` decodes to one byte, so `&data[..16]` on a 1-byte slice panics (`range end index 16 out of range for slice of length 1`). The length guard exists but sits two lines later, after the slice that already panicked. Any valid base45 that decodes to fewer than 16 bytes works; `00` is the smallest.

## Steps

The only thing the victim has to do is take a picture. On the badge the **center button is the camera shutter**, so scanning the QR is a single press.

1. Attacker side: generate the QR. Run the generator (`./gen_qr.sh`, writes `crash.png`), or by hand `qrencode -s 8 -o crash.png "00"`, or just type `00` into any phone QR-code app.
2. Show the QR to the victim badge: hold the phone screen or a printout in front of the badge camera.
3. **Press the badge's center button to take the picture.** That single capture is the scan.
4. The vault process dies immediately: the screen freezes, the LED pattern stops, the FIDO2 token stops answering over USB, and the password/TOTP menus are gone.
5. Power-cycle to recover. Stored passwords, TOTP records, and FIDO2 credentials all survive; it is a crash, not data loss.

## Evidence to capture for disclosure

Photo/video of the frozen badge, and if you can attach a debug build over the serial console, the panic line `range end index 16 out of range for slice of length 1`.
