#!/usr/bin/env python3
# Author: Infinit3i
# Stage 1 BIO pipeline validator for the DC34 badge (finding C3).
# Loads a tiny BIO program over the unauthenticated `bio` console command and reads
# its FIFO3 output back with `bio rx`. Success = the sentinel 0x5A5 comes back.
#
# This RUNS CODE on the badge (recoverable by power-cycle). Close any screen/minicom
# on the port first, and stop ModemManager if the port is busy.
#
#   sudo python3 bio_run.py --port /dev/ttyACM0
#
# Requires: pyserial  (sudo apt install python3-serial)

import argparse, base64, struct, sys, time, zlib

CHUNK_DATA = 64
NUM_CHUNKS = 60          # 60 * 64 = 3840 = 0xf00 = BIO code memory
BIO_MEM    = NUM_CHUNKS * CHUNK_DATA

# --- Stage 1 program: push sentinel 0x5A5 to FIFO3 (x19), then spin ------------
# Hand-assembled RV32I. Special regs: x16..x19 = FIFO0..3; writing x19 pushes a
# word the host reads back with `bio rx`.
#   addi x1, x0, 0x5A5     ; x1 = sentinel            0x5A500093
#   (x15) addi x19, x1, 0  ; push x1 -> FIFO3         0x00008993   (repeated)
#   jal  x0, 0             ; spin forever at self     0x0000006F
SENTINEL = 0x5A5
PROGRAM_WORDS = [0x5A500093] + [0x00008993] * 15 + [0x0000006F]

def program_bytes():
    b = b"".join(struct.pack("<I", w) for w in PROGRAM_WORDS)
    return b + b"\x00" * (BIO_MEM - len(b))          # zero-pad to full code memory

def frame_chunk(index, data64):
    # wire = index(2, BE) || data(64) || crc32(index||data)(4, BE)   [see image.rs/bio.rs]
    head = struct.pack(">H", index) + data64
    crc  = zlib.crc32(head) & 0xffffffff
    return base64.b64encode(head + struct.pack(">I", crc)).decode()

def send(ser, line, wait=0.15):
    try:
        ser.write((line + "\r\n").encode())
        ser.flush()
    except Exception as e:
        raise SystemExit(
            f"[!] write blocked/timed out: {e}\n"
            "    The badge is not draining USB serial input (console wedged or not at prompt).\n"
            "    Power-cycle the badge, re-attach it in VirtualBox Devices->USB, confirm with\n"
            "    `screen /dev/ttyACM0 115200` (press Enter -> you should see the command list), then re-run.")
    time.sleep(wait)
    return ser.read(ser.in_waiting or 1).decode(errors="replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--baud", type=int, default=115200)   # ignored by CDC-ACM
    ap.add_argument("--delay", type=float, default=0.12)
    ap.add_argument("--rx", type=int, default=16)
    args = ap.parse_args()

    try:
        import serial
    except ImportError:
        sys.exit("pyserial missing: sudo apt install python3-serial")

    ser = serial.Serial(args.port, args.baud, timeout=0.3, write_timeout=3,
                        rtscts=False, dsrdtr=False)
    ser.dtr = True; ser.rts = True     # assert control lines like screen does
    time.sleep(0.3)
    ser.reset_input_buffer(); ser.reset_output_buffer()
    prog = program_bytes()
    print(f"[*] program {len([w for w in PROGRAM_WORDS])} instrs, padded to {len(prog)} bytes")

    print("[*] bio clear"); print("   ", send(ser, "bio clear").strip())
    for i in range(NUM_CHUNKS):
        data = prog[i*CHUNK_DATA:(i+1)*CHUNK_DATA].ljust(CHUNK_DATA, b"\x00")
        r = send(ser, "bio " + frame_chunk(i, data), wait=args.delay)
        if i % 10 == 0 or "ERR" in r:
            print(f"    chunk {i:2d}: {r.strip()!r}")
    # run trigger (if 'ready' does not start it, we learn that from an empty rx)
    print("[*] bio ready"); print("   ", send(ser, "bio ready").strip())

    print(f"[*] bio rx {args.rx} 2  (draining FIFO3)")
    out = send(ser, f"bio rx {args.rx} 2", wait=2.0)
    print(out)
    hexes = [tok for tok in out.replace(",", " ").split() if tok.lower().lstrip("0x").strip("[]") ]
    if f"{SENTINEL:x}" in out or "5a5" in out.lower():
        print(f"[+] PIPELINE OK: sentinel 0x{SENTINEL:x} came back. Load->run->readback works.")
    else:
        print("[!] no sentinel seen. Paste this whole output back; likely the run-trigger,")
        print("    the x19->FIFO3 mapping, or the clock needs adjusting (Stage 1 is exactly this check).")
    ser.close()

if __name__ == "__main__":
    main()
