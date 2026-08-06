# Threat model for Baochip-1x SoC (tapeout-a1)

Silicon design (SystemVerilog/Verilog RTL) for the Baochip-1x, the security chip behind the DEF CON 34 badge. The artifact is a taped-out, unpatchable die: RTL flaws are permanent in shipped silicon and can only be mitigated (if at all) in firmware. Findings are hardware vulnerabilities, disclosed to the vendor (baochip / betrusted-io / bunnie) for firmware mitigation and future die revs.

## Attacker personas

1. **Non-secure on-chip master**: code running on a CPU/DMA master that sits on the non-secure side of the on-chip bus fabric (regular AHB/AXI), for example an application running under the OS on the VexRiscv core, or a peripheral DMA engine. Starts with: ability to issue bus reads/writes and to program the SCE (security co-processor) DMA descriptors from the non-secure port. Wants: to read secret key material out of the SCE, or to make the SCE operate on keys it should not have access to.
2. **Untrusted firmware image / peer over mailbox**: a lower-trust core or an unauthenticated image submitting work to a higher-trust core via the `mbox` mailbox. Wants: to drive the secure core into an unsafe state, corrupt its memory, or bypass the HMAC boot-auth (SCE) check.
3. **Physical / debug attacker**: JTAG/DFT/scan access. Wants: to read keys via scan chains, or to disable tamper sensors (`sec` mesh/sensorc). Out of primary scope for an RTL-only pass but noted where the RTL gates debug in secure states.

## Entry points

- **SCE DMA channels** (`crypto_top`: `sce.sv`, `scedma.sv`, `scedma_ac.sv`, `sce_memc.sv`): caller programs channel descriptors (segid, segaddr, segptr, rd/wr, transsize) from the bus. This is the richest weakly-validated-input-to-privileged-engine surface.
- **SCE register interface** (mode, key config, NVR access rules `nvracrules`): who can set `mode_sec`, load the access-rule override, trigger operations.
- **mbox** (`mbox.sv`, `mbox_client.v`): cross-core message passing; shared FIFO / doorbell.
- **crypto engines**: `crypto_aes`, `crypto_hash`, `crypto_pke`, `crypto_trng` (RNG health), `crypto_alu`.
- **sysctrl / ao / rrc**: system control, always-on domain, reset/clock control (security-state and lifecycle).
- **dft / rbist / scan**: test infrastructure gating in secure state.

## Trust boundaries

Deployment posture: NONE-IN-REPO (hardware; no network posture applies). The relevant boundaries are on-chip:

- **non-secure bus master -> SCE key storage**: the SCE holds key material (SEGID_LKEY/KEY/SKEY/AKEY/PKB) in an internal cryptoram; the per-segment access rules (`ACRULEs`, `scedma_ac`) are the boundary. A non-secure master must not read key segments.
- **`mode_sec` gates access control** (`sce.sv:370 acenable = mode_sec`): when the SCE is not in secure mode, `acenable=0` and `scedma_ac` grants ALL access (`chnlac='1`). Who controls `mode_sec` and can a non-secure caller clear it while keys are resident?
- **segid label vs actual segaddr**: `scedma_ac` decides access from the caller-supplied `segid`, and forwards the caller-supplied `segaddr` unchanged. If the memory controller honors `segaddr` independently of `segid`, the AC decision is decoupled from the access it authorizes (confused deputy).
- **NVR access-rule override**: `nvracrules[29]==0x5a` swaps the hardwired `ACRULEs` for fuse/register-supplied rules. Who can write `nvracrules`? A writable override is a full AC bypass.
- **lower-trust core -> secure core** across `mbox`.

## Sensitive assets (ranked)

1. SCE key material: local key, session key (SKEY), AES key (AKEY), PKE key buffer (PKB), secret (SCRT). Readout = full compromise.
2. HMAC boot-auth verdict (secure-boot bypass = arbitrary code as authenticated).
3. Security state / lifecycle (`mode_sec`, tamper sensors, debug gating).
4. TRNG output quality (predictable keys).

## Priority hunt

Short path from persona 1 (non-secure bus master) to asset 1 (key readout) through the SCE DMA access control: the segid/segaddr decoupling, the `mode_sec`->`acenable` gate, and the `nvracrules` override. This is the first walk.
