# baochip-1x silicon — source-verified candidates (tapeout-a1, commit 1be12f4)

The SoC is a taped-out, unpatchable die. These are source-verified RTL weaknesses found by reading the SCE (security co-processor) crypto DMA, its access control, and the HMAC secure-boot path. None is live-confirmed: the crypto RTL runs only in the verilator SCE simulation (not installed here) or on physical silicon with a fault-injection rig. `exploitable = false` for all three. Full machine-readable detail in `candidates.json`; the threat model is in `THREAT_MODEL.md`.

## S1 — SCE DMA first-beat segment pointer not bounds-checked (strongest)

Files: `rtl/modules/crypto_top/rtl/sce_memc.sv:212`, `sce_dmachnl.sv:123/127`, `scedma_amba.sv:436`, `scedma_ac.sv`.

The SCE DMA authorizes a transfer purely on the caller-supplied `segid` (the `scedma_ac` rule table), while the crypto-RAM address it actually accesses is `SEGCFGS[segid].segaddr + caller_segptr`. `scedma_chnl` does bound the running pointer (`rpptr > segsize ? 0`), but it applies the check one cycle late: at `chnlstart` the pointer loads the caller's `rpptr_start` (any 12-bit value, the whole 4096-word RAM that holds every key segment), and the reset only fires the next cycle, after the first read beat has already issued a read at `segaddr(base) + rpptr_start`. So the first beat reads an arbitrary crypto-RAM offset, gated only by holding read permission on any one segment on the caller's channel. A master authorized only for a benign segment on the non-secure AXI channel could single-beat-read arbitrary crypto RAM, including the LKEY/KEY/SKEY/AKEY/PKB key segments. There is also an off-by-one: the bound is `> segsize`, not `>= segsize`, so one word past the segment is always reachable.

Blocker to confirm: cycle-accurate read-enable timing plus the fifo `~fo_empt` handshake on the AXI-readable segments (which are all fifos). Source reading argues both ways; the verilator SCE sim settles it. If confirmed this is a High-to-Critical hardware key-readout.

## S2 — fail-open HMAC secure-boot verify

File: `rtl/modules/crypto_top/rtl/combohasha.sv:480-490`.

The HMAC / secret-check verdict `chkprepass` initializes to 1 (pass) at check start and is only cleared to 0 when a compared word is nonzero, and only when `segwr` fires. `chkpass = chkdone && chkprepass`, and on pass `sce_ts` sets the trust bit `kid`. If the compare phase reaches `chkdone` without the compare words streaming through (a suppressed or zero-length transfer, or a glitch on the write-enable during `MFSM_LD_SECRET`), `chkprepass` stays 1 and the HMAC passes vacuously. A fail-safe secure-boot check must default to FAIL and set PASS only on positive full-width confirmation. This is the classic fault-injection target on a security chip (CWE-636, failing open).

## S3 — fuse / devmode security bypasses

Files: `rtl/modules/crypto_top/rtl/sce.sv:131-139`, `sce_sec.sv`.

`devmode_sce = devmode ? '1 : nvrcfg[28]`. A `devmode` input, or fuse byte `nvrcfg[28]`, sets five bypass bits: ahb-enable bypass, mode-quit-reset bypass (keys persist into non-secure mode, where `acenable = mode_sec = 0` disables all SCE DMA access control), mode-value-lock bypass, pke-ahb-lock bypass, alu-sec bypass. Separately, `nvrcfg[29] == 0x5a` swaps the hardwired access-rule table for NVR-supplied rules. Production-relevant only if fuses are mis-provisioned; otherwise a defense-in-depth note. Documented here so the vendor can confirm the provisioned fuse state.

## Note on the mailbox and scan

`mbox.sv:96-97` swaps `rx_err` / `tx_err` in the status SFR mapping (functional, not security). Scan mode (`cmsatpg`) disables the tamper mesh (`mesh.sv:62-66`), which is a lifecycle-lock concern if scan can be asserted after provisioning. Neither is filed; both are worth a line to the vendor.

## Not yet walked

mbox_client.v (the real FIFO/abort logic), crypto_trng (RNG health/bias), crypto_pke/aes internals, rrc/sysctrl/ao (lifecycle), and the soc_coresub multi-master trust trace that decides whether a genuinely less-trusted principal can reach the S1 DMA channel. That trace is what upgrades S1 from intra-domain robustness to cross-boundary key readout.
