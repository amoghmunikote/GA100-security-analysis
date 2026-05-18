# Phase-2 Validation & New Findings — GA100 / CMP 170HX

**Status**: Source-validated against the actual archive at
`d:\lapsus\integ\gpu_drv\stage_rel\` and the VBIOS dump
`d:\lapsus\cmp170hxBinary.BIN` (1 044 480 B = 0xFF000, PCI device
`0x10DE:0x20C2`, IFR magic `NVGI`, BIT/PCIR tables intact).

> **Errata vs original Phase-2 draft**: file size was reported as
> 1 048 848 B; the correct value is **1 044 480 B (0xFF000)**, matched
> exactly by the A100 reference VBIOS
> `NVIDIA.A100.40960.200214.BIN`. See
> `14_PHASE3_BINARY_REVERSE_ENGINEERING.md §3` for the side-by-side.

This document re-grades the eight Phase-1 vulnerability hypotheses
against actual source, then adds four new findings that were not in the
original analysis. Every claim has a `file:line` citation. Where the
original analysis was wrong, I say so explicitly.

---

## 1. Architectural model corrections

### 1.1 GA100 does not have an FBfalcon HBM2e training profile

Phase-1 referenced
[fbflcn_gddr_boot_time_training_ga100.c](integ/gpu_drv/stage_rel/uproc/fbflcn/src/fbflcn_gddr_boot_time_training_ga10x.c)
as a target. **That file does not exist in the tree.** The fbflcn build
configuration ([fbfalcon-config.cfg](integ/gpu_drv/stage_rel/uproc/fbflcn/config/fbfalcon-config.cfg))
defines profiles only for:

- `fbfalcon-v0101` (GV100, HBM2)
- `fbfalcon-tu10x-{gddr,hbm}` (TU10x)
- `fbfalcon-ga10x-gddr` (GA10x consumer GDDR6/6X)
- `fbfalcon-ad10x-gddr` (Ada GDDR)
- `fbfalcon-gh100-hbm` (Hopper HBM3)

There is **no `fbfalcon-ga100-hbm`** profile, even though
[g_fbfalconuc_ga100-hbm.h](integ/gpu_drv/stage_rel/drivers/resman/kernel/inc/fbflcn/bin/g_fbfalconuc_ga100-hbm.h)
is shipped as a prebuilt blob. The build recipe for that blob is not in
this snapshot.

Consequence: on GA100, **HBM2e signal-integrity training is
predominantly performed by the VBIOS DEVINIT scripted sequencer
executing on PMU**, not by a standalone signed FBfalcon ucode the way
Hopper does. The runtime HBM site temperature path is the only
ampere-specific HBM logic present in PMU
([pmu_fbhbm2ga100.c](integ/gpu_drv/stage_rel/pmu_sw/prod_app/fb/ampere/pmu_fbhbm2ga100.c)).

This **invalidates Phase-1 findings #4 and #6** (HBM training state
unverified, VREF control unchecked) *as written*. Whatever training is
actually happening on GA100 happens inside DEVINIT scripted in the
VBIOS, not in a Falcon ucode in this tree. The correct re-frame is
"VBIOS DEVINIT script integrity," which is a different attack surface.

### 1.2 Falcon ISA, not "x86-like"

`01_SECURE_BOOT_CHAIN.md:86` calls Falcon "x86-like." That is wrong.
Falcon is a custom 32-bit Harvard-architecture core with a Renesas-like
ISA. The disassembly conventions you'll need are documented in NVIDIA's
"Envytools" reverse-engineering project. Treating it as x86 will mislead
binary analysis.

### 1.3 The Booter / ACR layering on GA100

The real boot chain for the GA100 GSP-RM datapath is:

```
   BootROM (immutable, in silicon)
     │ verifies HS signature of:
     ▼
   Booter-Load (Falcon HS)                  ← uproc/booter
     │ resets and brings up GSP, then runs:
     ▼
   GSP-RM RISC-V (LIBOS, runs at LEVEL0)    ← uproc/gsp + drivers/resman
     │
   AHESASC + ASB (SEC2 HS)                  ← uproc/acr/src/ahesasc, asb
     │ verifies LS images and locks WPR
     ▼
   LS Falcons (PMU, FECS, GPCCS, FBFLCN)
```

On the LS RISC-V detour (Hopper+, only "debug-only and temporary" on
GA100) the chain instead bounces through
[acr_riscv_ls_ga100.c](integ/gpu_drv/stage_rel/uproc/acr/src/asb/ampere/acr_riscv_ls_ga100.c)
— see §3.1 for the ITCM bootstub gadget.

---

## 2. Phase-1 vulnerabilities — validation verdicts

| # | Phase-1 claim | Verdict | Notes |
|---|---|---|---|
| 1 | SMC instance not validated (`acr_dma_ga100.c`) | **PARTIALLY VALIDATED** — reframe required | §2.1 |
| 2 | Dep-map array bounds (`_acrlibCheckDependency_v2`) | **LATENT, not directly reachable** | §2.2 |
| 3 | AES key source unknown | **RESOLVED** — fully traced | §2.3 |
| 4 | Training state unverified (`fbflcn_gddr_boot_time_training_ga100.c`) | **INVALID file path** — see §1.1 | — |
| 5 | LSF offset validation missing (`lsbOffset` setter) | **PARTIALLY VALIDATED** — setter is unchecked but caller path matters | §2.4 |
| 6 | VREF control unchecked | **INVALID for GA100** | training is in DEVINIT, not Falcon |
| 7 | Integer overflow in `i*2` depMap iteration | **NOT EXPLOITABLE as described** | §2.2 — depMap is fixed-size, `i*2*4` < 88 always once depMapCount is signed |
| 8 | Version rollback via `binVersion` | **LATENT** — see §2.5 | controlled by anti-rollback fuse, not by `binVersion` field alone |

### 2.1 FECS DMA / SMC instance selection

Real code, [acr_dma_ga100.c:32-72](integ/gpu_drv/stage_rel/uproc/acr/src/acrsec2shared/ampere/acr_dma_ga100.c#L32-L72):

```c
regFecsArbWpr = NV_GET_PGRAPH_SMC_REG(NV_PGRAPH_PRI_FECS_ARB_WPR,
                                      pFlcnCfg->falconInstance);
```

And [acr_register_access_ga100.c:51](integ/gpu_drv/stage_rel/uproc/acr/src/acrsec2shared/ampere/acr_register_access_ga100.c#L51):

```c
#define SMC_LEGACY_UNICAST_ADDR(addr, instance) \
        (addr + (NV_GPC_PRI_STRIDE * instance))
```

What's actually true:

- `falconInstance` is not "attacker-controlled" in any path I traced
  inside ACR. Every caller passes either `LSF_FALCON_INSTANCE_DEFAULT_0`
  (a constant) or a small loop index. There is no LS-data-controlled
  path into `falconInstance`.
- The bug 2565457 comment ("vulnerable to attacks") refers to a
  **different** vulnerability: NVIDIA chose to bypass the
  `NV_PGRAPH_PRI_FECS_*_SMC_INFO` priv-aperture entirely and use the
  legacy unicast aperture, *because the SMC_INFO aperture itself was
  attackable*. So the WAR is a defense; the original threat is in HW.
- The remaining risk is therefore not "ACR computes a bad MMIO address"
  but: **if any non-ACR HS or LS path uses `SMC_INFO` instead of the
  legacy aperture, those paths inherit bug 2565457**.

Recommended next step: grep every consumer of `NV_PGRAPH_PRI_*SMC_INFO*`
under `uproc/` and `pmu_sw/` and verify all reads/writes go via legacy
aperture. The decode-trap WAR
([booter_war_functions_ga100_only.c:38-66](integ/gpu_drv/stage_rel/uproc/booter/src/common/ampere/booter_war_functions_ga100_only.c#L38-L66))
isolates **one** specific register (`NV_PLTCG_LTC*_LTS*_TSTG_CFG_2`) to
FECS only — bug 2823165 — but it doesn't cover the whole SMC_INFO
aperture.

### 2.2 Dep-map OOB read

[acr_wpr_ctrl_ga10x.c:606-620](integ/gpu_drv/stage_rel/uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c#L606-L620):

```c
for (i = 0; i < pUcodeDescV2->depMapCount; i++) {
    depfalconId = ((NvU32*)pUcodeDescV2->depMap)[i*2];
    expVer      = ((NvU32*)pUcodeDescV2->depMap)[(i*2)+1];
    if ((pBinVersions[depfalconId] < expVer) &&
        (pBinVersions[depfalconId] != LSF_FALCON_BIN_VERSION_INVALID))
        return ACR_ERROR_REVOCATION_CHECK_FAIL;
}
```

`depMap[]` has fixed size `LSF_FALCON_DEPMAP_SIZE * 8 = 88` bytes
([rmlsfm.h:164,186](integ/gpu_drv/stage_rel/drivers/resman/arch/nvalloc/common/inc/rmlsfm.h#L164));
`pBinVersions` is a stack array of `LSF_FALCON_ID_END = 21` `NvU32`s
([acr_verify_ls_signature_ga10x.c:407](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_verify_ls_signature_ga10x.c#L407)).

If `depMapCount > 11`, the loop walks off `depMap[]` into adjacent
struct fields (`depMapCount`, `lsUcodeVersion`, `lsUcodeId`,
`bUcodeLsEncrypted`, `lsEncAlgoType`, `lsEncAlgoVer`, `lsEncIV[16]`,
`rsvd[36]`) and then off the descriptor entirely. The `depfalconId`
value harvested is then used to index `pBinVersions[]` with **no bounds
check**.

**But:** the descriptor is signature-covered — the SHA hash that RSA-3K
verifies is over `binary || (falconId, ucodeVer, ucodeId) ||
depMap[depMapCount*8 bytes]`
([acr_signature_manager_ga10x.c:445-547](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_signature_manager_ga10x.c#L445-L547)).
So an attacker without the NVIDIA RSA-3K private key cannot independently
choose `depMapCount` or `depMap[]`.

Reachability scenarios:
- **Attacker without signing key** → unreachable. The descriptor
  modifications break the SHA before `_acrlibCheckDependency_v2` runs.
- **Attacker with a signed-but-buggy ucode that happens to ship with
  `depMapCount > 11`** → real OOB, reads from stack. NVIDIA's signing
  pipeline is the only thing preventing that. There is no defensive
  check in this function.
- **Attacker who can fault-inject between SHA verify and
  `_acrlibCheckDependency_v2`** → exploitable. Both reads come from DMEM
  in the same ACR run, so the race window is tiny but non-zero.

Phase-1 score "CRITICAL / Information disclosure" was overstated for the
software-attack threat model. It is real but **gated on signing-pipeline
discipline or fault injection**.

The "integer overflow in `i*2`" Phase-1 finding (#7) is **not real**:
`i*2` is in `NvU32`; the controlling `depMapCount` itself is `NvU32`;
the only way to overflow is `depMapCount > 0x80000000`, which means the
loop would have already destroyed the world via the `depfalconId`
indirection long before the multiplication wrapped.

### 2.3 AES key source — **CORRECTION** (Phase-3 binary RE revealed this section was wrong)

> **Errata**: This subsection originally described GA10x source file
> `acr_decrypt_ls_ucode_ga10x.c`. The prod GA100 AHESASC binary does
> **not** include any of those `_GA10X` functions; it uses the
> Turing-era AES-DM signature path from
> `acr_verify_ls_signature_tu10x.c`. The correct, binary-validated
> description is in
> `14_PHASE3_BINARY_REVERSE_ENGINEERING.md §3a`.
>
> Key corrections:
> - SCP slot used on GA100 is **43** (not 31)
> - GA100 uses **AES-DM signatures**, not RSA-3K/SHA-256 (PKC) or LS encryption
> - GA100 LS ucodes ship in **cleartext** — no LS encryption is performed
> - The `bUcodeLsEncrypted` flag in the LSF descriptor is always `0` on GA100
>
> The text below describes the **GA10x+** path, not GA100. Read it as
> "what GA10x and later do," not "what CMP 170HX does."


[acr_decrypt_ls_ucode_ga10x.c:39,56-59,287-364](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga10x.c#L39):

```c
#define ACR_LS_ENCRYPT_KEY_INDEX_PROD       (31)   // SCP secret slot
#define ACR_LS_ENCRYPT_KEY_INDEX_DEBUG      (0)

NvU8 g_lsEncKdfSalt[16] = {
    0xB6,0xC2,0x31,0xE9,0x03,0xB2,0x77,0xD7,
    0x0E,0x32,0xA0,0x69,0x8F,0x4E,0x80,0x62 };

// Derived key = AES-ECB((g_lsEncKdfSalt XOR falconID), masterKey)
((NvU32*)g_tmpSaltBuffer)[0] ^= falconID;
falc_scp_secret(g_bIsDebug ? 0 : 31, SCP_R2);
falc_scp_key(SCP_R2);
falc_scp_encrypt(SCP_R1, SCP_R3);
falc_scp_rkey10(SCP_R3, SCP_R4);
```

Findings:

1. **Key is per-Falcon-class, not per-device.** `falconID` is XORed
   into only the first 4 bytes of the salt; the master key is SCP
   secret slot 31 (PROD). Slot 31 is fused at silicon level and the
   same value across all production GA100/CMP170HX silicon.
2. **Salt is hardcoded and public** (shown above).
3. **One-time extraction of SCP slot 31 trivially decrypts all LS
   firmware** for the entire CMP/A100 fleet for every Falcon class —
   the only per-image variation is the IV from
   `pUcodeDescV2->lsEncIV[]`, which is in the descriptor in cleartext.
4. SCP slot 31 is only readable while running in HS mode and is wiped
   from registers at exit ([:512-525](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga10x.c#L512-L525)).
   So extracting it requires an HS-mode RCE primitive (e.g. via the
   ITCM bootstub gadget, §3.1) or SCA / fault injection on the SCP unit.
5. **Confidentiality is therefore primarily silicon-mediated**, not
   cryptographic — once any HS bug exists, encryption gives nothing.

Phase-1 finding #3 graded "key derivation undocumented" — this is now
fully documented above.

### 2.4 LSF offset validation — partially valid

[acr_wpr_ctrl_ga10x.c:432-434](integ/gpu_drv/stage_rel/uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c#L432-L434):

```c
case LSF_WPR_HEADER_COMMAND_SET_LSB_OFFSET:
    pWprHeaderV2->lsbOffset = *(NvU32 * )pIoBuffer;
```

This is a pure structure setter with no validation. It writes into a
DMEM copy of the WPR header wrapper. The interesting question is
**who calls SET_LSB_OFFSET and where does the value come from**.

For the AHESASC path the WPR header is read from FB (driver-built,
pre-lock) into DMEM by `acrReadAllWprHeaderWrappers_HAL`. The `lsbOffset`
is harvested via the GET path and then used to compute the address from
which the LSB header is fetched. There is also a sanity check
[`acrSanityCheckBlData_HAL`](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_verify_ls_signature_ga10x.c#L514)
that validates the `blDataOffset/blDataSize`. The `ucodeOffset` /
`ucodeSize` get an overflow check at
[acr_sub_wpr_ga10x.c:181-185](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_sub_wpr_ga10x.c#L181-L185).

What is **not** checked:

- `lsbOffset` itself is never bounds-checked against the WPR region
  size. A driver that asks ACR to point at an `lsbOffset` outside WPR
  (or wrapping past 0xFFFFFFFF) is constrained only by the subsequent
  signature verification: ACR will try to load an LSB header from
  whatever location the driver pointed at, then attempt to verify the
  pointed-to binary. The signature check eventually fails, but only
  *after* ACR has DMA-read 192 bytes of attacker-chosen FB region into
  DMEM as a `LSF_LSB_HEADER_V2`. That's a controlled-source DMEM write
  primitive with no validation on source address before the read.
- `monitorCodeOffset`, `monitorDataOffset`, `manifestOffset`,
  `hsOvlSigBlobOffset` are all read out of the LSB header
  ([acr_wpr_ctrl_ga10x.c:265-307](integ/gpu_drv/stage_rel/uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c#L265-L307))
  and consumed by callers without bounds checks at the GET site itself.
  The hsOvlSigBlob path eventually scrubs the region
  ([acr_verify_ls_signature_ga10x.c:531](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_verify_ls_signature_ga10x.c#L531))
  with attacker-supplied offset/size — a **DMA-write-with-zero
  primitive into any address driver can express**, gated only by HW WPR
  range registers, *before* the LSB is signature-validated.

Phase-1 finding #5 ("OOB firmware access / signature bypass") is real
in spirit but the actual primitive is more nuanced: it is a *pre-verify
DMA scribble* against attacker-supplied offsets, bounded by HW WPR
range. Worth following up.

### 2.5 Version rollback (`binVersion`)

Phase-1 #8 is best understood as a misunderstanding. The `binVersion`
in the WPR header is just a numeric tag of which build is loaded — it
does not itself defeat anti-rollback. The anti-rollback mechanism is
the FPF (Field-Programmable Fuse) `NV_FUSE_OPT_FPF_UCODE_*_HS_REV`
fuses, e.g.
[booter_sanity_checks_ga100_and_later.c:25-49](integ/gpu_drv/stage_rel/uproc/booter/src/common/ampere/booter_sanity_checks_ga100_and_later.c#L25-L49):

```c
NvU32 fpfFuse = BOOTER_REG_RD32(BAR0, NV_FUSE_OPT_FPF_UCODE_BOOTER_HS_REV);
fpfFuse = DRF_VAL(_FUSE, _OPT_FPF_UCODE_BOOTER_HS_REV, _DATA, fpfFuse);
while (fpfFuse != 0) { count++; fpfFuse >>= 1; }
*pUcodeFpfFuseVersion = count;
```

Each silicon increment of the booter HS rev burns one more fuse bit
and the booter compares its `BOOTER_GA100_UCODE_BUILD_VERSION` against
the fuse-derived count. So "load vulnerable old firmware" requires
either (a) a build that never burned the fuse, or (b) an entirely fresh
chip on which fuses haven't been advanced. The `binVersion` LSF field
is a labelling convenience, not the rollback gate. Mark Phase-1 #8 as
"correctly identifies a missing setter check, but not a defeated
anti-rollback."

---

## 3. New findings (not in Phase-1)

### 3.1 [CRITICAL] GA100 RISC-V ITCM bootstub gadget

[acr_riscv_ls_ga100.c:27-163](integ/gpu_drv/stage_rel/uproc/acr/src/asb/ampere/acr_riscv_ls_ga100.c#L27-L163)

```c
/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *   This function writes a raw machine-code stub to the target core's ITCM.
 *   ... should not be prod-signed unless prior approval is given by HS code
 *   signers. ...
 *   This hack was used to minimize the overhead in getting a working RISC-V LS
 *   implementation ready for GA100. It will be removed for GA10X+.
 * WARNING WARNING ... */
```

The function constructs a 10-instruction RISC-V stub in DMEM and DMA's
it into the GSP/PMU/SEC2 RISC-V's ITCM. The stub then `csrw`s
`UACCESSATTR`, `MSPM`, and `MRSP` to **promote the target to LEVEL2
(LSMODE) for both M-mode and U-mode external accesses**, and finally
`jalr`s to a `bootvec` value derived from `wprAddress`:

```
NvU64 bootvec = NV_RISCV_AMAP_FBGPA_START + wprAddress;
```

Why this matters:

1. The stub itself is **not in the signed FW image**; it is emitted by
   the HS-signed ACR ucode at runtime. Its correctness is guaranteed
   only by `acr_riscv_ls_ga100.c` being unmodifiable.
2. The CSR writes (`MSPM` LEVEL0|LEVEL2 enable, `MRSP` LEVEL2) raise
   the RISC-V core's effective external priv level above its natural
   LS configuration — i.e. the stub is the privilege-escalation
   primitive.
3. `wprAddress` is computed by the AHESASC caller from
   `pLsbHeader->ucodeOffset` (post-signature-verify). If any LSB-offset
   tampering primitive (§2.4) can survive verification, this is the
   direct hand-off to "RISC-V starts execution at attacker-controlled
   FB address with LSMODE_LEVEL2 priv."
4. The NVIDIA author *explicitly* requested HS-signer approval before
   prod-signing this code. The prebuilt blob
   [g_acruc_ga100_asb_prod.h](integ/gpu_drv/stage_rel/drivers/resman/kernel/inc/acr/bin/gsp/ga100/asb/g_acruc_ga100_asb_prod.h)
   exists and is prod-signed, so the warning was either followed by HS
   review or ignored. Either way the gadget is in production
   firmware on every CMP 170HX.
5. The same comment notes "This hack was used to minimize the overhead
   in getting a working RISC-V LS implementation ready for GA100. It
   will be removed for GA10X+." Confirmation that GA10X uses a
   different — presumably safer — RISC-V boot path.

This is the single most concerning gadget in the GA100 ACR codebase.

### 3.2 [CRITICAL] GSP-RM DMEM left at READ_L0_WRITE_L0

[booter_boot_gsprm_tu10x_ga100.c:94](integ/gpu_drv/stage_rel/uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c#L94)

```c
BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK,
                BOOTER_PLMASK_READ_L0_WRITE_L0);
                // TODO suppal/derekw: TASK_RM fails to come up if this is WRITE_L3
```

`BOOTER_PLMASK_READ_L0_WRITE_L0 = 0xFFFFFFFF`
([booter.h:91](integ/gpu_drv/stage_rel/uproc/booter/inc/booter.h#L91)).

GSP DMEM is set fully open after the Booter hands control to GSP-RM.
That means:

- The driver (PL0) can `mov` GSP DMEM via BAR0 without going through
  the RPC ring.
- A compromised lower-priv Falcon or any source able to issue priv
  level 0 BAR0 writes can overwrite GSP-RM stacks, heaps, and RPC
  buffers in-place.
- GSP-RM is RISC-V running under LIBOS at "LEVEL0" (no LSMODE) per
  comments at lines 114-118, which means it's not isolated by LSMODE
  either.

Combined with line 96-98 setting `EXE`, `IRQTMR`, `MTHDCTX` PLMs also
to `WRITE_L0`, this is **the documented end of the isolation between
the driver and the GSP-RM control processor on GA100**. The "TODO"
indicates this was a known regression that blocked TASK_RM bring-up.

### 3.3 [HIGH] GSP FBIF REGIONCFG isolation explicitly disabled

[booter_boot_gsprm_tu10x_ga100.c:57-73](integ/gpu_drv/stage_rel/uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c#L57-L73)

```c
// TODO suppal/derekw: revisit this
// Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot
#if 0
    ...
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_REGIONCFG, data);
#endif
```

REGIONCFG normally constrains each FBIF DMA channel to its own region
(WPR, non-WPR, sysmem, etc.) per the LSB blob's CTXDMA mapping. With
this block disabled, every DMA index on GSP defaults to whatever
hardware reset state — effectively no per-channel isolation. GSP can
DMA to any FB or sysmem address that PLM and the global WPR window
permit.

Then immediately at line 145:

```c
BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_CTL2,
                DRF_DEF(_PGSP, _FBIF_CTL2, _NACK_MODE, _NACK_AS_ACK));
```

`NACK_AS_ACK` means an invalid DMA returns success instead of a fault.
Detection of bad addresses is hidden from any logic relying on DMA
faults to detect probing.

### 3.4 [MEDIUM] Pre-verify scrub-with-zero primitive

[acr_verify_ls_signature_ga10x.c:521-532](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/ampere/acr_verify_ls_signature_ga10x.c#L521-L532)

`acrScrubUnusedWprWithZeroes_HAL(pAcr, hsOvlSigBlobOffset, hsOvlSigBlobSize)`
is called using offset/size values read from the LSB header **before**
the signature on that LSB header's ucode has been validated in this
iteration. The values are constrained by the WPR HW range so the
scribble cannot leave WPR, but inside WPR — including the WPR header
table, other LSB headers, key material that was loaded earlier — every
4-byte region the attacker can express in `(offset, size)` becomes a
controlled zero-write target.

Combined with the LSB-header DMA-read primitive in §2.4, this gives
"read 192 bytes from any WPR offset into DMEM + zero any WPR range
expressible by `(offset, size)`" as pre-signature-verify capabilities.

---

## 4. Re-prioritized target list (Phase-2 → Phase-3)

| Rank | Target | Why first |
|---|---|---|
| 1 | **GA100 RISC-V ITCM bootstub gadget** (§3.1) | Direct privilege-escalation primitive baked into prod ACR; smallest gap between "find a way to influence wprAddress" and "execute LEVEL2 RISC-V" |
| 2 | **GSP-RM DMEM open PLM** (§3.2) | No isolation between driver and GSP-RM RPC server; given a kernel-mode primitive on host this is a one-step compromise |
| 3 | **GSP FBIF REGIONCFG disabled** (§3.3) | All DMA paths on GSP-RM operate without per-channel region isolation |
| 4 | **Pre-verify WPR scribble** (§3.4) | Useful as a primitive to support other attacks (key zeroing, header rewriting between iterations) |
| 5 | **AES SCP slot 31 extraction** (§2.3) | Once it falls, all GA100 LS firmware is plaintext globally; only the silicon and the ITCM gadget protect it |
| 6 | **SMC_INFO aperture usage audit** (§2.1) | Find any consumer of `NV_PGRAPH_PRI_*_SMC_INFO` that didn't get the legacy-aperture WAR |
| 7 | **VBIOS DEVINIT script auth** (§1.1) | Real GA100 HBM2e training lives here; review the IFR/BIT chain in `cmp170hxBinary.BIN` |
| 8 | **`acrlibSetupBootvecRiscv_GA100` callers** | Trace every path that feeds `wprAddress` and `regionId`; correlate with §3.1 |

---

## 5. Concrete next-step reverse-engineering tasks

1. Disassemble [g_acruc_ga100_asb_prod.h](integ/gpu_drv/stage_rel/drivers/resman/kernel/inc/acr/bin/gsp/ga100/asb/g_acruc_ga100_asb_prod.h)
   (Falcon HS) and confirm the ITCM bootstub gadget is intact in the
   prod-signed image. Use the `.nm` / `.objdump` / `.readelf` artifacts
   in the same directory as ground truth for symbol offsets.
2. Disassemble [g_gsp_ga100_riscv_image.bin](integ/gpu_drv/stage_rel/drivers/resman/kernel/inc/gsp/bin/g_gsp_ga100_riscv_image.bin)
   and locate where `MSPM`/`MRSP` are re-written after the bootstub
   exits — if GSP-RM never re-restricts itself, the bootstub's LEVEL2
   becomes permanent.
3. Carve out the VBIOS sections from `cmp170hxBinary.BIN` starting at
   the BIT table at 0x5EB2 and locate the DEVINIT script + the embedded
   PMU/FECS bootloaders.
4. Cross-reference RPC functions in
   [rpc_global_enums.h](integ/gpu_drv/stage_rel/drivers/resman/kernel/inc/vgpu/rpc_global_enums.h)
   (189 functions, ending at `PMA_SCRUBBER_SHARED_BUFFER_GUEST_PAGES_OPERATION`)
   against the GSP-RM RPC dispatch table to find any opcode whose
   parameter parser trusts a length field.
5. Locate the AHESASC entry that calls `acrlibSetupBootvecRiscv_GA100`
   and confirm whether `LSB_HEADER.ucodeOffset` is the *signed* value
   or a re-read after verification.

---

## 6. What is *not* exploitable

Calling these out so future readers don't waste time:

- **RSA-3072 verification itself.** No evidence of a primitive that
  bypasses the SHA / RSA-PSS check; the bypass paths are all
  pre-verify or post-verify state mutations.
- **The "depMap OOB" by an untrusted attacker.** Without signing key
  access or fault injection, the depMap stays signature-covered.
- **The "i*2 integer overflow."** Cannot reach overflow before the
  loop's OOB read crashes the process.
- **The "VREF / training-state corruption" via Falcon ucode** on GA100
  specifically. GA100's HBM2e training is not in a Falcon ucode in
  this tree. Re-frame as DEVINIT integrity if at all.

---

**Last updated**: 2026-05-17 — Phase-2 validation pass complete.
**Confidence**: High for §2 verdicts (source-grounded). Medium for
§3.1 / §3.2 exploitability claims (require binary RE in Phase-3).
