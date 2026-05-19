# 7.4 — AHESASC APM Analysis

**Date:** 2026-05-18  
**Binaries:** `ahesasc_apm` (28,928B), `ahesasc_gsp_rm` (23,296B), `ahesasc` baseline (23,296B)  
**Sources:** `uproc/acr/src/apm/ampere/`, `uproc/acr/src/apm/nv/`

---

## 1. Executive Summary

Three AHESASC (ACR HS SEC2 ACR) variants exist for GA100, selected at driver load time based on operating mode:

| Variant        | File                   | Size     | Purpose                                      |
|----------------|------------------------|----------|----------------------------------------------|
| `ahesasc`      | baseline               | 23,296 B | Standard ACR — standard boot path            |
| `ahesasc_gsp_rm` | gsp_rm variant       | 23,296 B | GSP-RM authenticated boot — handoff protocol |
| `ahesasc_apm`  | APM variant            | 28,928 B | Confidential Computing — attestation & MSRs  |

**Security-relevant findings:**
1. **APM is SKU-gated to A100 SXM4 only** (DevID=0x20B5 / P1001_SKU230) — CMP 170HX cannot enable APM mode.
2. **MSR extension buffer hardcodes `falconID = LSF_FALCON_ID_SEC2`** for all measurements — attribution ambiguity: all MSR entries appear to come from SEC2 regardless of which engine is measured.
3. **APM_RTS in WPR FB** — MSR state stored in WPR sub-region. Combined with the REGIONCFG `#if 0` finding (Phase-4 P1), GSP-RM unrestricted FB-DMA could reach APM_RTS if WPR2 sub-region lock fails or is bypassed.
4. **CC enable bit set by VBIOS** via `NV_PGC6_AON_SECURE_SCRATCH_GROUP_20` — not hardware-fused; set at VBIOS POST from OOB/NvFlash configuration. Debug boards bypass the SKU check entirely.

---

## 2. Binary Comparison

```
Variant          Size       Entropy   IMEM (.imem_acr)   New symbols vs baseline
─────────────────────────────────────────────────────────────────────────────────
ahesasc          23,296B    6.374     0x3E00 (15,872B)   —
ahesasc_gsp_rm   23,296B    5.087     0x3E00 (15,872B)   +2 (handoff check/write)
ahesasc_apm      28,928B    6.718     0x5300 (21,248B)   +26 (SHA engine + MSR + measure)
```

The `ahesasc_gsp_rm` entropy (5.087) is notably lower than baseline (6.374) despite identical binary size — same symbol set minus 2, but high code-reuse / different object layout produces more compressible text section. The APM binary is 5,632B larger, adding the entire SHA hardware engine driver and MSR management layer.

---

## 3. APM Variant: Symbols Added

26 new symbols vs baseline, grouped by subsystem:

**APM gate check:**
- `_acrCheckIfApmEnabled_GA100` (0x3C67, 0x71B) — SKU + CC-mode fuse check

**Measurement functions:**
- `_acrMeasureCCState_GA100` — reads `NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC` → extends MSR[0]
- `_acrMeasureFuses_GA100` — reads 14 security fuses in 2 batches → extends MSR[0]
- `_acrMeasureEngineVersionFuses_GA100` — reads NVDEC/SEC2/PMU/GSP FPF fuse versions (up to 16 slots each) → extends MSR[0]
- `_acrMeasureWprMmuState_GA100` — reads `NV_PFB_PRI_MMU_WPR_ALLOW_READ/WRITE` → extends MSR[1]
- `_acrMeasureStaticState_GA100` — orchestrates the above four in sequence
- `_acrMeasureDmhash_GA100` — extends per-falcon MSR[5–9] with DMhash
- `_acrFalconIdToMsrId_GA100` — maps LSF_FALCON_ID_* to APM_RTS_MSR_INDEX_FALCON_*

**MSR operations:**
- `_acrMsrExtend` — mutex-protected read-extend-write cycle on a single MSR group
- `_acrMsrResetAll` — zeros all 32 MSR groups in APM_RTS via DMA; soft-resets SHA engine first
- `_acrReadMsrGroup` — mutex-protected DMA read of an MSR group from WPR FB

**SHA-256 hardware engine:**
- `_shaGetConfigEncodeMode_GA100`, `_shaWaitEngineIdle_GA100`, `_shaReadHashResult_GA100`
- `_shaInsertTask_GA100`, `_shaReleaseMutex_GA100`, `_shaAcquireMutex_GA100`
- `_shaEngineHalt_GA100`, `_shaOperationInit_GA100`, `_shaEngineSoftReset_GA100`

**New DMEM globals:**
- `_g_msrExtBuffer` @ 0x10001130 (0x44B) — `APM_EXTENSION_BUFFER` staging area
- `_g_hashDstBuffer` @ 0x10001180 (0x20B) — SHA-256 result buffer
- `_g_apmDmaGroup`  @ 0x100011A0 (0x80B) — in-DMEM copy of one MSR group
- `_g_newMeasurement` @ 0x10001C20 (0x20B, BSS) — staging for new measurement input
- `_g_offsetApmRts` @ 0x10001C28 (0x4B, BSS) — FB byte offset of APM_RTS structure

---

## 4. APM_RTS Memory Layout

### APM_RTS in WPR FB

`g_offsetApmRts` holds the byte offset from FB base to the `APM_RTS` structure in WPR. The structure is 4,096 bytes (1 page, confirmed by `ct_assert` in `apm_rts.h`), stored in a dedicated sub-WPR region (`LSF_SHARED_DATA_SUB_WPR_APM_RTS_SIZE_IN_4K = 1`).

### APM_MSR_GROUP layout (128 bytes each, 32 groups = 4,096B total)

```c
typedef struct {
    APM_MSR     msr;       // [0x00] 32B — current measurement (SHA-256, big-endian)
    APM_MSR     msrs;      // [0x20] 32B — shadow measurement
    APM_MSR_CNT msrcnt;    // [0x40]  4B — extend count for msr
    APM_MSR_CNT msrscnt;   // [0x44]  4B — extend count for msrs
    NvU32       reserved[14]; // [0x48] 56B — pad to 128B
} APM_MSR_GROUP;  // 128B per group
```

### MSR Index Allocation (`sw_rts_msr_usage.h`)

```
MSR[0]   APM_RTS_MSR_INDEX_FUSES         — security fuses + engine FPF versions
MSR[1]   APM_RTS_MSR_INDEX_WPR_MMU_STATE — NV_PFB_PRI_MMU_WPR_ALLOW_READ/WRITE
MSR[2]   APM_RTS_MSR_INDEX_VPR_MMU_STATE — (not populated in APM source)
MSR[3]   APM_RTS_MSR_INDEX_DECODE_TRAPS  — (not populated in APM source)
MSR[4]   (unassigned)
MSR[5]   APM_RTS_MSR_INDEX_FALCON_SEC2
MSR[6]   APM_RTS_MSR_INDEX_FALCON_PMU
MSR[7]   APM_RTS_MSR_INDEX_FALCON_NVDEC
MSR[8]   APM_RTS_MSR_INDEX_FALCON_FECS
MSR[9]   APM_RTS_MSR_INDEX_FALCON_GPCCS
MSR[10–31] (unassigned)
```

MSR[4] and MSR[10–31] are unassigned. MSR[2] (VPR_MMU_STATE) and MSR[3] (DECODE_TRAPS) are defined but not extended in the APM source seen — they are either extended from a different context (e.g. PMU) or left at zero.

---

## 5. MSR Extend Algorithm

Each measurement extends an MSR using a PCR-style hash chain. The extension buffer (68 bytes) is:

```
Offset  Size  Field
─────────────────────────────────────────────────────────
0x00     1B   reserved = 0x00
0x01     1B   reserved = 0x00
0x02     1B   falconID = LSF_FALCON_ID_SEC2 (HARDCODED — see §7 Finding P3-1)
0x03     1B   prevStateSrc: 0x00=old_MSR_value, 0x01=zero_string
0x04    32B   newMeasurement (input measurement, big-endian SHA-256)
0x24    32B   prevState (current MSR value, or zeros if bFromZero=TRUE)
─────────────────────────────────────────────────────────
Total: 68B = APM_EXTENSION_BUFFER_SIZE
```

New MSR = SHA-256(extension buffer)

The `msrs` (shadow) register is always extended from zero (`bFromZero=TRUE` for shadow path). `msrscnt` resets to 1 on a shadow-flush; `msrcnt` increments on every extend.

Extension is protected by `SEC2_MUTEX_APM_RTS` (a hardware mutex) acquired before reading the MSR group from FB and released after writing it back. This prevents concurrent extensions corrupting the MSR chain.

---

## 6. APM Enable Gate

`acrCheckIfApmEnabled_GA100` (`acr_apm_checks_ga100.c`) implements a two-path gate:

**Debug board path** (skips SKU check):
```c
val = ACR_REG_RD32(BAR0, NV_FUSE_OPT_SECURE_SECENGINE_DEBUG_DIS);
if (val != NV_FUSE_OPT_SECURE_SECENGINE_DEBUG_DIS_DATA_NO) {
    // debug board — proceed to mode check, skip SKU check
```

**Production path** (requires both CC mode AND SKU):
```c
apmMode = ACR_REG_RD32(BAR0, NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC);
// must have CC_MODE_ENABLED = TRUE
devId   = DRF_VAL(_FUSE, _OPT_PCIE_DEVIDA, _DATA,    devId);   // must = 0x20B5
chipId  = DRF_VAL(_PMC,  _BOOT_42, _CHIP_ID, chipId);           // must = GA100 (0x170)
```

`NV_PCI_DEVID_DEVICE_P1001_SKU230 = 0x20B5` is the **A100 SXM4 80GB** PCIe device ID. This means:
- CMP 170HX (DevID ≠ 0x20B5): APM mode **cannot be enabled** in production.
- A100 SXM4 (DevID = 0x20B5): APM mode enabled if `NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC` has the mode bit set.
- Any GA100 debug board: APM mode enabled if mode bit set (SKU not checked).

The CC mode bit is **set by VBIOS at POST** from either OOB (out-of-band management) or NvFlash — it is not a hardware fuse. This means APM can be toggled without reflashing OTP fuses.

---

## 7. Security Analysis

### Finding P3-1: MSR Extension Buffer FalconID Hardcoded to SEC2 (Informational)

Source: `acr_apmmsr.c:_acrPrepareExtendMsr`:
```c
pExtensionBuffer->falconID = LSF_FALCON_ID_SEC2;
// This needs to be replaced with the ID of the current falcon
```

The comment explicitly acknowledges this as incomplete. All 9 active MSR groups (fuses, WPR MMU, 5 Falcon DMhashes) are extended with `falconID = LSF_FALCON_ID_SEC2` — even PMU, FECS, GPCCS, and NVDEC measurements. 

An attestation verifier reading the MSR extension buffer cannot distinguish SEC2 self-measurements from measurements of other engines based on the falconID field alone. The verifier must rely on the MSR index and the fixed ordering of extensions to determine what was measured.

**Impact:** Attestation log correlation — an attacker who controls measurement ordering (if ever possible) cannot be definitively attributed. **Does not break security** given fixed ordering, but reduces auditability.

**Severity:** Informational (documentation gap / incomplete implementation acknowledged in source).

### Finding P3-2: APM_RTS Reachable via Unrestricted GSP-RM FB-DMA (Potential Compound Vulnerability)

This finding combines two earlier Phase-4 P1 results with the APM architecture:

1. **REGIONCFG `#if 0`** (Phase-4 P1): `NV_PGSP_FBIF_REGIONCFG` is disabled — GSP-RM has no WPR FB-region restriction on its DMA engine.
2. **APM_RTS stored in WPR sub-region** at `g_offsetApmRts` in FB.
3. GSP-RM runs at L0 (LS) and has unrestricted FB-DMA post-REGIONCFG-disable.

**Question:** Does the WPR2 hardware lock (set by `acrLockWpr1DuringACRLoad_TU10X`) prevent GSP-RM FB-DMA to the APM_RTS sub-region?

The WPR2 lock restricts **CPU** (host) access to WPR FB range. The FBIF REGIONCFG restriction, when enabled, would restrict Falcon DMA to WPR. With REGIONCFG disabled, Falcon DMA to WPR FB is **not hardware-blocked** by FBIF — only the CPU-side WPR lock applies.

**If GSP-RM were compromised**, it could DMA to APM_RTS in WPR FB, overwriting MSR values and extend-counts before or after AHESASC_APM runs. This would silently corrupt the attestation state without SEC2 detecting it.

**Severity:** Medium — exploitable only if GSP-RM is compromised AND APM mode is active (A100 SXM4 only). The DMEM PLM vulnerability (Phase-4 P1) is a prerequisite path to compromising GSP-RM from LS. This is a compound chain: DMEM PLM → GSP-RM compromise → APM_RTS corruption via unrestricted FBIF DMA.

**PSIRT note:** This compound chain (DMEM PLM + REGIONCFG disabled + APM_RTS in unrestricted WPR region) directly undermines the Confidential Computing attestation guarantee on A100 SXM4.

### Finding P3-3: APM CC Enable Bit Not Hardware-Fused

`NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC` is a **secure scratch register** written by VBIOS at POST, not an OTP fuse. It can be changed by:
- OOB management (BMC via NvFlash protocol)
- VBIOS reflash

**Impact:** A privileged attacker with BMC access or VBIOS flash capability can toggle CC mode without fuse programming. If APM mode is disabled, the APM AHESASC variant is not loaded, and no MSR measurements are taken — the attestation subsystem silently provides no evidence.

**Severity:** Low — requires OOB/flash access which is considered privileged. But worth noting for the threat model in Confidential Computing deployments.

---

## 8. GSP-RM Variant: Handoff Protocol

`ahesasc_gsp_rm` adds exactly two symbols vs baseline:

### `acrAhesascGspRmCheckHandoff_GA100`
```c
NvU32 handoffValue = ACR_REG_RD32(BAR0, NV_PGC6_BSI_VPR_SECURE_SCRATCH_14);
if (!FLD_TEST_DRF(_PGC6, _BSI_VPR_SECURE_SCRATCH_14, _BOOTER_LOAD_HANDOFF, _VALUE_DONE, handoffValue))
    return ACR_ERROR_AUTH_GSP_RM_HANDOFF_FAILED;
```
Verifies Booter LOAD completed successfully before AHESASC_GSP_RM begins.

### `acrWriteAhesascGspRmHandoffValueToBsiSecureScratch_GA100`
```c
handoffValue = FLD_SET_DRF(_PGC6, _BSI_VPR_SECURE_SCRATCH_14, _AHESASC_BOOTER_RELOAD_HANDOFF, _VALUE_DONE, handoffValue);
ACR_REG_WR32(BAR0, NV_PGC6_BSI_VPR_SECURE_SCRATCH_14, handoffValue);
```
Signals Booter RELOAD that AHESASC_GSP_RM completed, enabling the reload to proceed.

**Full handoff chain** encoded in `NV_PGC6_BSI_VPR_SECURE_SCRATCH_14`:
```
BOOTER_LOAD_HANDOFF          ← set by Booter LOAD
AHESASC_BOOTER_RELOAD_HANDOFF← set by AHESASC_GSP_RM
BOOTER_RELOAD_ACR_UNLOAD_HANDOFF ← set by Booter RELOAD
ACR_UNLOAD_BOOTER_UNLOAD_HANDOFF ← set by ACR Unload
```
ACR Unload checks all four bits are set before allowing Booter UNLOAD to proceed.

This handoff chain is a liveness check, not an authentication step — it verifies each stage ran but not that it ran correctly. A compromised AHESASC_GSP_RM could set `_AHESASC_BOOTER_RELOAD_HANDOFF` without doing any actual ACR work.

---

## 9. IMEM Size Comparison

```
Variant          .imem_acr   .data     .bss
─────────────────────────────────────────────────
ahesasc          0x3E00      0x1131    0x0908
ahesasc_gsp_rm   0x3E00      0x1131    0x0908
ahesasc_apm      0x5300      0x1221    0x092C
                 (+0x1500B)  (+0xF0B)  (+0x24B)
```

APM adds 5,376 bytes of IMEM (SHA engine + MSR management + measurement functions). The additional 240B of `.data` and 36B of `.bss` are the new DMEM globals (`g_msrExtBuffer`, `g_hashDstBuffer`, `g_apmDmaGroup`).

---

## 10. Cross-References

- **Phase-4 P1** (`7-3-phase4-booter-analysis.md`): DMEM PLM=READ_L0_WRITE_L0 — prerequisite to GSP-RM compromise in compound chain (Finding P3-2).
- **Phase-4 P1**: REGIONCFG `#if 0` — direct enabler of APM_RTS FB-DMA attack in compound chain.
- **Phase-2**: AES-DM salt @ AHESASC DMEM 0x800 — separate DMEM, not affected by GSP DMEM PLM finding.
- **Phase-4 P4** (next target): `_acrSetupLSFalcon_TU10X` at ASB 0x1E81 — pre-verify DMA scribble.

---

## 11. Summary of New PSIRT-Relevant Findings

| ID    | Description                                       | Severity | Prerequisite          |
|-------|---------------------------------------------------|----------|-----------------------|
| P3-1  | MSR falconID hardcoded to SEC2 for all measures   | Info     | None                  |
| P3-2  | APM_RTS reachable via unrestricted GSP-RM FB-DMA  | Medium   | P1-1 + P1-2 (compound)|
| P3-3  | CC enable bit is scratch reg, not OTP fuse        | Low      | OOB/VBIOS flash access|

---

*Next: Phase-4 P4 — `_acrSetupLSFalcon_TU10X` @ ASB 0x1E81, pre-verify DMA scribble*
