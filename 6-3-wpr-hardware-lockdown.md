# 6.3 — Synthesis: WPR Hardware Lockdown Mechanics

**Document:** 23 | **Phase:** 4-Extension  
**Date:** 2026-05-18  
**Scope:** GA100 only (chip ID 0x170). All source verbatim from `integ/gpu_drv/stage_rel/`.  
**Sources:**  
- `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c`  
- `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c`  
- `uproc/acr/inc/acr.h`  
- `drivers/resman/arch/nvalloc/common/inc/rmlsfm.h`  
- `uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c`  
**Cross-references:** `7-3-phase4-booter-analysis.md` (binary-verified PLMs), `6-1-crypto-auth-chain-map.md` §4, `6-2-verification-state-machine.md` §2.6/§3/§4

---

## 0. Purpose

This document provides a register-level, source-verified breakdown of every hardware
primitive used to enforce secure-boot boundaries in the GA100 firmware ecosystem after
cryptographic signature verification but before Falcon execution. Three distinct
enforcement layers are described:

1. **WPR MMU lock** — `NV_PFB_PRI_MMU_*` registers programmed by AHESASC
2. **Per-Falcon privilege-level masks** — `FALCON_*_PRIV_LEVEL_MASK` registers programmed by Booter and AHESASC
3. **PPRIV_SYS decode trap** — transient SEC2 register-space isolation programmed by ASB during SEC2 RTOS load

A fourth subsection documents the REGIONCFG omission (confirmed dead code) which eliminates the intended FB-DMA restriction on GSP-RM.

---

## 1. WPR MMU Register Architecture

The hardware WPR is controlled exclusively through `NV_PFB_PRI_MMU_*` registers.
These are part of the Framebuffer Partition (PFB) MMU subsystem and operate independently
of Falcon privilege levels. Access to WPR-protected DRAM is filtered by the MMU before
it reaches the memory controller; no Falcon or host-CPU instruction can bypass this gate
without first reprogramming these registers (which requires HS privilege, L3).

### 1.1 Register Table

| Register | Effective Address | Granularity | Purpose |
|---|---|---|---|
| `NV_PFB_PRI_MMU_WPR1_ADDR_LO` | PFB space | 4K pages | WPR1 start, stored as `phys >> 12` |
| `NV_PFB_PRI_MMU_WPR1_ADDR_HI` | PFB space | 4K pages | WPR1 end (inclusive), stored as `(phys-1) >> 12` |
| `NV_PFB_PRI_MMU_WPR2_ADDR_LO` | PFB space | 4K pages | WPR2 start (GSP-RM container) |
| `NV_PFB_PRI_MMU_WPR2_ADDR_HI` | PFB space | 4K pages | WPR2 end |
| `NV_PFB_PRI_MMU_WPR_ALLOW_READ` | PFB space | — | Per-region read privilege bitmask |
| `NV_PFB_PRI_MMU_WPR_ALLOW_WRITE` | PFB space | — | Per-region write privilege bitmask |

### 1.2 Privilege-Level Bitmask Encoding (ALLOW_READ / ALLOW_WRITE)

Both `ALLOW_READ` and `ALLOW_WRITE` contain a 4-bit field per WPR region (WPR1, WPR2).
Each bit enables access for one privilege level:

| Bit | Level | Who |
|---|---|---|
| 3 | L3 | HS Falcon (hardware-authenticated, ROM-boot) |
| 2 | L2 | HS task (software-signed, e.g. AHESASC on SEC2) |
| 1 | L1 | LS Falcon (authenticated LS code) |
| 0 | L0 | Host driver / unauthenticated |

**Constants from `rmlsfm.h`:**

```c
// rmlsfm.h lines 28–33
#define LSF_WPR_REGION_RMASK                    (0xCU) // L2+L3 readable
#define LSF_WPR_REGION_WMASK                    (0xCU) // L2+L3 writable
#define LSF_WPR_REGION_RMASK_SUB_WPR_ENABLED    (0x8)  // L3-only readable (sub-WPRs govern L0/L1/L2)
#define LSF_WPR_REGION_WMASK_SUB_WPR_ENABLED    (0x8)  // L3-only writable (sub-WPRs govern L0/L1/L2)
#define LSF_WPR_REGION_ALLOW_READ_MISMATCH_NO   (0x0)  // deny read on address mismatch
#define LSF_WPR_REGION_ALLOW_WRITE_MISMATCH_NO  (0x0)  // deny write on address mismatch

#define LSF_WPR_EXPECTED_REGION_ID  (0x1U)            // only region ID 1 is valid
```

**Constants from `acr.h`:**

```c
// acr.h lines 93–101
#define ACR_SUB_WPR_MMU_RMASK_L2_AND_L3             0xC
#define ACR_SUB_WPR_MMU_WMASK_L2_AND_L3             0xC
#define ACR_SUB_WPR_MMU_RMASK_L3                    0x8
#define ACR_SUB_WPR_MMU_WMASK_L3                    0x8
#define ACR_SUB_WPR_MMU_RMASK_ALL_LEVELS_DISABLED   0x0
#define ACR_SUB_WPR_MMU_WMASK_ALL_LEVELS_DISABLED   0x0
#define ACR_UNLOCK_READ_MASK                         0x0   // used by Unload to clear WPR
#define ACR_UNLOCK_WRITE_MASK                        0x0

#define ACR_WPR1_REGION_IDX                         (0x0)  // index into g_desc.regions.regionProps[]
```

When `ALLOW_READ/WRITE._WPR1 = 0x8` (SUB_WPR_ENABLED), the outer WPR1 gate only passes
L3 (HS) accesses; all lower-privilege accesses are governed by the per-falcon sub-WPR
descriptors programmed in the MMU alongside the outer gate.

---

## 2. `acrLockWpr1DuringACRLoad_TU10X` — Complete Register Sequence

**Source:** `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c` lines 454–531

This function is called at AHESASC init **step 7**, before the LS signature verification
loop (step 11). The full function body:

```c
ACR_STATUS
acrLockWpr1DuringACRLoad_TU10X
(
    NvU32 *pWprIndex
)
{
    ACR_STATUS               status         = ACR_OK;
    // defAlign: addresses stored as >>8 (256B granular); >>4 more = 4K granular for MMU regs
    NvU32                    defAlign       = (NV_PFB_PRI_MMU_VPR_WPR_WRITE_ADDR_ALIGNMENT - 8);  // = 12-8 = 4
    NvU32                    data           = 0;
    RM_FLCN_ACR_REGION_PROP *pRegionProp;
    NvU32                    wprStartAddr4K = INVALID_WPR_ADDR_LO;
    NvU32                    wprEndAddr4K   = INVALID_WPR_ADDR_HI;

    *pWprIndex = ACR_WPR1_REGION_IDX;  // 0x0

    pRegionProp = &(g_desc.regions.regionProps[ACR_WPR1_REGION_IDX]);

    // GUARD 1: regionID must be exactly LSF_WPR_EXPECTED_REGION_ID (0x1)
    if (pRegionProp->regionID != LSF_WPR_EXPECTED_REGION_ID)
    {
        return ACR_ERROR_INVALID_REGION_ID;
    }

    // GUARD 2: start < end (non-empty region)
    if (pRegionProp->startAddress >= pRegionProp->endAddress)
    {
        return ACR_ERROR_INVALID_ARGUMENT;
    }

    // ADDRESS CONVERSION: addresses are pre-aligned to 256B by RM.
    // Shift right 4 more bits to express in 4K pages for the MMU register.
    wprStartAddr4K = (pRegionProp->startAddress)   >> defAlign;   // >> 4
    wprEndAddr4K   = (pRegionProp->endAddress - 1) >> defAlign;   // inclusive end, >> 4

    // WRITE 1: Program WPR1 start address (4K granular)
    data = ACR_REG_RD32(BAR0, NV_PFB_PRI_MMU_WPR1_ADDR_LO);
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR1_ADDR_LO, _VAL, wprStartAddr4K, data);
    ACR_REG_WR32(BAR0, NV_PFB_PRI_MMU_WPR1_ADDR_LO, data);

    // WRITE 2: Program WPR1 end address (inclusive, 4K granular)
    data = ACR_REG_RD32(BAR0, NV_PFB_PRI_MMU_WPR1_ADDR_HI);
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR1_ADDR_HI, _VAL, wprEndAddr4K, data);
    ACR_REG_WR32(BAR0, NV_PFB_PRI_MMU_WPR1_ADDR_HI, data);

    // WRITE 3: Set WPR1 read access to L3-only (sub-WPRs control L0/L1/L2 access)
    //          Set MIS_MATCH = NO (deny reads that don't hit any sub-WPR)
    data = ACR_REG_RD32(BAR0, NV_PFB_PRI_MMU_WPR_ALLOW_READ);
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR_ALLOW_READ, _WPR1,    LSF_WPR_REGION_RMASK_SUB_WPR_ENABLED, data);  // 0x8
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR_ALLOW_READ, _MIS_MATCH, LSF_WPR_REGION_ALLOW_READ_MISMATCH_NO, data); // 0x0
    ACR_REG_WR32(BAR0, NV_PFB_PRI_MMU_WPR_ALLOW_READ, data);

    // WRITE 4: Set WPR1 write access to L3-only; deny writes on mismatch
    data = ACR_REG_RD32(BAR0, NV_PFB_PRI_MMU_WPR_ALLOW_WRITE);
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR_ALLOW_WRITE, _WPR1,     LSF_WPR_REGION_WMASK_SUB_WPR_ENABLED, data); // 0x8
    data = FLD_SET_DRF_NUM( _PFB, _PRI_MMU_WPR_ALLOW_WRITE, _MIS_MATCH, LSF_WPR_REGION_ALLOW_WRITE_MISMATCH_NO, data); // 0x0
    ACR_REG_WR32(BAR0, NV_PFB_PRI_MMU_WPR_ALLOW_WRITE, data);

    // Persist WPR geometry to BSI secure scratch (for GC6 suspend/resume restore)
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrSaveWprInfoToBSISecureScratch_HAL());

    // SUB-WPR PROGRAMMING (three sub-regions within WPR1):

    // SEC2 subWPR-0: AHESASC ACRlib running on SEC2 needs R/W to all of WPR1
    //   R=L2+L3 (0xC), W=L2+L3 (0xC), span = [wprStartAddr4K, wprEndAddr4K]
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrProgramFalconSubWpr_HAL(pAcr,
        LSF_FALCON_ID_SEC2, SEC2_SUB_WPR_ID_0_ACRLIB_FULL_WPR1,
        wprStartAddr4K, wprEndAddr4K,
        ACR_SUB_WPR_MMU_RMASK_L2_AND_L3,   // 0xC
        ACR_SUB_WPR_MMU_WMASK_L2_AND_L3,   // 0xC
        NV_TRUE));

    // PMU subWPR-0: PMU ACRlib also needs full WPR1 during AHESASC execution
    //   R=L2+L3 (0xC), W=L2+L3 (0xC), span = full WPR1
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrProgramFalconSubWpr_HAL(pAcr,
        LSF_FALCON_ID_PMU, PMU_SUB_WPR_ID_0_ACRLIB_FULL_WPR1,
        wprStartAddr4K, wprEndAddr4K,
        ACR_SUB_WPR_MMU_RMASK_L2_AND_L3,   // 0xC
        ACR_SUB_WPR_MMU_WMASK_L2_AND_L3,   // 0xC
        NV_TRUE));

    // GSP-lite subWPR-2: ASB (runs on GSP-lite) needs full WPR1 to DMA SEC2 RTOS in
    //   R=L3 only (0x8), W=L3 only (0x8), span = full WPR1
    //   NOTE: TODO comment in source — should be L3-only (HS) once ACRlib is HS SEC2 task
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrProgramFalconSubWpr_HAL(pAcr,
        LSF_FALCON_ID_GSPLITE, GSP_SUB_WPR_ID_2_ASB_FULL_WPR1,
        wprStartAddr4K, wprEndAddr4K,
        ACR_SUB_WPR_MMU_RMASK_L3,           // 0x8
        ACR_SUB_WPR_MMU_WMASK_L3,           // 0x8
        NV_TRUE));

    return status;
}
```

### 2.1 Pre-Step: `acrDisableAllFalconSubWprs_HAL`

Before `acrLockWpr1DuringACRLoad_TU10X` is called, `acrLockAcrRegions_TU10X` first
calls `acrDisableAllFalconSubWprs_HAL`. This zeroes all sub-WPR MMU descriptors:

```c
// acr_lock_wpr_tu10x.c  acrLockAcrRegions_TU10X():
if (ACR_OK != (status = acrDisableAllFalconSubWprs_HAL(pAcr)))
{
    return status;
}
// ... then calls acrLockWpr1DuringACRLoad_HAL()
```

This is required because Turing hardware does not reset sub-WPR descriptors to disabled
state on power-on. Without this step, stale sub-WPR values from a prior boot (e.g. GC6
resume) could grant unintended access.

### 2.2 WPR2 Lock (`acrLockWpr2DuringACRLoad_TU10X`)

For non-fmodel builds, WPR2 lock is a no-op:

```c
ACR_STATUS
acrLockWpr2DuringACRLoad_TU10X(NvU32 *pWprIndex)
{
#ifdef ACR_FMODEL_BUILD
    return acrLockWpr2DuringACRLoadForFmodel_HAL(pAcr, pWprIndex);
#else
    return ACR_OK;   // WPR2 not hardware-locked on production silicon
#endif
}
```

WPR2's geometry (`NV_PFB_PRI_MMU_WPR2_ADDR_LO/HI`) was already programmed by FWSEC
(running on ROM trust) before Booter ran. On GA100 production silicon, AHESASC does not
re-program WPR2 MMU registers. The WPR2 `ALLOW_READ/WRITE` fields in
`NV_PFB_PRI_MMU_WPR_ALLOW_READ` carry whatever values FWSEC left.

### 2.3 WPR Unlock Path (`acrUnloadACR_TU10X`)

For completeness: when ACR Unload runs (SEC2 PMU teardown path), each sub-WPR is
re-programmed with `RMASK=0x0, WMASK=0x0` (all disabled), then the outer WPR1 gate is
cleared by writing `ACR_UNLOCK_READ_MASK=0x0` and `ACR_UNLOCK_WRITE_MASK=0x0` back to
`NV_PFB_PRI_MMU_WPR_ALLOW_READ/WRITE._WPR1`. The WPR1 address registers are not cleared
(the hardware gate remains set but admits no privilege level). PMU/SEC2 PLM teardown
behavior after this is an open gap (see §7.1).

---

## 3. Critical Timing: WPR Lock Fires Before LS Signature Verification

This is the most security-relevant timing relationship in the entire boot chain.

### 3.1 AHESASC Init Sequence (`acrInit_TU10X`)

**Source:** `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c` (init dispatcher)  
**Cross-ref:** `6-1-crypto-auth-chain-map.md` §4

```
acrInit_TU10X():
  Step  1: acrProgramHubEncryption_HAL()
             → TRNG-generated HUB encryption keys, written to SFBHUB via SCP
  Step  2: acrProtectNvlinkRegs_HAL()
             → LTCS/HSHUB registers → privilege level 2+ write-only
  Step  3: acrProtectHostTimerRegisters_HAL()
             → timer PLM → L3
  Step  4: acrAllowFecsToUpdateSecureScratchGroup15_HAL()
  Step  5: acrProtectHost2JtagWARBug2401005_HAL()
             → JTAG WAR (Turing-only)
  Step  6: g_bIsDebug = acrIsDebugModeEnabled_HAL()
             → reads NV_CSEC_SCP_CTL_STAT.DEBUG_MODE

  ╔═══════════════════════════════════════════════════════════════╗
  ║ Step  7: acrLockAcrRegions_HAL()                             ║
  ║          → acrDisableAllFalconSubWprs_HAL()                  ║
  ║          → acrLockWpr1DuringACRLoad_TU10X()    ← WPR LOCK   ║
  ║             Programs NV_PFB_PRI_MMU_WPR1_ADDR_LO/HI         ║
  ║             Sets ALLOW_READ/WRITE._WPR1 = 0x8 (L3-only)     ║
  ║             Programs SEC2/PMU/GSPlite sub-WPRs               ║
  ╚═══════════════════════════════════════════════════════════════╝

  Step  8: _acrShadowCopyOfWpr()
             → DMA host-provided shadow data into WPR1
  Step  9: acrSetupSharedSubWprs_HAL()
             → APM_RTS sub-WPR and other shared sub-regions
  Step 10: acrCopyFrtsData_HAL()
             → DMA FRTS data from WPR2 (FWSEC-placed) to WPR1

  ╔═══════════════════════════════════════════════════════════════╗
  ║ Step 11: acrValidateSignatureAndScrubUnusedWpr_HAL()         ║
  ║          ← LS SIGNATURE VERIFICATION LOOP                    ║
  ║             For each WPR header entry (falconId sentinel      ║
  ║             0xFFFFFFFF):                                      ║
  ║               AES-DM hash → KDF(SCP slot 43) → AES-ECB sig  ║
  ║               FAIL → DMA-zero scrub + halt                   ║
  ╚═══════════════════════════════════════════════════════════════╝
```

### 3.2 Security Implication of the Lock-Before-Verify Ordering

The WPR1 MMU hardware gate is established at step 7. The content of WPR1 is not
cryptographically authenticated by AHESASC until step 11. During steps 8–10, AHESASC
itself performs DMA writes into WPR1 (shadow copy, FRTS data). These writes are
authorized by the SEC2 sub-WPR (RMASK=0xC, WMASK=0xC, L2+L3 access), so AHESASC can
legitimately write during this window.

The relevant attack surface is whether any DMA path that is not governed by the sub-WPR
access check could overwrite WPR1 content between step 7 and step 11. The outer gate
(`ALLOW_WRITE._WPR1 = 0x8`) limits unsubscribed writes to L3 only; no host-driver or
LS-Falcon path reaches L3 during AHESASC execution. The window is architecturally
bounded; no exploitable path is currently confirmed within this window specifically.

**Key contrast with Booter's RSA-3072 verification:** Booter (layer L3) completed
RSA-3072-PSS-SHA-256 on GSP-RM BL + ELF *before* AHESASC ran, and wrote
`WprMeta.verified = 0xa0a0a0a0a0a0a0a0` into WPR2 as its authentication token.
AHESASC's step-11 verification covers all *other* LS Falcons (PMU, SEC2, FECS, GPCCS,
NVDEC, NVDEC). So at step 7 when the lock fires, only GSP-RM has been cryptographically
authenticated (via RSA); all other LS content is in WPR1 but unverified by AHESASC.

---

## 4. Falcon SCTL / PLM Isolation Chain

After WPR lock and LS verification, Booter and AHESASC program per-falcon privilege-level
masks. These registers restrict which privilege levels can write to each Falcon subsystem
register.

### 4.1 Booter-Set PLMs for GSP-RM (TU10X path, binary-confirmed)

**Source:** `uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c`  
**Binary offsets confirmed in `7-3-phase4-booter-analysis.md` §4**

```
Write sequence (BAR0 CSB bridge, all issued by Booter HS on SEC2):

Step 1:  NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK  (0x110298) ← 0x8F  READ_L0 / WRITE_L3
         Protects the SCTL register itself — only HS can modify SCTL after this write.

Step 2:  NV_PGSP_FALCON_SCTL               (SCTL fields):
           RESET_LVLM_EN   = FALSE
           STALLREQ_CLR_EN = FALSE
           AUTH_EN         = TRUE   ← Prevents unauthenticated CPU control-reg access

Step 3:  NV_PGSP_FALCON_CPUCTL            ALIAS_EN = FALSE  (during setup)

Step 4a: NV_PGSP_FALCON_IMEM_PRIV_LEVEL_MASK  (0x110280) ← 0x8F  READ_L0 / WRITE_L3
Step 4b: NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK  (0x110284) ← 0xFF  READ_L0 / WRITE_L0 ★W-1★
Step 4c: NV_PGSP_FALCON_CPUCTL_PRIV_LEVEL_MASK (0x110288) ← 0x8F READ_L0 / WRITE_L3
Step 4d: NV_PGSP_FALCON_EXE_PRIV_LEVEL_MASK   (0x11028C) ← 0xFF  READ_L0 / WRITE_L0
Step 4e: NV_PGSP_FALCON_IRQTMR_PRIV_LEVEL_MASK (0x110290) ← 0xFF READ_L0 / WRITE_L0
Step 4f: NV_PGSP_FALCON_MTHDCTX_PRIV_LEVEL_MASK (0x110294) ← 0xFF READ_L0 / WRITE_L0
Step 5a: NV_PGSP_FALCON_DIODT_PRIV_LEVEL_MASK  (0x1100EC) ← 0x8F READ_L0 / WRITE_L3
Step 5b: NV_PGSP_FALCON_DIODTA_PRIV_LEVEL_MASK (0x1100F0) ← 0x8F READ_L0 / WRITE_L3

Step 6:  NV_PGSP_FALCON_SCTL               (final):
           RESET_LVLM_EN   = TRUE
           STALLREQ_CLR_EN = TRUE
           AUTH_EN         = TRUE   ← verify sticky

         Sanity-read back SCTL; if AUTH_EN not set → BOOTER_ERROR_LS_BOOT_FAIL_AUTH

Step 7:  NV_PGSP_RISCV_CPUCTL             ALIAS_EN = TRUE   (pre-GA10X path)

Launch: NV_PGSP_RISCV_CPUCTL_ALIAS        STARTCPU = TRUE
        Binary: 8a 6c 12 11 0b 01 → BAR0[0x11126C] = STARTCPU_TRUE
```

**PLM mask bit encoding:**
- Bits 3:0 = READ protection: `0xF` = all levels can read, `0x0` = none
- Bits 7:4 = WRITE protection: `0xF` = all levels, `0x8` = L3-only, `0x0` = none

### 4.2 AHESASC-Set PLMs (Post-Verification)

After the LS signature loop (step 11) passes, `acrlibSetupTargetFalconPlms_TU10X` programs:

```c
// All falcons:
NV_PFALCON_FALCON_PRIVSTATE_PRIV_LEVEL_MASK → ACR_PLMASK_READ_L0_WRITE_L3  (0x8F)

// SEC2-specific:
NV_PSEC_FBIF_CTL2_PRIV_LEVEL_MASK          → ACR_PLMASK_READ_L0_WRITE_L2  (0x4F)
NV_PSEC_BLOCKER_PRIV_LEVEL_MASK            → ACR_PLMASK_READ_L0_WRITE_L2
NV_PSEC_IRQTMR_PRIV_LEVEL_MASK            → ACR_PLMASK_READ_L0_WRITE_L2

// SEC2 DIODT/DIODTA: L0 and L1 write disabled
NV_PSEC_FALCON_DIODT_PRIV_LEVEL_MASK:
    WRITE_PROTECTION_LEVEL0 = DISABLE
    WRITE_PROTECTION_LEVEL1 = DISABLE
NV_PSEC_FALCON_DIODTA_PRIV_LEVEL_MASK:
    WRITE_PROTECTION_LEVEL0 = DISABLE
    WRITE_PROTECTION_LEVEL1 = DISABLE
```

**No `BCR_PRIV_LEVEL_MASK` (0x111664) on GA100.** This register, which would restrict
RISC-V boot control access to L3-only, is absent from the GA100/TU10X code path. It was
introduced in GA10X (GA102+) which uses the RISC-V boot manifest path. Confirmed absent
from the Booter LOAD binary (needle `64 16 11` not found in 24,320-byte active section).

---

## 5. PPRIV_SYS Decode Trap — Host Isolation During SEC2 RTOS Load

ASB runs as a HS task on GSP-lite and loads the SEC2 RTOS (LS firmware) from WPR1 into
SEC2 IMEM/DMEM. During this load, ASB uses the PPRIV_SYS decode trap subsystem to
prevent any L0/L1/L2 access to SEC2's register space. This is a *transient* lock — it is
armed at the start of `acrSetupLSFalcon_TU10X` and disarmed at `Cleanup:`.

### 5.1 Decode Trap Constants

```c
// acr.h lines 165–167
#define DECODE_TRAP_FOR_FALCON_REG_SPACE_INDEX   (20)
// Decode trap index 20 is dedicated to Falcon register-space isolation (distinct from
// trap 21, which isolates LTC TSTG_CFG_2 to FECS-only via GA100 WAR).

#define DECODE_TRAP_MASK_LSF_FALCON_SEC2  (0xfc003fff)
// SEC2 BAR0 register aperture: 0x840000–0x843fff
// Mask logic: (incoming_addr & ~mask) == match
//   ~0xfc003fff = 0x03ffc000
//   match       = 0x840000
//   Matches any addr where [bits 25:14] == 0x840000[25:14]
//   Effective range: 0x840000 – 0x843FFF (16KB, SEC2 register space on TU10X)
```

### 5.2 `acrLockFalconRegSpaceViaDecodeTrapCommon_TU10X` — Trap Configuration

**Source:** `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c` lines 187–215

```c
// WRITE 1: Set trap action = FORCE_ERROR_RETURN on match
ACR_REG_WR32(BAR0,
    NV_PPRIV_SYS_PRI_DECODE_TRAP_ACTION(20),
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_ACTION, _FORCE_ERROR_RETURN, _ENABLE));

// WRITE 2: Set trap PLM — only L3 may write to trapped range; all levels may read
NvU32 regPlm = ACR_REG_RD32(BAR0, NV_PPRIV_SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK(20));
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _READ_PROTECTION, _ALL_LEVELS_ENABLED, regPlm);
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _WRITE_PROTECTION_LEVEL0, _DISABLE, regPlm);  // L0 writes blocked
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _WRITE_PROTECTION_LEVEL1, _DISABLE, regPlm);  // L1 writes blocked
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _WRITE_PROTECTION_LEVEL2, _DISABLE, regPlm);  // L2 writes blocked
                     // L3 write protection = not set = ENABLE (default) → L3 can write
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _READ_VIOLATION, _REPORT_ERROR, regPlm);
regPlm = FLD_SET_DRF(_PPRIV, _SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK,
                     _WRITE_VIOLATION, _REPORT_ERROR, regPlm);
ACR_REG_WR32(BAR0, NV_PPRIV_SYS_PRI_DECODE_TRAP_PRIV_LEVEL_MASK(20), regPlm);

// WRITE 3: Set trap match config — trap applies to L0/L1/L2 writes; L3 passes; reads ignored
ACR_REG_WR32(BAR0,
    NV_PPRIV_SYS_PRI_DECODE_TRAP_MATCH_CFG(20),
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_MATCH_CFG, _TRAP_APPLICATION_LEVEL0, _ENABLE)  |
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_MATCH_CFG, _TRAP_APPLICATION_LEVEL1, _ENABLE)  |
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_MATCH_CFG, _TRAP_APPLICATION_LEVEL2, _ENABLE)  |
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_MATCH_CFG, _TRAP_APPLICATION_LEVEL3, _DISABLE) |
    DRF_DEF(_PPRIV, _SYS_PRI_DECODE_TRAP_MATCH_CFG, _IGNORE_READ, _IGNORED));
```

### 5.3 `acrLockFalconRegSpace_TU10X` — Address Range Arming

**Source:** `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c` lines 230–244

```c
// First clear the match/mask registers (deactivate any prior trap)
ACR_REG_WR32(BAR0, NV_PPRIV_SYS_PRI_DECODE_TRAP_MASK(20),  0);
ACR_REG_WR32(BAR0, NV_PPRIV_SYS_PRI_DECODE_TRAP_MATCH(20), 0);

if (setTrap == NV_TRUE)
{
    // ARM the trap: match = SEC2 register base (0x840000)
    ACR_REG_WR32(BAR0,
        NV_PPRIV_SYS_PRI_DECODE_TRAP_MATCH(20),
        pFlcnCfg->registerBase);           // 0x840000 for SEC2

    // MASK selects which bits of the address are compared
    // 0xfc003fff means bits [25:14] are the match field
    ACR_REG_WR32(BAR0,
        NV_PPRIV_SYS_PRI_DECODE_TRAP_MASK(20),
        DECODE_TRAP_MASK_LSF_FALCON_SEC2); // 0xfc003fff
}
```

### 5.4 Trap Teardown

At `Cleanup:` in `acrSetupLSFalcon_TU10X`:

```c
// setTrap = NV_FALSE → writes MASK=0, MATCH=0, leaving the trap configured but
// matching no address range (mask=0 means all bits compared, match=0 matches
// only address 0x0 which is not a valid SEC2 register). Effectively disarmed.
acrStatusCleanup = acrlibLockFalconRegSpace_HAL(pAcrlib, LSF_FALCON_ID_GSPLITE,
                                                 &flcnCfg, NV_FALSE,
                                                 &targetMaskPlmOldValue,
                                                 &targetMaskOldValue);
```

The trap is **transient**: it exists only during the interval between SEC2 reset
and the point where SEC2 RTOS is fully loaded into IMEM/DMEM and the decode trap is
released. After teardown, host-driver access to SEC2 register space is no longer
blocked by this trap (though `FALCON_SCTL.AUTH_EN = TRUE` and the PLM locks remain
in effect for the lifetime of the session).

---

## 6. REGIONCFG — Confirmed Dead Code (No FB-DMA Restriction)

**Source:** `uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c` lines 57–73  
**Binary confirmation:** `7-3-phase4-booter-analysis.md` §5

```c
// TODO suppal/derekw: revisit this
// Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot
#if 0
    data = BOOTER_REG_RD32(BAR0, NV_PGSP_FBIF_REGIONCFG);
    for (i = 0; i < NV_PFALCON_FBIF_TRANSCFG__SIZE_1; i++)
    {
        mask = ~(0xF << (i*4));
        data = (data & mask) | ((2 & 0xF) << (i * 4));
    }
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_REGIONCFG, data);    // 0x11066C
#endif
```

`NV_PGSP_FBIF_REGIONCFG` (`0x11066C`) would restrict each GSP-RM FBIF DMA channel
to a specific region type (value `2` = WPR-region-only). The register is never written.
The 3-byte LE needle `6c 06 11` is absent from the 24,320-byte active Booter binary
section, confirming the block is compiled out.

**Effect:** GSP-RM FBIF DMA has no WPR-source restriction. Any transaction that reaches
the FBIF (e.g. a RISC-V load/store or DMA engine command) can target arbitrary
framebuffer addresses, including memory regions outside WPR1/WPR2. This is the root
cause of Weakness W-2 and the GSP-RM → APM_RTS DMA overwrite path described in
`7-4-phase4-ahesasc-apm.md`.

---

## 7. Complete Isolation State After Boot Completes

When AHESASC exits and ASB has completed SEC2 RTOS load, the hardware isolation state is:

```
NV_PFB_PRI_MMU_WPR1_ADDR_LO._VAL = wprStartAddr4K  (WPR1 start, 4K pages)
NV_PFB_PRI_MMU_WPR1_ADDR_HI._VAL = wprEndAddr4K    (WPR1 end-1, 4K pages)
NV_PFB_PRI_MMU_WPR_ALLOW_READ._WPR1    = 0x8   (L3-only outer gate; sub-WPRs govern rest)
NV_PFB_PRI_MMU_WPR_ALLOW_WRITE._WPR1   = 0x8
NV_PFB_PRI_MMU_WPR_ALLOW_READ._MIS_MATCH  = 0x0  (deny read on no-sub-WPR-match)
NV_PFB_PRI_MMU_WPR_ALLOW_WRITE._MIS_MATCH = 0x0  (deny write on no-sub-WPR-match)

Sub-WPR state:
  SEC2   subWPR-0: [WPR1 start..end], RMASK=0xC (L2+L3), WMASK=0xC
  PMU    subWPR-0: [WPR1 start..end], RMASK=0xC,          WMASK=0xC
  GSPlite subWPR-2: [WPR1 start..end], RMASK=0x8 (L3),    WMASK=0x8
  (all other sub-WPRs disabled / at RMASK=0x0 WMASK=0x0)

NV_PGSP_FALCON_SCTL.AUTH_EN           = TRUE  (unauthenticated CPU reg access blocked)
NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK   = 0x8F  (SCTL itself: L3-only write)
NV_PGSP_FALCON_IMEM_PRIV_LEVEL_MASK   = 0x8F  (GSP IMEM: L3-only write)
NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK   = 0xFF  ★W-1: L0-writable, unfixed on GA100★
NV_PGSP_FALCON_CPUCTL_PRIV_LEVEL_MASK = 0x8F  (CPUCTL: L3-only)
NV_PGSP_FBIF_REGIONCFG                = NOT WRITTEN  ★W-2: no DMA source restriction★

PPRIV_SYS decode trap 20:
  ACTION = FORCE_ERROR_RETURN
  PLM    = L0/L1/L2 writes blocked, all reads pass
  MATCH  = 0 (disarmed: matches no valid address after Cleanup:)
  MASK   = 0

PPRIV_SYS decode trap 21 (GA100 WAR — permanent):
  Targets LTC TSTG_CFG_2 (0x140098)
  Applies to ALL privilege levels EXCEPT FECS (via SOURCE_ID inversion)
  ACTION = FORCE_ERROR_RETURN
  → Only FECS can write TSTG_CFG_2
```

---

## 8. Weaknesses Exposed by This Analysis

These are cross-referenced against the master weakness table in `6-2-verification-state-machine.md` §7.

| ID | Register | Defect | Consequence |
|---|---|---|---|
| **W-1** | `NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK` (0x110284) | Set to `0xFF` (READ_L0_WRITE_L0). Source comment: "TODO: TASK_RM fails to come up if this is WRITE_L3" | Any L0 accessor (host driver, any LS falcon with BAR0 access) can DMA-overwrite GSP-RM DMEM. See `7-4-phase4-ahesasc-apm.md` §6 for APM_RTS overwrite path. |
| **W-2** | `NV_PGSP_FBIF_REGIONCFG` (0x11066C) | Never written (`#if 0`). Source comment: "Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot" | GSP-RM FBIF DMA unrestricted — can target any framebuffer address including APM_RTS WPR sub-region. |
| **W-3** | SCP slot 43 (global) | Single LS root-of-trust shared across all GA100 dies. KDF salt `B6 C2 31 E9...` is public. | Compromise of any die's SCP slot 43 secret enables LS signature forgery for all GA100 LS falcons globally (see `6-1-crypto-auth-chain-map.md` §5.6). |
| **W-4** | `GspFwWprMeta.magic` (0xdc3aae21371a60b3) | Developer sanity check, not a cryptographic credential. Magic is not secret. | Any attacker who can write sysmem before Booter's DMA (IOMMU bypass scenario) can supply a crafted WprMeta. |
| **W-5** | WPR2 APM_RTS sub-region | W-1 + W-2 compound. GSP-RM runs at L0, DMEM writable at L0, FBIF DMA unrestricted | GSP-RM can DMA-overwrite APM_RTS in WPR (Confidential Computing attestation state), silently corrupting CC attestation on A100 SXM4 (DevID 0x20B5). |

### 8.1 Open Gap: PMU + SEC2 Unload PLM Teardown

PLM teardown behavior during ACR Unload (PMU and SEC2 teardown path) is not confirmed.
Specifically: whether `FALCON_DMEM_PRIV_LEVEL_MASK` is re-tightened during Unload or
remains at `0xFF` is unknown. If it remains `0xFF` through Unload, any post-Unload
GSP-RM or host-driver interaction with SEC2 DMEM is unrestricted.

---

## 9. Source File Reference

| Source File | Relevance |
|---|---|
| `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c` | `acrLockWpr1DuringACRLoad_TU10X`, `acrLockWpr2DuringACRLoad_TU10X`, `acrLockWprRegionsDuringACRLoad_TU10X`, WPR2 FRTS DMA helpers |
| `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c` | `acrLockFalconRegSpaceViaDecodeTrapCommon_TU10X`, `acrLockFalconRegSpace_TU10X`, `acrSetupLSFalcon_TU10X`, SEC2 CPUCTL STARTCPU |
| `uproc/acr/inc/acr.h` | `DECODE_TRAP_FOR_FALCON_REG_SPACE_INDEX=20`, `DECODE_TRAP_MASK_LSF_FALCON_SEC2=0xfc003fff`, `ACR_SUB_WPR_MMU_*MASK_*`, `ACR_WPR1_REGION_IDX=0` |
| `drivers/resman/arch/nvalloc/common/inc/rmlsfm.h` | `LSF_WPR_REGION_*MASK_*`, `LSF_WPR_EXPECTED_REGION_ID=0x1` |
| `uproc/booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c` | REGIONCFG `#if 0` block, PLM write sequence, GSP-RM SCTL/PLM setup, RISC-V STARTCPU |
| `uproc/acr/src/unload/turing/acr_unload_tu10x.c` | WPR unlock sequence (sub-WPR RMASK/WMASK→0, WPR1 ALLOW→0) |
