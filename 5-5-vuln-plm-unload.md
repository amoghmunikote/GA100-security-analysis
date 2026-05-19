# 5.5 — Vulnerability Analysis: PLM Unload Teardown

**Phase**: P5a  
**Binary confirmed**: Yes (SEC2 Unload objdump + source + dev_falcon_v4.h)  
**Open gap resolved**: Yes — no new W-level finding  
**Prior references**: `1-1-asset-inventory.md` §9 (P4 item 7); `6-3-wpr-hardware-lockdown.md` §2.3

---

## 1. Question and Scope

The P5a gap asks: when the SEC2 Unload binary tears down WPR and resets LS falcons, does it re-tighten `FALCON_DMEM_PRIV_LEVEL_MASK` to L3-only, or does it leave PMU and SEC2 at a less restrictive value? Specifically:

- **PMU** (falconId=0): DMEM PLM during LS operation = `ACR_PLMASK_READ_L0_WRITE_L2 = 0xCF`
- **SEC2** (falconId=7): DMEM PLM during LS operation = `ACR_PLMASK_READ_L3_WRITE_L3 = 0x88`

---

## 2. Hardware Reset Default for FALCON_DMEM_PRIV_LEVEL_MASK

Source: `drivers/common/inc/hwref/ampere/ga100/dev_falcon_v4.h` line 62.

```c
#define NV_PFALCON_FALCON_DMEM_PRIV_LEVEL_MASK   0x00000284  /* RWI4R */

// Field init values (all marked /* RWI-V */):
READ_PROTECTION   [2:0]  init = ALL_LEVELS_ENABLED = 0x7  → L0/L1/L2 can read
READ_VIOLATION    [3:3]  init = REPORT_ERROR        = 0x1
WRITE_PROTECTION  [6:4]  init = ALL_LEVELS_ENABLED = 0x7  → L0/L1/L2 can write
WRITE_VIOLATION   [7:7]  init = REPORT_ERROR        = 0x1
```

**Hardware reset value = 0xFF** (`ACR_PLMASK_READ_L0_WRITE_L0`).

In the Falcon privilege model, bit=1 in the protection field means the level IS allowed to access (protection for that level is not active). L3 (HS) is always implicitly allowed. So `0xFF` = all levels (L0 through L3) can read and write DMEM.

Any falcon that does not explicitly tighten its DMEM PLM after power-on inherits the permissive 0xFF default. This is the mechanism behind W-1 (GSP DMEM PLM = 0xFF set by Booter — the TODO comment notes it was left at the permissive value because tightening breaks GSP-RM).

---

## 3. Unload Binary: `g_resetPLM` Clarification

**Not** a preset PLM default. `g_resetPLM` (DMEM 0x10000300, 1 byte) is the save-slot for `NV_CSEC_FALCON_RESET_PRIV_LEVEL_MASK._WRITE_PROTECTION` — the register that controls **who can reset SEC2 itself**, not the falcon's DMEM access mask.

Source: `uproc/acr/src/acrshared/turing/acr_helper_functions_tu10x.c:61–110`:

```c
// ACR_UNLOAD_ON_SEC2 path:
reg = ACR_REG_RD32_STALL(CSB, NV_CSEC_FALCON_RESET_PRIV_LEVEL_MASK);
if (bLock) {
    // Save current reset-protection mask
    g_resetPLM = (NvU8)(DRF_VAL(_CSEC, _FALCON_RESET_PRIV_LEVEL_MASK, _WRITE_PROTECTION, reg));
    // Disable L0/L1/L2 reset capability (only HS can reset SEC2 while Unload runs)
    reg = FLD_SET_DRF(_CSEC, ..., _WRITE_PROTECTION_LEVEL0, _DISABLE, reg);
    ...
}
else {
    // Restore saved mask
    reg = FLD_SET_DRF_NUM(_CSEC, ..., _WRITE_PROTECTION, g_resetPLM, reg);
}
```

This is a self-protection mechanism: Unload locks the SEC2 reset register at startup (so ring-0 can't abort the teardown mid-flight) and restores it on exit. Unrelated to LS falcon DMEM PLMs.

---

## 4. PMU Unload Teardown

### 4.1 PLM Before Unload

Set during LS Load by `_acrSetupLSFalcon_TU10X` in the ASB binary (`acr_ls_falcon_boot_tu10x.c:319`):

```c
acrlibFlcnRegLabelWrite_HAL(pAcrlib, &flcnCfg, REG_LABEL_FLCN_DMEM_PRIV_LEVEL_MASK, flcnCfg.dmemPLM);
```

For PMU, `flcnCfg.dmemPLM = ACR_PLMASK_READ_L0_WRITE_L2 = 0xCF` (from `acr_register_access_ga100.c:100` — "Allow read of PMU DMEM to level 0 for debug of PMU code").

**PMU DMEM PLM during operation = 0xCF** (L0 can read, L2+ can write, violations reported).

### 4.2 Unload Reset Sequence

Source: `uproc/acr/src/unload/turing/acr_unload_tu10x.c:33–72`.

```c
ACR_STATUS acrResetFalcon_TU10X(NvU32 falconId)
{
    // Step 1: Bring out of reset (may already be running)
    acrlibBringFalconOutOfReset_HAL(pAcrlib, &flcnCfg);

    // Step 2: Set RESET_LVLM_EN to ensure PLMs will be reset on the next reset event
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _RESET_LVLM_EN, _TRUE, data);
    acrlibFlcnRegLabelWrite_HAL(pAcrlib, &flcnCfg, REG_LABEL_FLCN_SCTL, data);

    // Step 3: Hardware reset — PLMs cleared to hardware defaults (0xFF)
    acrlibPutFalconInReset_HAL(pAcrlib, &flcnCfg, NV_FALSE);

    // Step 4: Bring back out of reset for subsequent non-secure use
    acrlibBringFalconOutOfReset_HAL(pAcrlib, &flcnCfg);
}
```

**Effect on PMU DMEM PLM**: Reset to hardware default = **0xFF** (`ACR_PLMASK_READ_L0_WRITE_L0`).

### 4.3 Ordering: PMU Reset vs WPR Unlock

Source: `uproc/acr/src/unload/nv/acr_unload.c` `acrDeInit` loop:

```c
for (index = 0; index < LSF_FALCON_ID_END; index++) {
    // ACR_UNLOAD_ON_SEC2: skip SEC2 (falconId=7)
    if (pWprHeader->falconId == LSF_FALCON_ID_SEC2) continue;
    acrResetFalcon_HAL(pAcr, pWprHeader->falconId);  // ← PMU reset here
}
acrUnLockAcrRegions_HAL(pAcr);  // ← WPR unlock after all resets
```

**Ordering confirmed**: All LS falcon resets happen BEFORE `acrUnLockAcrRegions_TU10X`. There is a window between PMU reset (PLM=0xFF) and WPR unlock during which:

- PMU DMEM PLM = 0xFF (all levels, including L0, can read AND write)
- WPR1 is still hardware-locked (MMU protection intact)
- PMU has no firmware running (just brought out of reset, idle)

`acrUnLockAcrRegions_TU10X` then clears all sub-WPR configurations and sets WPR1 MMU gate to INVALID + `WPR_ALLOW_READ/WRITE._WPR1 = 0x0`.

### 4.4 Security Assessment: PMU

| Property | Value |
|----------|-------|
| PLM during LS operation | `0xCF` (L0-readable, L2-writable) |
| PLM after Unload reset | `0xFF` (all-levels-readable, all-levels-writable) |
| Window duration | Between `acrResetFalcon_HAL(PMU)` and `acrUnLockAcrRegions_HAL()` |
| WPR state during window | Locked (not yet cleared) |
| PMU firmware state | Halted (idle after reset, no ucode running) |
| PMU DMEM content | Residual runtime state from just-halted firmware |
| L0-read risk | PMU DMEM was already L0-readable during operation (`0xCF`). No new read exposure. |
| L0-write risk | PMU DMEM becomes L0-writable (0xFF) during teardown window. PMU is idle — no active use of DMEM. Attack would require a concurrent L0 write to PMU DMEM in this narrow window, targeting a falcon that isn't running. No meaningful impact. |
| Verdict | **No vulnerability.** Intentional teardown behavior. PMU DMEM L0-writeability during teardown has no exploitable impact given the halted PMU state. |

---

## 5. SEC2 Unload Teardown

### 5.1 Bootstrap Owner Exception

GA100 uses `ACR_UNLOAD_ON_SEC2` — the Unload binary itself runs on SEC2. The `acrDeInit` loop explicitly skips SEC2:

```c
// acr_unload.c:
if (pWprHeader->falconId == LSF_FALCON_ID_SEC2) continue;
```

Binary-confirmed from `g_acruc_ga100_unload.objdump`, `_acrDeInit` (0x266a):
```
cmpbreq.w a10 0x7 0x26b6   // if falconId == 7 (SEC2), skip
```

SEC2 cannot reset itself while executing. The skip is correct and intentional.

### 5.2 PLM Lifecycle

- **During LS Load**: `acrlibGetFalconConfig_GA100` returns `dmemPLM = ACR_PLMASK_READ_L3_WRITE_L3 = 0x88` for SEC2 (default, no override). ASB writes this to SEC2's `FALCON_DMEM_PRIV_LEVEL_MASK`.
- **During Unload**: SEC2 is the running binary — its PLM is the hardware's current state. Not modified by `acrResetFalcon`.
- **After WPR unlock**: `acrUnLockAcrRegions_TU10X` clears all sub-WPR configurations (including SEC2's sub-WPRs) and invalidates WPR1 MMU gate. SEC2 DMEM PLM register is **not touched** — remains `0x88`.

### 5.3 Security Assessment: SEC2

| Property | Value |
|----------|-------|
| PLM during LS operation | `0x88` (L3-only read and write) |
| PLM after Unload | `0x88` (unchanged — SEC2 not reset) |
| WPR state after Unload | Cleared (all sub-WPRs INVALID, WPR1 gate = 0x0) |
| Verdict | **Clean.** SEC2 DMEM PLM stays at maximum restriction throughout. After WPR unlock, WPR protection is gone but SEC2 DMEM PLM is maximally restrictive. |

---

## 6. Fallback: DMEM Range0 Non-Programmable Path

Source: `acr_ls_falcon_boot_tu10x.c:79–90` (ASB, not Unload):

```c
// If RANGE0 register cannot be programmed (sanity read-back fails):
if (rdata != data) {
    acrlibFlcnRegLabelWrite_HAL(pAcrlib, pFlcnCfg, REG_LABEL_FLCN_DMEM_PRIV_LEVEL_MASK,
                               ACR_PLMASK_READ_L0_WRITE_L0);  // 0xFF — all access
}
```

If a falcon's DMEM RANGE0 protection register is non-programmable during LS boot, the ASB falls back to setting `DMEM_PRIV_LEVEL_MASK = 0xFF`. This is a defense-in-depth failure mode that makes DMEM fully open — consistent with the hardware power-on default. This path is not specific to Unload but documents how the permissive default propagates.

---

## 7. Summary

| Falcon | PLM at LS Load | PLM during Unload | Post-Unload WPR state | Finding |
|--------|---------------|-------------------|----------------------|---------|
| PMU (0) | 0xCF (L0-read, L2-write) | Reset → 0xFF (all-access) | WPR cleared | No vulnerability — transient, PMU halted |
| SEC2 (7) | 0x88 (L3-only) | Unchanged (skipped) | WPR cleared | Clean |
| HW default | — | 0xFF (power-on value) | — | Baseline; W-1 occurs when Booter leaves GSP at this default |

**P5a conclusion: No new W-level finding.** The PMU DMEM PLM resets to the hardware default (0xFF) during teardown as an explicit consequence of `SCTL_RESET_LVLM_EN=TRUE`. This is intentional — the Unload binary is designed to fully reset all LS falcons to a clean state. The brief window of PMU DMEM all-access has no exploitable path because PMU firmware is halted and WPR remains locked during that window.

The SEC2 PLM remains at `0x88` (maximally restrictive) throughout the entire Unload sequence and beyond, as SEC2 cannot self-reset.

**Related weaknesses**: [[W-1]] (GSP DMEM PLM = 0xFF, Booter Load path — the Unload behavior here is distinct: it's a deliberate teardown reset, not a load-time security gap).

---

## 8. Register Cross-Reference

| Symbol | Address | Value | Source |
|--------|---------|-------|--------|
| `NV_PFALCON_FALCON_DMEM_PRIV_LEVEL_MASK` | BAR0+0x284 | 0xFF (reset default) | `dev_falcon_v4.h:62` |
| `ACR_PLMASK_READ_L3_WRITE_L3` | — | 0x88 | `acr.h` |
| `ACR_PLMASK_READ_L0_WRITE_L2` | — | 0xCF | `acr.h` |
| `ACR_PLMASK_READ_L0_WRITE_L0` | — | 0xFF | `acr.h` |
| `NV_CSEC_FALCON_RESET_PRIV_LEVEL_MASK` | SEC2 CSB | runtime | `acr_helper_functions_tu10x.c:93` |
| `_g_resetPLM` | DMEM 0x300 | runtime save-slot (reset-protection, not DMEM PLM) | `acr_helper_functions_tu10x.c:46,77` |
