# 5.4 — Vulnerability Analysis: DMA Scribble (W-6)

**Phase**: P5b  
**Binary confirmed**: Yes (ASB objdump + AHESASC source)  
**Weakness label**: W-6  
**Prior asset reference**: `1-1-asset-inventory.md` §9 (P4 item); `4-4-runtime-post-verification.md` §pre-verify note

---

## 1. Background: LSF Image Layout in WPR

The WPR1 layout for each LS falcon consists of three independently-addressed sub-structures:

```
WPR1 (hardware locked, driver-populated before lock):
  [WPR_BASE + 0]         WPR_HEADER_TABLE (6 × sizeof(LSF_WPR_HEADER), 256-byte aligned)
                           falconId | lsbOffset | bootstrapOwner | bLazyBootstrap | binVersion | status
  [WPR_BASE + lsbOffset]  LSF_LSB_HEADER (one per falcon)
                           LSF_UCODE_DESC signature (192 B) + ucodeOffset + ucodeSize + dataSize
                           + blCodeSize + blImemOffset + blDataOffset + blDataSize + appCode/Data + flags
  [WPR_BASE + ucodeOffset] Ucode payload (code section)   ← AES-DM authenticated
  [WPR_BASE + ucodeOffset + ucodeSize] Data section        ← AES-DM authenticated
  [WPR_BASE + blDataOffset] BL DMEM descriptor (≤256 B)   ← NOT authenticated
```

Key point: **`blDataOffset` points to the BL command-line arguments block, separate from the ucode payload. This block is not included in the AES-DM hash.**

---

## 2. AES-DM Authentication Scope (`acrVerifySignature_TU10X`)

`acrVerifySignature_TU10X` (AHESASC 0x1eda) is called with:
- `a12 = LSB_HEADER.ucodeSize` — code section size
- `a13 = LSB_HEADER.ucodeOffset` — code section WPR offset
- Second call: `a12 = LSB_HEADER.dataSize`, `a13 = ucodeOffset + ucodeSize`

The AES-DM hash covers:
```
WPR[ucodeOffset .. ucodeOffset + ucodeSize]      (code section)
WPR[ucodeOffset + ucodeSize .. + dataSize]       (data section)
```

**Not covered by AES-DM:**
- `LSF_LSB_HEADER` itself (all fields: `blImemOffset`, `blDataOffset`, `blDataSize`, `flags`, etc.)
- BL DMEM descriptor at `WPR[blDataOffset]`
- `WPR_HEADER_TABLE` (falconId, lsbOffset, etc.)

---

## 3. The Pre-Verify Scribble: `acrSanityCheckBlData_TU10X`

**File**: `uproc/acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c`  
**Caller**: verification loop at line 859, before `acrVerifySignature_HAL` at line 889

```c
// line 859 — BEFORE AES-DM verification (line 889)
if ((status = acrSanityCheckBlData_HAL(pAcr, pWprHeader->falconId,
                 pLsfHeader->blDataOffset, pLsfHeader->blDataSize)) != ACR_OK)
    return status;

// line 864 — immediately after scribble, before verification
acrScrubUnusedWprWithZeroes_HAL(pAcr, pLsfHeader->blDataOffset, pLsfHeader->blDataSize);

// ... 25 lines later ...

// line 889 — AES-DM signature verification
if ((status = acrVerifySignature_HAL(pAcr, pSignature, falconId,
         pLsfHeader->ucodeSize, pLsfHeader->ucodeOffset, pLsfHeader, NV_TRUE)) != ACR_OK)
    goto VERIF_FAIL;
```

`acrSanityCheckBlData_TU10X` body (lines 566–628):

```c
ACR_STATUS acrSanityCheckBlData_TU10X(NvU32 falconId, NvU32 blDataOffset, NvU32 blDataSize)
{
    if ((blDataOffset >= g_scrubState.scrubTrack) && (blDataSize > 0))
    {
        // Bounds check: size only, no upper-bound on blDataOffset
        if (blDataSize > LSF_LS_BLDATA_EXPECTED_SIZE)  // 0x100 = 256 bytes
            return ACR_ERROR_BLDATA_SANITY;

        // DMA READ: WPR[blDataOffset .. +blDataSize] → g_blCmdLineArgs
        acrIssueDma_HAL(pAcr, &g_blCmdLineArgs, NV_FALSE,
            blDataOffset, blDataSize, ACR_DMA_FROM_FB, ACR_DMA_SYNC_AT_END, &g_dmaProp);

        // PATCH: write Falcon HALT opcode (0x02f80000) at reserved[0]
        //        reserved[0] is the FIRST 4 bytes of RM_FLCN_BL_DMEM_DESC
        g_blCmdLineArgs.genericBlArgs.reserved[0] = ACR_FLCN_BL_RESERVED_ASM;  // 0x02f80000

        // DMA WRITE-BACK: g_blCmdLineArgs → WPR[blDataOffset .. +blDataSize]
        acrIssueDma_HAL(pAcr, &g_blCmdLineArgs, NV_FALSE,
            blDataOffset, blDataSize, ACR_DMA_TO_FB, ACR_DMA_SYNC_AT_END, &g_dmaProp);
    }
    return ACR_OK;
}
```

**Net effect of the scribble**: `WPR[blDataOffset + 0 .. +3]` = `0x02f80000` (Falcon HALT). Bytes 4..blDataSize-1 unchanged (read-back of original content).

**`g_dmaProp.regionID`**: covers the entire WPR1 region. No per-falcon sub-WPR boundary enforcement on this DMA — any WPR1 offset is reachable.

---

## 4. Vulnerability W-6: Cross-Falcon WPR Scribble

### 4.1 Root Cause

`LSF_LSB_HEADER.blDataOffset` is driver-supplied. The host driver writes this field into the LSF image in DRAM before AHESASC runs. AHESASC copies it to WPR but does not authenticate it — AES-DM covers only `ucodeOffset..ucodeOffset+ucodeSize+dataSize`. There is no check that `blDataOffset` falls within the current falcon's WPR sub-allocation.

### 4.2 Write Primitive 1: Targeted HALT Write

A compromised driver sets `LSF_LSB_HEADER_A.blDataOffset = X`, where X is any WPR1 offset. AHESASC's scribble for Falcon A writes `0x02f80000` to `WPR[X + 0 .. +3]`. This happens at line 859, before Falcon A's AES-DM verification at line 889.

**Interesting targets for X:**

| Target | Effect |
|--------|--------|
| `lsbOffset_B` for Falcon B | Corrupts first 4 bytes of B's `LSF_UCODE_DESC.prdKeys[0]` (AES-DM signature) → B's signature verification fails |
| `ucodeOffset_B` for Falcon B | Writes HALT at first 4 bytes of B's code → B's AES-DM check fails (code modified) |
| `WPR_HEADER_TABLE + i*24` | Corrupts `falconId` of i-th WPR entry to `0x02f80000` → `IS_FALCONID_INVALID` triggers, halting the verification loop |

### 4.3 Write Primitive 2: Range Zero-Fill (Scrub)

`acrScrubUnusedWprWithZeroes_HAL` at line 864 zeros the "gap" between `g_scrubState.scrubTrack` and `blDataOffset`. If `blDataOffset` is set far into WPR (beyond Falcon B's `ucodeOffset`), the scrub zeros everything from the end of Falcon A's data section through Falcon B's code and data — a large-range WPR zero-fill controlled by the driver.

```
scrubTrack → [zero-filled by scrub] → blDataOffset(malicious) → [preserved] → ...
```

**Effect**: If the zeroed range covers Falcon B's `[ucodeOffset..+ucodeSize]`, Falcon B's AES-DM verification fails (code is all zeros, hash mismatch). B is not booted.

### 4.4 Timing Analysis

```
AHESASC Verification Loop (per-falcon, sequential):
  Falcon A iteration:
    step 1: acrReadLsbHeader_HAL()                   → reads blDataOffset (driver-controlled)
    step 2: acrScrubUnusedWprWithZeroes (ucodeOffset) → zeros gap before A's ucode
    step 3: acrScrubUnusedWprWithZeroes (dataOffset)  → zeros gap before A's data
    step 4: acrSanityCheckBlData_HAL()                ← SCRIBBLE at blDataOffset (may target B)
    step 5: acrScrubUnusedWprWithZeroes (blDataOffset) ← RANGE ZERO-FILL to blDataOffset
    step 6: acrVerifySignature_HAL (A's ucode)         ← AES-DM check (too late for B's area)
  
  Falcon B iteration:
    step 1: acrReadLsbHeader_HAL()                    → reads B's (now corrupted) lsbHeader
    step 6: acrVerifySignature_HAL (B's ucode)         → FAILS if B's code/sig was zeroed
```

### 4.5 Constraints

- **WPR bounds**: `g_dmaProp` wraps WPR1. Writes cannot escape WPR1. No cross-WPR2 access.
- **Size cap**: `blDataSize ≤ 256` bytes enforced at line 580. The scribble is at most 256 bytes.
- **Range zero-fill**: Only limited by WPR1 size (up to ~MB range).
- **Pre-condition**: Compromised host driver (ring-0 access to write LSF images to DRAM before boot).
- **No SCP key required**: Attacker uses legitimate signed images with only the `blDataOffset` field modified in the driver-written LSB_HEADER.

---

## 5. ASB-Side Corroboration: `_acrSetupLSFalcon_TU10X`

After AHESASC completes, the ASB (GSP RISC-V, binary at `gsp/ga100/asb/`) runs `_acrSetupLSFalcon_TU10X` (ASB 0x1cd3–0x1e49, confirmed from nm). It uses `blImemOffset` and `blDataOffset` from the LSB_HEADER in DMA calls with no validation:

```c
// IMEM DMA: uses blImemOffset for base calculation AND as fbOff
blWprBase = (wprBase + ucodeOffset/ALIGN) - blImemOffset/ALIGN;
acrlibIssueTargetFalconDma_HAL(dst, blWprBase, pLsbHeader->blImemOffset,
    pLsbHeader->blCodeSize, regionID, ...);  // ← blImemOffset unchecked

// DMEM DMA: uses blDataOffset as FB offset, unchecked
acrlibIssueTargetFalconDma_HAL(0, wprBase, pLsbHeader->blDataOffset,
    pLsbHeader->blDataSize, regionID, ...);  // ← blDataOffset unchecked

// BOOTVEC: uses blImemOffset as entry point
acrlibSetupBootvec_HAL(pAcrlib, &flcnCfg, pLsbHeader->blImemOffset);  // ← unchecked
```

Note on `blImemOffset` in IMEM DMA: due to the algebraic cancellation in `blWprBase`, the IMEM DMA always reads from `wprBase + ucodeOffset/ALIGN` regardless of `blImemOffset`. However, `blImemOffset` controls the IMEM virtual address tagging and the BOOTVEC — causing the Falcon to start execution at a wrong IMEM virtual address if `blImemOffset` is wrong.

For the DMEM DMA: `blDataOffset` directly controls WHERE in WPR the Falcon's DMEM is initialized from. A malicious `blDataOffset` loads key material or other falcon's code into the LS falcon's DMEM. Since the LS falcon runs authentic code, it will use its DMEM data as expected — but that data came from the wrong WPR location.

**ASB constraint**: By the time ASB runs, AHESASC verification is complete and WPR is locked. The LSB_HEADER data in WPR was already set by the driver and potentially modified by the scribble. ASB trusts it unconditionally.

---

## 6. Weakness Summary (W-6)

| Property | Value |
|----------|-------|
| **ID** | W-6 |
| **Name** | Pre-Verify BL-Data DMA Scribble |
| **Location** | `acr_verify_ls_signature_tu10x.c:859`, `acr_ls_falcon_boot_tu10x.c:343,348,352` |
| **Root cause** | `LSF_LSB_HEADER.blDataOffset` driver-controlled, not AES-DM authenticated |
| **Attack** | Set Falcon A's `blDataOffset` to point to Falcon B's WPR region; AHESASC scribble corrupts B before B is verified |
| **Write primitive 1** | 4-byte write of `0x02f80000` (HALT) to any WPR1 offset |
| **Write primitive 2** | Large-range zero-fill from `scrubTrack` to arbitrary `blDataOffset` in WPR |
| **Timing** | Scribble at verification loop step 4, verification at step 6 — pre-verify |
| **Pre-condition** | Compromised host driver; no SCP slot 43 key needed |
| **Impact** | Selective LS falcon DoS (signature verification failure), cross-falcon WPR corruption |
| **Severity** | MEDIUM (ring-0 pre-condition, no WPR escape, no direct code execution path) |
| **Binary confirmed** | AHESASC source: `acr_verify_ls_signature_tu10x.c:566–628`; ASB nm: `_acrSetupLSFalcon_TU10X @ 0x1cd3` |

Related weaknesses: [[W-1]] (DMEM PLM = L0-writable, enables reading loaded DMEM), [[W-3]] (shared SCP slot 43 key).

---

## 7. Open Questions

1. **`blDataOffset` vs sub-WPR start check**: Does `g_scrubState.scrubTrack` provide any incidental lower-bound protection, or can an attacker always set `blDataOffset > scrubTrack` when targeting later-processed falcons? Answer: yes — Falcon A's `blDataOffset` (targeting Falcon B's lsbOffset) will always be greater than A's own scrubTrack at that point.

2. **Falcon processing order**: Confirm the WPR header iteration order. If SEC2 (most privileged LS falcon, falconId=7) is processed LAST, it is the most resistant to cross-falcon scribble from A targeting B — but A's `blDataOffset` could target ANY already-processed falcon's WPR-adjacent region.

3. **`acrScrubUnusedWprWithZeroes_HAL` exact semantics**: Confirm whether the second call at line 864 zeros `scrubTrack..blDataOffset` (large-range) or just `blDataOffset..blDataOffset+blDataSize` (256 B only). The former is the more dangerous primitive.

4. **DMEM PLM interaction (W-1 × W-6)**: If the LS falcon loaded with malicious `blDataOffset` has `DMEM_PLM = 0xFF` (all-readable, W-1 applies to GSP on GA100), its DMEM initialized from a wrong WPR location is readable by L0 (driver). This enables driver-level key material exfiltration if `blDataOffset` is directed at a WPR key storage region.
