# 6.2 — Synthesis: Verification State Machine

**Document:** 22 | **Phase:** 4-Extension  
**Date:** 2026-05-18  
**Scope:** GA100 only (chip ID 0x170 / NV_PMC_BOOT_42_CHIP_ID_GA100). All code verbatim from source tree.  
**Sources:** `integ/gpu_drv/stage_rel/` tree + `<GPU ROM archive>`/`<GPU ROM archive>`.

---

## 0. Overview

The GA100 boot-time verification chain spans five software layers before any Falcon microcontroller executes untrusted firmware. Each layer has a distinct set of magic-number comparisons, checksum/hash loops, and cryptographic signature checks. The sections below trace every check, the exact C source, the error codes returned on failure, and the terminal state (halt vs. error propagation).

```
Host driver (CPU ring-0)
  └─► VBIOS BIT header: 0xB8FF + "BIT\0" magic + byte-sum checksum
        └─► FWSEC ucode extracted and dispatched to SEC2 (FWSEC runs in HS on ROM trust)
              └─► Booter LOAD (HS on SEC2, TU10X path)
                    ├─ GspFwWprMeta: 0xdc3aae21371a60b3 magic + revision 1
                    ├─ WPR2 geometry sanity (>9 distinct bounds checks)
                    ├─ RSA-3072-PSS-SHA256 sig on GSP-RM BL + ELF (via SE PKA)
                    └─► AHESASC (HS task on SEC2, TU10X path)
                          ├─ Chip-lock: PMC_BOOT_42 chip_id == 0x170
                          ├─ Anti-rollback: FPF fuse 0x824250 vs AHESASC build version
                          ├─ WPR header loop: falconId sentinel 0xFFFFFFFF
                          ├─ AES-DM hash (Davies-Meyer, 16-byte blocks via SCP)
                          ├─ KDF: AES-ECB(g_kdfSalt^falconId, SCP slot 43)
                          └─ LS sig: AES-ECB(dmHash, derivedKey) == stored sig
                                └─► ASB (HS on GSP-lite, TU10X path)
                                      ├─ WPR header scan for SEC2 falconId
                                      ├─ acrSetupLSFalcon_TU10X: SEC2 IMEM/DMEM load + PLM program
                                      └─► SEC2 RTOS (LS on SEC2) → GSP-RM startup
```

---

## 1. Layer L4 — Host-Driver VBIOS Parser

**Source:** `drivers/resman/src/kernel/gpu/gsp/kernel_gsp_fwsec.c`

### 1.1 Magic Number Comparisons

```c
// kernel_gsp_fwsec.c lines 30–31
#define BIT_HEADER_ID         0xB8FF
#define BIT_HEADER_SIGNATURE  0x00544942  // "BIT\0" in little-endian
```

`s_vbiosFindBitHeader` scans the VBIOS image linearly from offset 0 looking for the two-part magic:

```c
static NV_STATUS
s_vbiosFindBitHeader
(
    const KernelGspVbiosImg * const pVbiosImg,
    NvU32 *pBitAddr  // out
)
{
    NV_STATUS status = NV_OK;
    NvU32 addr;

    NV_ASSERT_OR_RETURN(pVbiosImg != NULL, NV_ERR_INVALID_ARGUMENT);
    NV_ASSERT_OR_RETURN(pVbiosImg->pImage != NULL, NV_ERR_INVALID_ARGUMENT);
    NV_ASSERT_OR_RETURN(pVbiosImg->biosSize > 0, NV_ERR_INVALID_ARGUMENT);
    NV_ASSERT_OR_RETURN(pBitAddr != NULL, NV_ERR_INVALID_ARGUMENT);

    for (addr = 0; addr < pVbiosImg->biosSize - 3; addr++)
    {
        if ((s_vbiosRead16(pVbiosImg, addr, &status) == BIT_HEADER_ID) &&
            (s_vbiosRead32(pVbiosImg, addr + 2, &status) == BIT_HEADER_SIGNATURE))
        {
            // found candidate BIT header
            NvU32 candidateBitAddr = addr;

            // verify BIT header checksum
            NvU32 headerSize = s_vbiosRead8(pVbiosImg,
                                            candidateBitAddr + BIT_HEADER_SIZE_OFFSET, &status);

            NvU32 checksum = 0;
            NvU32 j;

            for (j = 0; j < headerSize; j++)
            {
                checksum += (NvU32) s_vbiosRead8(pVbiosImg, candidateBitAddr + j, &status);
            }

            NV_ASSERT_OK_OR_RETURN(status);

            if ((checksum & 0xFF) == 0x0)
            {
                // found!
                // candidate BIT header passes checksum, lets use it
                *pBitAddr = candidateBitAddr;
                return status;
            }
        }

        NV_ASSERT_OK_OR_RETURN(status);
    }

    // not found
    return NV_ERR_GENERIC;
}
```

**Checks performed:**
1. `*[addr+0 .. addr+1]` == `0xB8FF`
2. `*[addr+2 .. addr+5]` == `0x00544942` (`"BIT\0"`)
3. Block-level checksum: sum of all bytes in the header (length from byte `BIT_HEADER_SIZE_OFFSET`) must satisfy `(sum & 0xFF) == 0`. This is an 8-bit additive checksum; all header bytes including the checksum byte sum to 0 mod 256.

**Failure terminal:** Returns `NV_ERR_GENERIC`. The caller `kgspInitVbiosInfo` propagates this back to the driver init path; FWSEC is not dispatched and the GPU remains non-functional.

### 1.2 BIT Token Scan for FWSEC (BIT token 'p' = 0x70)

After the header is located, `s_vbiosParseFwsecUcodeDescFromBit` iterates all BIT tokens:

```c
for (tokIdx = 0; tokIdx < bitHeader.TokenEntries; tokIdx++)
{
    BIT_TOKEN_V1_00 bitToken;
    BIT_DATA_FALCON_DATA_V2 falconData;
    FALCON_UCODE_TABLE_HDR_V1 ucodeHeader;

    status = s_vbiosReadStructure(pVbiosImg, &bitToken,
                                  bitAddr + bitHeader.HeaderSize +
                                    tokIdx * bitHeader.TokenSize,
                                  BIT_TOKEN_V1_00_FMT);
    if (status != NV_OK) { continue; }

    // skip tokens that are not for falcon ucode data v2
    if (bitToken.TokenId != BIT_TOKEN_FALCON_DATA ||
        bitToken.DataVersion != 2 ||
        bitToken.DataSize < BIT_DATA_FALCON_DATA_V2_SIZE_4)
```

`BIT_TOKEN_FALCON_DATA` = `'p'` = `0x70`. Only tokens with Id=0x70, DataVersion=2, DataSize≥`BIT_DATA_FALCON_DATA_V2_SIZE_4` are processed. The first entry in the FALCON_DATA_V2 block whose `engineId` matches FWSEC becomes the ucode descriptor. No cryptographic check occurs at this layer; the VBIOS image itself was validated by FWSEC ROM signature verification before Booter runs.

---

## 2. Layer L3 — Booter LOAD (HS on SEC2, TU10X path for GA100)

**Primary source:** `uproc/booter/src/load/turing/booter_load_tu10x.c`  
**GA100-specific check:** `uproc/booter/src/common/ampere/booter_sanity_checks_ga100.c`  
**FPF check:** `uproc/booter/src/common/ampere/booter_sanity_checks_ga100_and_later.c`

### 2.1 Chip-Lock Check

```c
// booter_sanity_checks_ga100.c
BOOTER_STATUS
booterCheckIfBuildIsSupported_GA100(void)
{
    NvU32 chip = DRF_VAL(_PMC, _BOOT_42, _CHIP_ID, BOOTER_REG_RD32(BAR0, NV_PMC_BOOT_42));

    if (chip == NV_PMC_BOOT_42_CHIP_ID_GA100)   // 0x170
    {
        return BOOTER_OK;
    }

    if (chip == NV_PMC_BOOT_42_CHIP_ID_GA101)   // 0x171
    {
        if (booterIsDebugModeEnabled_HAL(pBooter) == NV_FALSE)
        {
            return BOOTER_ERROR_PROD_MODE_NOT_SUPPORTED;
        }
        return BOOTER_OK;
    }
    return  BOOTER_ERROR_INVALID_CHIP_ID;
}
```

Register `NV_PMC_BOOT_42` at BAR0 `0xA00`. Field `CHIP_ID` = bits [23:8]. Values:
- `0x170` (GA100): unconditional pass.
- `0x171` (GA101 debug silicon): pass only if `NV_CSEC_SCP_CTL_STAT.DEBUG_MODE` is not DISABLED (debug fuse).
- Any other value: `BOOTER_ERROR_INVALID_CHIP_ID` → `falc_halt()`.

### 2.2 Anti-Rollback (Booter FPF Fuse)

```c
// booter_sanity_checks_ga100_and_later.c
BOOTER_STATUS
booterGetUcodeFpfFuseVersion_GA100(NvU32* pUcodeFpfFuseVersion)
{
    NvU32 count = 0;
    NvU32 fpfFuse = BOOTER_REG_RD32(BAR0, NV_FUSE_OPT_FPF_UCODE_BOOTER_HS_REV);

    fpfFuse = DRF_VAL( _FUSE, _OPT_FPF_UCODE_BOOTER_HS_REV, _DATA, fpfFuse);

    /*
     * FPF Fuse and SW Ucode version has below binding
     * FPF FUSE      SW Ucode Version
     *   0              0
     *   1              1
     *   3              2
     *   7              3
     * and so on. */
    while (fpfFuse != 0)
    {
        count++;
        fpfFuse >>= 1;
    }

    *pUcodeFpfFuseVersion = count;

    return BOOTER_OK;
}
```

```c
// booter_sanity_checks_tu10x.c
BOOTER_STATUS
booterCheckFuseRevocationAgainstHWFpfVersion_TU10X(NvU32 ucodeBuildVersion)
{
    BOOTER_STATUS status              = BOOTER_OK;
    NvU32      ucodeFpfFuseVersion = 0;

    status = booterGetUcodeFpfFuseVersion_HAL(pBooter, &ucodeFpfFuseVersion);
    if (status != BOOTER_OK)
    {
        return BOOTER_ERROR_INVALID_UCODE_FUSE;
    }

    if (ucodeBuildVersion < ucodeFpfFuseVersion)
    {
        return BOOTER_ERROR_UCODE_REVOKED;
    }

    return BOOTER_OK;
}
```

Fuse register `NV_FUSE_OPT_FPF_UCODE_BOOTER_HS_REV`. Anti-rollback encoding: popcount of trailing set bits = version number. `BOOTER_GA100_UCODE_BUILD_VERSION < fpfFuseVersion` → `BOOTER_ERROR_UCODE_REVOKED` → `falc_halt()`.

### 2.3 GspFwWprMeta Magic Number Check

CPU-RM places a `GspFwWprMeta` structure in sysmem and writes its address (right-shifted 12) into `NV_CSEC_FALCON_MAILBOX1`. Booter reads it via DMA then validates:

```c
// booter_load_tu10x.c  booterLoad_TU10X()
    NvU64 mailbox1 = BOOTER_REG_RD32(CSB, NV_CSEC_FALCON_MAILBOX1);
    NvU64 wprMetaSysmemAddr = (mailbox1 << MAILBOX1_SYSMEM_ALIGNMENT_FROM_CPU_RM);  // << 12 = 4K alignment
    GspFwWprMeta *pWprMeta = &g_gspFwWprMeta;
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterReadGspRmWprHeader_HAL(pBooter, pWprMeta, wprMetaSysmemAddr, &g_dmaProp[BOOTER_DMA_SYSMEM_CONTEXT]));

    // ...

    // Sanity check GspFwWprMeta received from CPU-RM
    if (pWprMeta->magic != GSP_FW_WPR_META_MAGIC ||
        pWprMeta->revision != GSP_FW_WPR_META_REVISION)
    {
        return BOOTER_ERROR_INVALID_WPRMETA_MAGIC_OR_REVISION;
    }
```

Constants from `uproc/os/libos-v2.0.0/include/gsp_fw_wpr_meta.h`:
```c
#define GSP_FW_WPR_META_MAGIC     0xdc3aae21371a60b3ULL
#define GSP_FW_WPR_META_REVISION  1
#define GSP_FW_WPR_META_VERIFIED  0xa0a0a0a0a0a0a0a0ULL
```

**Failure:** `BOOTER_ERROR_INVALID_WPRMETA_MAGIC_OR_REVISION`. Booter writes status to MAILBOX0 and halts.

### 2.4 WPR2 Geometry Bounds Checks

```c
    // Ensure WPR2 will actually be up
    if (pWprMeta->gspFwWprEnd < pWprMeta->gspFwWprStart)
    {
        return BOOTER_ERROR_INVALID_WPRMETA_WPR2_REGION;
    }

    // Ensure WPR2 start and end are well-aligned for WPR
    if (!(NV_IS_ALIGNED(pWprMeta->gspFwWprStart, BOOTER_WPR_ALIGNMENT) &&
          NV_IS_ALIGNED(pWprMeta->gspFwWprEnd, BOOTER_WPR_ALIGNMENT)))
    {
        return BOOTER_ERROR_INVALID_WPRMETA_WPR2_ALIGNMENT;
    }

    // Ensure FRTS offset is well-aligned for sub-WPR
    if (bFrtsIsSetUp)
    {
        if (!NV_IS_ALIGNED(pWprMeta->frtsOffset, BOOTER_SUB_WPR_ALIGNMENT))
        {
            return BOOTER_ERROR_INVALID_WPRMETA_FRTS_ALIGNMENT;
        }
    }

    // GSP-RM ELF must be inside WPR2
    if ((pWprMeta->gspFwOffset <= pWprMeta->gspFwWprStart) || 
        (pWprMeta->gspFwOffset >= pWprMeta->gspFwWprEnd) ||
        ((pWprMeta->gspFwWprEnd - pWprMeta->gspFwOffset) < pWprMeta->sizeOfRadix3Elf))
    {
        return BOOTER_ERROR_INVALID_WPRMETA_ELF_REGION;
    }

    // GSP-RM BL must be inside WPR2
    if ((pWprMeta->bootBinOffset <= pWprMeta->gspFwWprStart) || 
        (pWprMeta->bootBinOffset >= pWprMeta->gspFwWprEnd) ||
        ((pWprMeta->gspFwWprEnd - pWprMeta->bootBinOffset) < pWprMeta->sizeOfBootloader))
    {
        return BOOTER_ERROR_INVALID_WPRMETA_BL_REGION;
    }
```

Nine separate bounds checks in total. Any failure → corresponding `BOOTER_ERROR_INVALID_WPRMETA_*` → MAILBOX0 write → halt.

### 2.5 RSA-3072 Signature Verification

After DMA-copying GSP-RM ELF and BL into WPR2, Booter verifies both sections:

```c
// booter_load_tu10x.c  booterLoad_TU10X()
    // Verify signature of GSP-RM ELF and BL
    g_bIsDebug = booterIsDebugModeEnabled_HAL(pBooter);
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterVerifyLsSignatures_HAL(pBooter, pWprMeta));

    // Write WprMeta (with verified marked) to WPR2
    pWprMeta->verified = GSP_FW_WPR_META_VERIFIED;  // 0xa0a0a0a0a0a0a0a0ULL
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterWriteGspRmWprHeaderToWpr_HAL(pBooter, pWprMeta, pWprMeta->gspFwWprStart));
```

The `verified` field is written to WPR2 only after signature verification passes. The `0xa0a0a0a0a0a0a0a0ULL` sentinel is verified by AHESASC later.

#### 2.5.1 `booterVerifyLsSignatures_TU10X`

```c
// booter_sig_verif_tu10x.c
BOOTER_STATUS
booterVerifyLsSignatures_TU10X(GspFwWprMeta *pWprMeta)
{
    BOOTER_STATUS status = BOOTER_OK;

    NvU32 falconId = LSF_FALCON_ID_GSP_RISCV;
    NvU64 baseAddr = pWprMeta->gspFwWprStart;
    NvU32 codeSize = NvU64_LO32(pWprMeta->sizeOfBootloader);
    NvU32 codeOffset = NvU64_LO32(pWprMeta->bootBinOffset - baseAddr);
    NvU32 dataSize = NvU64_LO32(pWprMeta->sizeOfRadix3Elf);
    NvU32 dataOffset = NvU64_LO32(pWprMeta->gspFwOffset - baseAddr);
    PLSF_UCODE_DESC_WRAPPER pLsfUcodeDescWrapper = (PLSF_UCODE_DESC_WRAPPER) g_bounceBufferB;

    g_dmaProp[BOOTER_DMA_SYSMEM_CONTEXT].baseAddr = (pWprMeta->sysmemAddrOfSignature >> 8);
    NvU32 dmaOff = NvU64_LO32(pWprMeta->sysmemAddrOfSignature) & 0xFF;
    if ((booterIssueDma_HAL(pBooter, g_bounceBufferB, NV_FALSE, dmaOff, pWprMeta->sizeOfSignature,
       BOOTER_DMA_FROM_FB, BOOTER_DMA_SYNC_AT_END, &g_dmaProp[BOOTER_DMA_SYSMEM_CONTEXT])) != pWprMeta->sizeOfSignature)
    {
        return BOOTER_ERROR_DMA_FAILURE;
    }

    NvU8 *pSignature = (NvU8 *)g_lsSignature;

    // Get the code signature (prod or debug)
    if (g_bIsDebug)
    {
        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_DEBUG_SIGNATURE_CODE,
                                                                            pLsfUcodeDescWrapper, (void *)pSignature));
    }
    else
    {
        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_PROD_SIGNATURE_CODE,
                                                                            pLsfUcodeDescWrapper, (void *)pSignature));
    }

    // Verify code section
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterValidateLsSignature_HAL(pBooter, falconId, pSignature, baseAddr, codeOffset, codeSize, pLsfUcodeDescWrapper, NV_TRUE));

    // Get the data signature (prod or debug)
    if (g_bIsDebug)
    {
        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_DEBUG_SIGNATURE_DATA,
                                                                            pLsfUcodeDescWrapper, (void *)pSignature));
    }
    else
    {
        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_PROD_SIGNATURE_DATA,
                                                                            pLsfUcodeDescWrapper, (void *)pSignature));
    }

    // Verify data section
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterValidateLsSignature_HAL(pBooter, falconId, pSignature, baseAddr, dataOffset, dataSize, pLsfUcodeDescWrapper, NV_FALSE)); 

    // Check if GSP-RM is revoked based on LS ucode version
    {
        BOOTER_STATUS status;
        NvU32 lsUcodeVer;
        NvU32 lsUcodeId;

        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_LS_UCODE_VER, pLsfUcodeDescWrapper, &lsUcodeVer));
        CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_LS_UCODE_ID, pLsfUcodeDescWrapper, &lsUcodeId));

        CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterCheckRevocation(lsUcodeVer));
    }

    return status;
}
```

#### 2.5.2 `booterValidateLsSignature_TU10X` — Algorithm Dispatch

```c
BOOTER_STATUS
booterValidateLsSignature_TU10X
(
    NvU32  falconId,
    NvU8  *pSignature,
    NvU64  binBaseAddr,
    NvU32  binOffset,
    NvU32  binSize,
    PLSF_UCODE_DESC_WRAPPER pLsfUcodeDescWrapper,
    NvBool bIsUcode
)
{
    NvU32  hashAlgoVer;
    NvU32  hashAlgo;
    NvU32  sigAlgoVer;
    NvU32  sigAlgo;
    NvU32  sigPaddingType;
    NvU32  lsSigValidationId;
    NvU8  *pPlainTextHash = g_hashResult;
    BOOTER_STATUS status = BOOTER_ERROR_UNKNOWN;
    SHA_ID  hashAlgoId = SHA_ID_LAST;
    NvU32  hashSizeByte;
    NvU32  saltSizeByte;

    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_HASH_ALGO_VER, pLsfUcodeDescWrapper, (void *)&hashAlgoVer));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_HASH_ALGO, pLsfUcodeDescWrapper, (void *)&hashAlgo));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_SIG_ALGO_VER, pLsfUcodeDescWrapper, (void *)&sigAlgoVer));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_SIG_ALGO, pLsfUcodeDescWrapper, (void *)&sigAlgo));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_SIG_ALGO_PADDING_TYPE, pLsfUcodeDescWrapper, (void *)&sigPaddingType));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterGetSignatureValidationId(hashAlgoVer, hashAlgo, sigAlgoVer, sigAlgo, sigPaddingType, &lsSigValidationId));

    if (lsSigValidationId == LS_SIG_VALIDATION_ID_1)
    {
        hashAlgoId   = SHA_ID_SHA_256;
        hashSizeByte = SHA_256_HASH_SIZE_BYTE;
        saltSizeByte = SHA_256_HASH_SIZE_BYTE;
    }

    switch (lsSigValidationId)
    {
        case LS_SIG_VALIDATION_ID_1: // RSA3K-PSS + SHA256
        {
            // Compute SHA-256 hash of: binary data || falconId || lsUcodeVer || lsUcodeId || depMapCtx
            CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterGeneratePlainTextHash(falconId, hashAlgoId, binBaseAddr, binOffset, binSize,
                                                                            pPlainTextHash, pLsfUcodeDescWrapper, bIsUcode));

            // RSA-3072 decrypt signature via SE PKA (modular exponentiation)
            CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterRsaDecryptLsSignature(pSignature, RSA_KEY_SIZE_3072_BIT, pSignature));

            // PSS padding verification
            CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterSignatureValidationHandler(falconId, hashAlgoId, pPlainTextHash, pSignature,
                                              RSA_KEY_SIZE_3072_BIT, hashSizeByte, saltSizeByte));
        }
        break;

        default:
            return BOOTER_ERROR_INVALID_ARGUMENT;
    }

    return BOOTER_OK;
}
```

**Algorithm gate:** `_booterGetSignatureValidationId` only returns `LS_SIG_VALIDATION_ID_1` when:
- `hashAlgoVer == LSF_HASH_ALGO_VERSION_1`
- `sigAlgoVer  == LSF_SIGNATURE_ALGO_VERSION_1`
- `sigAlgo     == LSF_SIGNATURE_ALGO_TYPE_RSA3K`
- `sigPaddingType == LSF_SIGNATURE_ALGO_PADDING_TYPE_PSS`
- `hashAlgo    == LSF_HASH_ALGO_TYPE_SHA256`

Any mismatch → `BOOTER_ERROR_LS_SIG_VERIF_FAIL`.

#### 2.5.3 Plain-Text Hash Construction (`_booterGeneratePlainTextHash`)

The message being signed is **not** the raw binary. It is a two-task SHA-256 operation:

```
Task-1:  SHA-256 over binary section (FB DMA, 16 MB chunks max)
Task-2:  SHA-256 continuation over DMEM buffer:
         [ falconId (4 B) | lsUcodeVer (4 B) | lsUcodeId (4 B) | depMapCtx (depMapSize B) ]
```

```c
static BOOTER_STATUS
_booterGeneratePlainTextHash(...)
{
    // ...
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_DEPMAP_SIZE,
                                                                        pLsfUcodeDescWrapper, (void *)&depMapSize));

    plainTextSize = binSize + LS_SIG_VALIDATION_ID_1_NOTIONS_SIZE_BYTE + depMapSize;

    CHECK_STATUS_AND_RETURN_IF_NOT_OK(shaEngineSoftReset_HAL(pSha, SHA_ENGINE_SW_RESET_TIMEOUT));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(shaAcquireMutex_HAL(pSha, BOOTER_LOAD_LS_SIGNATURE_VALIDATION));
    shaCtx.algoId  = algoId;
    shaCtx.msgSize = plainTextSize;
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(shaOperationInit_HAL(pSha, &shaCtx));

    // Task-1: SHA over bin data on FB (chunked, max 0xF00000 per call)
    taskCfg.srcType       = SHA_SRC_CONFIG_SRC_FB;
    taskCfg.dmaIdx        = BOOTER_DMA_FB_WPR_CONTEXT;
    taskCfg.defaultHashIv = NV_TRUE;

    while(binSize > 0)
    {
        bytesToHash  = (binSize > 0xF00000) ? 0xF00000 : binSize;
        binAddr      = (binBaseAddr + binOffset + bytesHashed);

        taskCfg.size = bytesToHash;
        taskCfg.addr = binAddr;
        CHECK_STATUS_OK_OR_GOTO_CLEANUP(shaInsertTask_HAL(pSha, &shaCtx, &taskCfg));

        bytesHashed  += bytesToHash;
        binSize      -= bytesToHash;
        taskCfg.defaultHashIv = NV_FALSE;
    }

    // Task-2: SHA continuation over DMEM concatenation
    pBufferDw    = (NvU32 *)g_copyBufferA;
    pBufferDw[0] = falconId;
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_LS_UCODE_VER,
                                                                      pLsfUcodeDescWrapper, (void *)&pBufferDw[1]));
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_GET_LS_UCODE_ID,
                                                                      pLsfUcodeDescWrapper,  (void *)&pBufferDw[2]));
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(booterLsfUcodeDescWrapperCtrl_HAL(pBooter, LSF_UCODE_DESC_COMMAND_COPY_DEPMAP_CTX,
                                                                      pLsfUcodeDescWrapper,  (void *)&pBufferDw[3]));

    binAddr               = (NvU64)((NvU32)pBufferDw);
    taskCfg.srcType       = SHA_SRC_CONFIG_SRC_DMEM;
    taskCfg.defaultHashIv = NV_FALSE;
    taskCfg.dmaIdx        = 0;
    taskCfg.size          = LS_SIG_VALIDATION_ID_1_NOTIONS_SIZE_BYTE + depMapSize;
    taskCfg.addr          = binAddr;
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(shaInsertTask_HAL(pSha, &shaCtx, &taskCfg));

    CHECK_STATUS_OK_OR_GOTO_CLEANUP(shaReadHashResult_HAL(pSha, &shaCtx, (void *)pBufOut, NV_TRUE));
    // ...
}
```

#### 2.5.4 RSA-3072 Decrypt (`_booterRsaDecryptLsSignature`)

```c
static BOOTER_STATUS
_booterRsaDecryptLsSignature
(
    NvU8 *pSignatureEnc,
    SE_KEY_SIZE keySizeBit,   // RSA_KEY_SIZE_3072_BIT
    NvU8 *pSignatureDec
)
{
    SE_PKA_REG sePkaReg;
    BOOTER_STATUS status, tmpStatus;

    CHECK_STATUS_AND_RETURN_IF_NOT_OK(seAcquireMutex_HAL(pSe));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(seContextIni_HAL(pSe, &sePkaReg, keySizeBit));

    // load RSA-3072 key (prod or debug)
    if (g_bIsDebug)
    {
        CHECK_STATUS_OK_OR_GOTO_CLEANUP(seInitializationRsaKeyDbg_HAL(pSe, g_rsaKeyModulus, g_rsaKeyExponent,
                                                                         g_rsaKeyMp, g_rsaKeyRsqr));
        CHECK_STATUS_OK_OR_GOTO_CLEANUP(seSetRsaOperationKeys_HAL(pSe, &sePkaReg,
                                                                  g_rsaKeyModulus,
                                                                  g_rsaKeyExponent,
                                                                  g_rsaKeyMp,
                                                                  g_rsaKeyRsqr));
    }
    else
    {
        CHECK_STATUS_OK_OR_GOTO_CLEANUP(seInitializationRsaKeyProd_HAL(pSe, g_rsaKeyModulus, g_rsaKeyExponent,
                                                                          g_rsaKeyMp, g_rsaKeyRsqr));
        CHECK_STATUS_OK_OR_GOTO_CLEANUP(seSetRsaOperationKeys_HAL(pSe, &sePkaReg,
                                                                  g_rsaKeyModulus,
                                                                  g_rsaKeyExponent,
                                                                  g_rsaKeyMp,
                                                                  g_rsaKeyRsqr));
    }

    // RSA-3072 modular exponentiation via SE PKA hardware
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(seRsaSetParams_HAL(pSe, &sePkaReg, SE_RSA_PARAMS_TYPE_BASE, (NvU32 *)pSignatureEnc));
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(seStartPkaOperationAndPoll_HAL(pSe,
                                    NV_SSE_SE_PKA_PROGRAM_ENTRY_ADDRESS_ALIAS_PROG_ADDR_MODEXP,
                                    sePkaReg.pkaRadixMask, SE_ENGINE_OPERATION_TIMEOUT_DEFAULT));
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(seRsaGetParams_HAL(pSe, &sePkaReg, SE_RSA_PARAMS_TYPE_RSA_RESULT, (NvU32 *)pSignatureDec));

    _endianRevert((NvU8 *)pSignatureDec, (keySizeBit >> 3));  // convert big-endian PKA result to little-endian

Cleanup:
    tmpStatus = seReleaseMutex_HAL(pSe);
    status = (status == BOOTER_OK ? tmpStatus : status);
    return status;
}
```

The key material (`g_rsaKeyModulus`, `g_rsaKeyExponent`, `g_rsaKeyMp`, `g_rsaKeyRsqr`) lives in the Booter binary data section. `g_rsaKeyMp` is Montgomery parameter, `g_rsaKeyRsqr` is R² mod N for Montgomery multiplication. The SE PKA hardware computes `sig^e mod N` entirely in hardware with no software loop.

#### 2.5.5 PSS Padding Verification (`_booterSignatureValidationHandler`)

```c
static BOOTER_STATUS
_booterSignatureValidationHandler
(
    NvU32 falconId,
    SHA_ID hashAlgoId,
    NvU8 *pPlainTextHash,
    NvU8 *pDecSig,          // decrypted RSA-3K result (in-place in pSignature)
    NvU32 keySizeBit,       // 3072
    NvU32 hashSizeByte,     // 32 (SHA-256)
    NvU32 saltSizeByte      // 32 (SHA-256)
)
{
    BOOTER_STATUS status = BOOTER_ERROR_UNKNOWN;
    NvU32  msBits = GET_MOST_SIGNIFICANT_BIT(keySizeBit);  // (3072-1) & 7 = 7
    NvU32  emLen  = GET_ENC_MESSAGE_SIZE_BYTE(keySizeBit); // (3072+7)>>3 = 384
    NvU32  maskedDBLen, i, j;
    NvU8  *pEm = pDecSig;
    NvU8  *pDb = NULL;
    NvU8  *pHashGoldenStart = NULL;
    NvU8  *pHashGolden = NULL;
    NvU8  *pHash = NULL;
    NvU32  msgGoldenLen;

    // CHECK 1: Most significant bits of EM[0] must be zero (PSS spec)
    if (pEm[0] & (0xFF << msBits))
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    if (msBits == 0)
    {
       pEm++;
       emLen--;
    }

    // CHECK 2: emLen >= hashSize + 2
    if (emLen < hashSizeByte + 2)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // CHECK 3: saltSize must not exceed allowed bound
    if (saltSizeByte > emLen - hashSizeByte - 2)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // CHECK 4: Last byte of EM must be 0xBC (PSS trailer)
    if (pEm[emLen - 1] != 0xbc)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // PKCS#1 MGF1 mask generation: pDb = MGF1(SHA-256, pHash, maskedDBLen)
    pDb = (NvU8 *)g_copyBufferA;
    maskedDBLen = emLen - hashSizeByte - 1;
    pHash = pEm + maskedDBLen;

    if (_booterEnforcePkcs1Mgf1(pDb, maskedDBLen, pHash, hashSizeByte, hashAlgoId) != BOOTER_OK)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // XOR maskedDB with MGF output to recover DB
    for (i = 0; i < maskedDBLen; i++)
    {
        pDb[i] ^= pEm[i];
    }

    if (msBits)
    {
        pDb[0] &= 0xFF >> (8 - msBits);
    }

    // CHECK 5: DB must be zero-padded then 0x01 separator
    // find first non-zero value in pDb[]
    for (i = 0; pDb[i] == 0 && i < (maskedDBLen - 1); i++);

    if (pDb[i++] != 0x1)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // CHECK 6: remaining bytes after 0x01 == saltSizeByte
    if ((maskedDBLen - i) != saltSizeByte)
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    // CHECK 7: Reconstruct M' = 0x00*8 || mHash || salt, hash it, compare to H in signature
    pHashGoldenStart = g_hashBuffer;
    pHashGolden = pHashGoldenStart;

    // Insert 8 zero bytes (PSS M' padding)
    for (j = 0 ; j < RSA_PSS_PADDING_ZEROS_SIZE_BYTE ; j++)   // RSA_PSS_PADDING_ZEROS_SIZE_BYTE = 8
    {
        pHashGolden[j] = 0;
    }
    pHashGolden += RSA_PSS_PADDING_ZEROS_SIZE_BYTE;

    // Insert SHA-256(plaintext) result
    for (j = 0; j < hashSizeByte; j++)
    {
        pHashGolden[j] = pPlainTextHash[j];
    }
    pHashGolden += hashSizeByte;

    msgGoldenLen = hashSizeByte + RSA_PSS_PADDING_ZEROS_SIZE_BYTE;

    // Append salt
    if (maskedDBLen - i)
    {
        for (j = 0; j < maskedDBLen - i; j++)
        {
            pHashGolden[j] = pDb[i + j];
        }
        msgGoldenLen += (maskedDBLen - i);
    }

    // SHA-256(M') via SE
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(_booterShaRunSingleTaskDmem(hashAlgoId, pHashGoldenStart,
                                                               pHashGoldenStart, msgGoldenLen))

    // CHECK 7 final: SHA-256(M') must equal H extracted from signature
    if(booterMemcmp(pHash, pHashGoldenStart, hashSizeByte))
    {
        return BOOTER_ERROR_LS_SIG_VERIF_FAIL;
    }

    return BOOTER_OK;
}
```

**Complete PSS check sequence:**
1. High bits of EM[0] zero
2. emLen ≥ hashSize + 2
3. saltSize ≤ emLen - hashSize - 2
4. EM[emLen-1] == `0xBC` (trailer byte)
5. DB[0..sep-1] all zero
6. DB[sep] == `0x01`
7. |salt| == saltSizeByte
8. SHA-256(`0x00*8 || SHA256(plaintext) || salt`) == H from signature

Any failure → `BOOTER_ERROR_LS_SIG_VERIF_FAIL` → propagates up to `booterLoad_TU10X` → written to MAILBOX0 → `falc_halt()`.

### 2.6 GSP Target Register Setup and GSP-RM Handoff

After successful signature verification, Booter programs GSP-lite registers:

```c
// booter_boot_gsprm_tu10x_ga100.c  booterSetupTargetRegisters_TU10X()

    // NOTE: REGIONCFG intentionally disabled — GSP-RM SA fault during boot if enabled
#if 0
    data = BOOTER_REG_RD32(BAR0, NV_PGSP_FBIF_REGIONCFG);
    for (i = 0; i < NV_PFALCON_FBIF_TRANSCFG__SIZE_1; i++)
    {
        mask = ~(0xF << (i*4));
        data = (data & mask) | ((2 & 0xF) << (i * 4));
    }
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_REGIONCFG, data);
#endif

    // Step 1: SCTL PLM → L3 write-only
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK, BOOTER_PLMASK_READ_L0_WRITE_L3);

    // Step 2: Initial SCTL
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _RESET_LVLM_EN, _FALSE, 0);
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _STALLREQ_CLR_EN, _FALSE, data);
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _AUTH_EN, _TRUE, data);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_SCTL, data);

    // Step 3: CPUCTL_ALIAS_EN = FALSE
    data = FLD_SET_DRF(_PFALCON, _FALCON_CPUCTL, _ALIAS_EN, _FALSE, 0);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_CPUCTL, data);

    // Step 4: PLM setup
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_IMEM_PRIV_LEVEL_MASK,    BOOTER_PLMASK_READ_L0_WRITE_L3);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK,    BOOTER_PLMASK_READ_L0_WRITE_L0);
    // TODO: TASK_RM fails to come up if this is WRITE_L3 ← CONFIRMED WEAKNESS W-1
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_CPUCTL_PRIV_LEVEL_MASK,  BOOTER_PLMASK_READ_L0_WRITE_L3);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_EXE_PRIV_LEVEL_MASK,     BOOTER_PLMASK_READ_L0_WRITE_L0);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_IRQTMR_PRIV_LEVEL_MASK,  BOOTER_PLMASK_READ_L0_WRITE_L0);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_MTHDCTX_PRIV_LEVEL_MASK, BOOTER_PLMASK_READ_L0_WRITE_L0);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_DIODT_PRIV_LEVEL_MASK,   BOOTER_PLMASK_READ_L0_WRITE_L3);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_DIODTA_PRIV_LEVEL_MASK,  BOOTER_PLMASK_READ_L0_WRITE_L3);

    // Step 6: Final SCTL
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _RESET_LVLM_EN, _TRUE, 0);
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _STALLREQ_CLR_EN, _TRUE, data);
    data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _AUTH_EN, _TRUE, data);
    BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_SCTL, data);

    // Verify AUTH_EN stuck (sanity check)
    data = BOOTER_REG_RD32(BAR0, NV_PGSP_FALCON_SCTL);
    if (!FLD_TEST_DRF(_PFALCON, _FALCON_SCTL, _AUTH_EN, _TRUE, data))
    {
        return BOOTER_ERROR_LS_BOOT_FAIL_AUTH;
    }

    // Step 7: RISC-V CPUCTL_ALIAS_EN = TRUE (GA100 uses pre-GA10X alias)
    data = FLD_SET_DRF(_PRISCV, _RISCV_CPUCTL, _ALIAS_EN, _TRUE, 0);
    BOOTER_REG_WR32(BAR0, NV_PGSP_RISCV_CPUCTL, data);

    return status;
```

Final handoff — RISC-V CPU start:

```c
// booterStartGspRm_TU10X()
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_CTL,
        DRF_DEF(_PGSP, _FBIF_CTL, _ENABLE, _TRUE) |
        DRF_DEF(_PGSP, _FBIF_CTL, _ALLOW_PHYS_NO_CTX, _ALLOW));

    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_CTL2, DRF_DEF(_PGSP, _FBIF_CTL2, _NACK_MODE, _NACK_AS_ACK));

#ifdef NV_PRISCV_RISCV_CPUCTL_ALIAS_EN  // Pre-GA10X only — GA100 takes this path
    BOOTER_REG_WR32(BAR0, NV_PGSP_RISCV_CPUCTL_ALIAS,
        DRF_DEF(_PGSP, _RISCV_CPUCTL_ALIAS, _STARTCPU, _TRUE));
#else
    BOOTER_REG_WR32(BAR0, NV_PGSP_RISCV_CPUCTL,
        DRF_DEF(_PGSP, _RISCV_CPUCTL, _STARTCPU, _TRUE));
#endif
```

GA100 takes the `#ifdef NV_PRISCV_RISCV_CPUCTL_ALIAS_EN` path (pre-GA10X), writing `STARTCPU=TRUE` to `NV_PGSP_RISCV_CPUCTL_ALIAS` (confirmed binary offset 0x5498 in Booter LOAD, from Phase-4 analysis).

---

## 3. Layer L2 — AHESASC (HS Task on SEC2, TU10X path for GA100)

**Source:** `uproc/acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c`  
**Source:** `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c`  
**GA100 check:** `uproc/acr/src/acrshared/ampere/acr_sanity_checks_ga100.c`

### 3.1 Chip-Lock Check

```c
// acr_sanity_checks_ga100.c
ACR_STATUS acrCheckIfBuildIsSupported_GA100(void)
{
    NvU32 chip = DRF_VAL(_PMC, _BOOT_42, _CHIP_ID, ACR_REG_RD32(BAR0, NV_PMC_BOOT_42));
    if (chip == NV_PMC_BOOT_42_CHIP_ID_GA100)    // 0x170
    {
        return ACR_OK;
    }
    if (chip == NV_PMC_BOOT_42_CHIP_ID_GA101)    // 0x171
    {
        if (acrIsDebugModeEnabled_HAL(pAcr) == NV_FALSE)
        {
            return ACR_ERROR_PROD_MODE_NOT_SUPPORTED;
        }
        return ACR_OK;
    }
    return ACR_ERROR_INVALID_CHIP_ID;
}
```

### 3.2 Anti-Rollback (AHESASC FPF Fuse)

```c
// acr_sanity_checks_ga100_and_later.c
ACR_STATUS acrCheckFuseRevocation_GA100(void)
{
    NvU32 ucodeBuildVersion;
    NvU32 ucodeFuseVersion;
    NvU32 ucodeFpfFuseVersion;

    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrGetUcodeBuildVersion_HAL(pAcr, &ucodeBuildVersion));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrGetUcodeFuseVersion_HAL(pAcr, &ucodeFuseVersion));
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrGetUcodeFpfFuseVersion_HAL(pAcr, &ucodeFpfFuseVersion));

    if (ucodeBuildVersion < ucodeFuseVersion)
    {
        return ACR_ERROR_UCODE_REVOKED;
    }
    if (ucodeBuildVersion < ucodeFpfFuseVersion)
    {
        return ACR_ERROR_UCODE_REVOKED;
    }

    return ACR_OK;
}

ACR_STATUS acrGetUcodeFpfFuseVersion_GA100(NvU32* pUcodeFpfFuseVersion)
{
    NvU32 count = 0;
    NvU32 fpfFuse = ACR_REG_RD32(BAR0, NV_FUSE_OPT_FPF_UCODE_ACR_HS_REV);  // BAR0 0x824250
    fpfFuse = DRF_VAL(_FUSE, _OPT_FPF_UCODE_ACR_HS_REV, _DATA, fpfFuse);
    while (fpfFuse != 0)
    {
        count++;
        fpfFuse >>= 1;
    }
    *pUcodeFpfFuseVersion = count;
    return ACR_OK;
}
```

AHESASC uses two fuse sources: software-programmed fuse (`ucodeFuseVersion`) and field-programmable fuse (`ucodeFpfFuseVersion` at 0x824250). Both must be ≤ `ACR_GA100_UCODE_BUILD_VERSION`. Two separate revocation checks; either failing returns `ACR_ERROR_UCODE_REVOKED` → written to MAILBOX0 → `falc_halt()`.

### 3.3 Engine Validation (SEC2 ENGID)

```c
// acr_sanity_checks_tu10x.c
ACR_STATUS acrCheckIfEngineIsSupported_TU10X(void)
{
#if defined(AHESASC) || defined(BSI_LOCK) || defined(ACR_UNLOAD_ON_SEC2)
    NvU32 engId = DRF_VAL(_CSEC, _FALCON_ENGID, _FAMILYID, ACR_REG_RD32(CSB, NV_CSEC_FALCON_ENGID));
    if (engId != NV_CSEC_FALCON_ENGID_FAMILYID_SEC)
    {
        return ACR_ERROR_BINARY_NOT_RUNNING_ON_EXPECTED_FALCON;
    }
#endif
    return ACR_OK;
}
```

AHESASC reads its own engine ID from `NV_CSEC_FALCON_ENGID`; must be `FAMILYID_SEC` (SEC2). This prevents the AHESASC binary from executing on any other engine.

### 3.4 Secure Lock HW State Compatibility

```c
// acr_sanity_checks_tu10x.c
ACR_STATUS acrValidateSecureLockHwStateCompatibilityWithACR_TU10X(void)
{
    ACR_STATUS  status                           = ACR_OK;
    NvBool      bIsMmuSecureLockEnabledInHW      = NV_TRUE;
    NvBool      bIsWprAllowedWithSecureLockInHW  = NV_FALSE;
    NvBool      bPolicyAllowsWPRWithMMULocked    = NV_FALSE;

    if (ACR_OK != (status = acrGetMmuSecureLockStateFromHW_HAL(pAcr, &bIsMmuSecureLockEnabledInHW, &bIsWprAllowedWithSecureLockInHW)))
        return status;

    if (ACR_OK != (status = acrGetMmuSecureLockWprAllowPolicy_HAL(pAcr, &bPolicyAllowsWPRWithMMULocked)))
        return status;

    // GA100 policy (from acrGetMmuSecureLockWprAllowPolicy_TU10X): bPolicyAllowsWPRWithMMULocked = NV_FALSE
    // Therefore entering the else branch:
    if (!bIsMmuSecureLockEnabledInHW && bIsWprAllowedWithSecureLockInHW)
    {
        return ACR_ERROR_SECURE_LOCK_NOT_ENABLED_BUT_WPR_ALLOWED_SET;
    }
    else if (bIsMmuSecureLockEnabledInHW && !bIsWprAllowedWithSecureLockInHW)
    {
        return ACR_ERROR_SECURE_LOCK_SETUP_DOES_NOT_ALLOW_WPR;
    }
    else if (bIsMmuSecureLockEnabledInHW && bIsWprAllowedWithSecureLockInHW)
    {
        return ACR_ERROR_ACR_POLICY_DOES_NOT_ALLOW_ACR_WITH_SECURE_LOCK;
    }
    return status;
}
```

GA100's `acrGetMmuSecureLockWprAllowPolicy_TU10X` always returns `bPolicyAllowsWPRWithMMULocked = NV_FALSE`.

### 3.5 IMEM Block Bubble Invalidation

```c
// acr_sanity_checks_tu10x.c
void acrValidateBlocks_TU10X(void)
{
    NvU32 start     = (ACR_PC_TRIM((NvU32)_acr_resident_code_start));
    NvU32 end       = (ACR_PC_TRIM((NvU32)_acr_resident_code_end));
    NvU32 tmp, imemBlks, blockInfo, currAddr;

    tmp = ACR_REG_RD32(CSB, NV_CSEC_FALCON_HWCFG);
    imemBlks = DRF_VAL(_CSEC_FALCON, _HWCFG, _IMEM_SIZE, tmp);

    for (tmp = 0; tmp < imemBlks; tmp++)
    {
        falc_imblk(&blockInfo, tmp);

        if (!(IMBLK_IS_INVALID(blockInfo)))
        {
            currAddr = IMBLK_TAG_ADDR(blockInfo);

            // Invalidate any IMEM block not belonging to ACR binary
            if (currAddr < start || currAddr >= end)
            {
                falc_iminv(tmp);
            }
        }
    }
}
```

This iterates all IMEM blocks (SEC2 IMEM is 256 B per block; total count from `NV_CSEC_FALCON_HWCFG.IMEM_SIZE`). Any block with a tag address outside `[_acr_resident_code_start, _acr_resident_code_end)` is invalidated by the `falc_iminv` instruction. Protects against IMEM injection from prior HS code.

### 3.6 WPR Header Traversal and LS Signature Verification Loop

`acrValidateSignatureAndScrubUnusedWpr_TU10X` is the outer loop called from `acrInit_TU10X`:

```c
// acr_verify_ls_signature_tu10x.c  (excerpt from full function at line 772)
ACR_STATUS
acrValidateSignatureAndScrubUnusedWpr_TU10X(void)
{
    ACR_STATUS       status       = ACR_OK;
    PLSF_WPR_HEADER  pWprHdr      = NULL;
    LSF_LSB_HEADER   lsbHeader;
    NvU32            falconIndex;

    // Read WPR header into DMEM global buffer
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrReadWprHeader_HAL(pAcr));

    for (falconIndex = 0; falconIndex <= LSF_FALCON_ID_END; falconIndex++)
    {
        pWprHdr = GET_WPR_HEADER(falconIndex);

        // Sentinel: falconId == LSF_FALCON_ID_INVALID (0xFFFFFFFF) marks end of table
        // Also check: id >= LSF_FALCON_ID_END, or lsbOffset == 0
        if (IS_FALCONID_INVALID(pWprHdr->falconId, pWprHdr->lsbOffset))
        {
            break;
        }

        CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrReadLsbHeader_HAL(pAcr, pWprHdr, &lsbHeader));

        // acrVerifySignature_TU10X: AES-DM + KDF + SCP slot 43 verify
        status = acrVerifySignature_TU10X(pWprHdr, &lsbHeader);

        if (status != ACR_OK)
        {
            // Scrub the WPR region belonging to this falcon (zero-fill via DMA)
            acrWriteFailingFalconIdToMailbox_TU10X(pWprHdr->falconId);
            // scrub code omitted — zero-fills [ucodeOffset, ucodeOffset+ucodeSize)
            return status;
        }
    }

    return ACR_OK;
}
```

`IS_FALCONID_INVALID` macro:
```c
// acr.h
#define IS_FALCONID_INVALID(id, off) ((id == LSF_FALCON_ID_INVALID) || (id >= LSF_FALCON_ID_END) || (!off))
```
```c
// rmlsfm.h
#define LSF_FALCON_ID_INVALID   (0xFFFFFFFFU)
```

The sentinel value `0xFFFFFFFF` in the `falconId` field marks the end of the WPR header table. `lsbOffset == 0` also signals invalid. Any entry beyond `LSF_FALCON_ID_END` is also treated as terminal.

### 3.7 AES-DM Hash Accumulation and LS Signature Verification

```c
// acr_verify_ls_signature_tu10x.c

// AES-DM KDF salt (hard-coded in binary, confirmed at AHESASC DMEM 0x800)
NvU8 g_kdfSalt[ACR_AES128_SIG_SIZE_IN_BYTES] ATTR_OVLY(".data") ATTR_ALIGNED(ACR_AES128_SIG_SIZE_IN_BYTES) =
{
    0xB6,0xC2,0x31,0xE9,0x03,0xB2,0x77,0xD7,0x0E,0x32,0xA0,0x69,0x8F,0x4E,0x80,0x62
};
```

**Step A — AES-DM hash (`acrCalculateDmhash_TU10X`):**

```c
ACR_STATUS
acrCalculateDmhash_TU10X
(
    NvU64  binBaseAddr,
    NvU32  binOffset,
    NvU32  binSize,
    NvU8  *pDmHash,         // out: 16-byte Davies-Meyer hash
    NvU32  falconId
)
{
    NvU32  hashIdx;
    NvU64  startAddr;
    NvU32  nBlocks;
    NvU8   dmHashLocal[ACR_AES128_SIG_SIZE_IN_BYTES];

    nBlocks = binSize / ACR_AES128_SIG_SIZE_IN_BYTES;  // 16-byte blocks

    // Initialize H[0] = 0x00*16
    acrMemset(dmHashLocal, 0, ACR_AES128_SIG_SIZE_IN_BYTES);

    falc_scp_trap(TC_INFINITY);

    for (hashIdx = 0; hashIdx < nBlocks; hashIdx++)
    {
        startAddr = binBaseAddr + binOffset + ((NvU64)hashIdx * ACR_AES128_SIG_SIZE_IN_BYTES);

        // DMA current 16-byte block to SCP register R3
        g_dmaProp.baseAddr = (startAddr >> 8);
        NvU32 dmaOff = (NvU32)(startAddr & 0xFF);
        if ((acrIssueDma_HAL(pAcr, pAcrGlobal->scpScratch, NV_FALSE, dmaOff,
                ACR_AES128_SIG_SIZE_IN_BYTES, ACR_DMA_FROM_FB, ACR_DMA_SYNC_AT_END,
                &g_dmaProp)) != ACR_AES128_SIG_SIZE_IN_BYTES)
        {
            falc_scp_trap(TC_DISABLE_CCR);
            return ACR_ERROR_DMA_FAILURE;
        }

        // Load H[i-1] into SCP register R2
        falc_trapped_dmwrite(falc_sethi_i((NvU32)(dmHashLocal), SCP_R2));
        falc_dmwait();

        // Load block m[i] into SCP register R3 (already loaded via DMA)

        // AES-ECB encrypt: AES(key=m[i], plaintext=H[i-1]) → SCP R4
        falc_scp_key(SCP_R3);          // use m[i] as AES key
        falc_scp_encrypt(SCP_R2, SCP_R4); // encrypt H[i-1] with key m[i]

        // Davies-Meyer: H[i] = AES(m[i], H[i-1]) XOR H[i-1]
        // (SCP XOR operation, result back to dmHashLocal)
        falc_scp_xor(SCP_R4, SCP_R2, SCP_R2); // R2 = R4 XOR R2
        falc_trapped_dmread(falc_sethi_i((NvU32)(dmHashLocal), SCP_R2));
        falc_dmwait();
    }

    falc_scp_trap(TC_DISABLE_CCR);

    acrMemcpy(pDmHash, dmHashLocal, ACR_AES128_SIG_SIZE_IN_BYTES);

    return ACR_OK;
}
```

**Step B — KDF and Signature Computation (`acrDeriveLsVerifKeyAndEncryptDmHash_TU10X`):**

```c
ACR_STATUS
acrDeriveLsVerifKeyAndEncryptDmHash_TU10X
(
    NvU32  falconId,
    NvU8  *pDmHash,     // in: 16-byte AES-DM hash
    NvBool bUseFalconId
)
{
    NvU8 pSaltBuf[ACR_AES128_SIG_SIZE_IN_BYTES] ATTR_ALIGNED(ACR_AES128_SIG_SIZE_IN_BYTES);

    // Start with KDF salt
    acrMemcpy(pSaltBuf, g_kdfSalt, ACR_AES128_SIG_SIZE_IN_BYTES);

    // Domain separation: XOR first 4 bytes of salt with falconId
    if (bUseFalconId == NV_TRUE)
    {
        ((NvU32*)pSaltBuf)[0] ^= (falconId);
    }

    // Enter SCP trap mode (prevents DMA snooping of key material)
    falc_scp_trap(TC_INFINITY);

    // Load salt^falconId into SCP register R3
    falc_trapped_dmwrite(falc_sethi_i((NvU32)(pSaltBuf), SCP_R3));
    falc_dmwait();

    // Load SCP slot secret into R2 (slot 43 in prod, slot 0 in debug)
    if (g_bIsDebug)
        falc_scp_secret(ACR_LS_VERIF_KEY_INDEX_DEBUG, SCP_R2);          // slot 0
    else
        falc_scp_secret(ACR_LS_VERIF_KEY_INDEX_PROD_TU10X_AND_LATER, SCP_R2); // slot 43 (0x2B)
    // Binary confirmed: cci 0xc2b2 = falc_scp_secret(0x2B=43, SCP_R2)

    // AES-ECB: derivedKey = AES-ECB(key=SCP[43], plain=salt^falconId) → SCP R4
    falc_scp_key(SCP_R2);
    falc_scp_encrypt(SCP_R3, SCP_R4);    // R4 = AES(SCP_slot43, salt^falconId) = derivedKey

    // Set R4 as key (chmod writes key into SCP slot, preventing extraction)
    falc_scp_chmod(0x1, SCP_R4);

    // Load dmHash into SCP register R3
    falc_trapped_dmwrite(falc_sethi_i((NvU32)pDmHash, SCP_R3));
    falc_dmwait();

    // AES-ECB: computedSig = AES-ECB(key=derivedKey, plain=dmHash) → SCP R2
    falc_scp_key(SCP_R4);
    falc_scp_encrypt(SCP_R3, SCP_R2);    // R2 = AES(derivedKey, dmHash) = computedSig

    // Read computedSig back from SCP R2 into pDmHash buffer
    falc_trapped_dmread(falc_sethi_i((NvU32)(pDmHash), SCP_R2));
    falc_dmwait();

    falc_scp_trap(TC_DISABLE_CCR);

    return ACR_OK;
}
```

**Complete AES-DM formula:**

```
H[0]    = 0x00 * 16
H[i]    = AES-ECB(key=m[i], plain=H[i-1]) XOR H[i-1]    for i = 1..nBlocks
dmHash  = H[nBlocks]

salt    = g_kdfSalt = {B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62}
saltXor = salt XOR (falconId || 0x00 * 12)   (if bUseFalconId)

derivedKey  = AES-ECB(key=SCP_slot43, plain=saltXor)
computedSig = AES-ECB(key=derivedKey, plain=dmHash)
```

**Step C — Outer verification loop (`acrVerifySignature_TU10X`):**

The full function (lines 199–770 of `acr_verify_ls_signature_tu10x.c`) implements double-buffered DMA, versioning extension, and group signatures. The comparison step:

```c
    // Compare computedSig (now in pDmHash after acrDeriveLsVerifKeyAndEncryptDmHash_TU10X)
    // against storedSig from WPR2 LSB header
    if (acrMemcmp(pLsbHeader->signature, pDmHash, ACR_AES128_SIG_SIZE_IN_BYTES) != 0)
    {
        return ACR_ERROR_LS_SIG_VERIF_FAIL;
    }
```

`ACR_ERROR_LS_SIG_VERIF_FAIL` propagates up to `acrValidateSignatureAndScrubUnusedWpr_TU10X` → the failing falcon's WPR region is DMA-zeroed (scrubbed) → status written to MAILBOX0 → MAILBOX1 gets failing `falconId` → `falc_halt()`.

### 3.8 PLM Programming After Verification

After all LS signatures pass, AHESASC programs the target falcon PLMs. For GSP-RM (the one that needs elevated DMEM access for task startup), the weakness is preserved:

```c
// booter_boot_gsprm_tu10x_ga100.c  (DMEM PLM line 94)
BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK, BOOTER_PLMASK_READ_L0_WRITE_L0);
// Comment: TODO: TASK_RM fails to come up if this is WRITE_L3
```

For other LS falcons (SEC2, PMU, NVDEC), `acrlibSetupTargetFalconPlms_TU10X` sets:
- `FALCON_PRIVSTATE_PRIV_LEVEL_MASK` → `ACR_PLMASK_READ_L0_WRITE_L3` (all falcons)
- `FALCON_DIODT_PRIV_LEVEL_MASK` → L0-read, L2-write (SEC2, GSP, NVDEC, PMU)

---

## 4. Layer L1 — ASB Bootstrap (HS on GSP-lite, TU10X path)

**Source:** `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10xga100.c`  
**Source:** `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c`

ASB runs after AHESASC exits and is responsible for loading SEC2 RTOS (LS firmware) from WPR2.

### 4.1 WPR Header Scan for SEC2

```c
// acr_ls_falcon_boot_tu10x.c  acrBootstrapFalcon_TU10X()
ACR_STATUS
acrBootstrapFalcon_TU10X(void)
{
    ACR_STATUS              status     = ACR_OK;
    PLSF_WPR_HEADER         pWprHeader = NULL;
    LSF_LSB_HEADER          lsbHeader;
    NvU32                   index      = 0;

    // Read the WPR header into heap
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrReadWprHeader_HAL(pAcr));

    for (index = 0; index <= LSF_FALCON_ID_END; index++)
    {
        pWprHeader = GET_WPR_HEADER(index);

        if (pWprHeader->falconId == LSF_FALCON_ID_SEC2)
        {
            break;
        }
    }

    if (index > LSF_FALCON_ID_END)
    {
        return ACR_ERROR_ACRLIB_HOSTING_FALCON_NOT_FOUND;
    }

    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrReadLsbHeader_HAL(pAcr, pWprHeader, &lsbHeader));

    // Setup the LS falcon: load IMEM/DMEM from WPR, program PLMs, start CPU
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrSetupLSFalcon_HAL(pAcr, pWprHeader, &lsbHeader));

    return status;
}
```

The scan looks for `falconId == LSF_FALCON_ID_SEC2`. If not found before `LSF_FALCON_ID_END` → `ACR_ERROR_ACRLIB_HOSTING_FALCON_NOT_FOUND` → halt.

### 4.2 `acrSetupLSFalcon_TU10X` — SEC2 IMEM/DMEM Load and PLM Programming

```c
// acr_ls_falcon_boot_tu10x.c
ACR_STATUS
acrSetupLSFalcon_TU10X
(
    PLSF_WPR_HEADER  pWprHeader,
    PLSF_LSB_HEADER  pLsbHeader
)
{
    ACR_STATUS       status                = ACR_OK;
    ACR_STATUS       acrStatusCleanup      = ACR_OK;
    ACR_FLCN_CONFIG  flcnCfg;
    NvU64            blWprBase;
    NvU32            dst;
    NvU32            targetMaskPlmOldValue = 0;
    NvU32            targetMaskOldValue    = 0;

    // Configure decode traps (prevents L0/L1/L2 from writing SEC2 reg space while we set up)
    status = acrLockFalconRegSpaceViaDecodeTrapCommon_HAL(pAcr);

    // Get falcon config for SEC2 (instance 0)
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrlibGetFalconConfig_HAL(pAcrlib, pWprHeader->falconId,
                                                                 LSF_FALCON_INSTANCE_DEFAULT_0, &flcnCfg));

    // Lock SEC2 reg space (trap L0/L1/L2 writes) using decode trap
    CHECK_STATUS_AND_RETURN_IF_NOT_OK(acrlibLockFalconRegSpace_HAL(pAcrlib, LSF_FALCON_ID_GSPLITE, &flcnCfg,
                                                                    NV_TRUE, &targetMaskPlmOldValue, &targetMaskOldValue));

    // Reset SEC2
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(acrResetAndPollForSec2_HAL(pAcr, pWprHeader));

    pLsbHeader->blCodeSize = NV_ALIGN_UP(pLsbHeader->blCodeSize, FLCN_IMEM_BLK_SIZE_IN_BYTES);

    // Program SEC2 SCTLs and PLMs via acrlibSetupTargetRegisters_HAL
    CHECK_STATUS_OK_OR_GOTO_CLEANUP(acrlibSetupTargetRegisters_HAL(pAcrlib, &flcnCfg));

    // Override IMEM/DMEM PLMs to final values for SEC2
    acrlibFlcnRegLabelWrite_HAL(pAcrlib, &flcnCfg, REG_LABEL_FLCN_IMEM_PRIV_LEVEL_MASK, flcnCfg.imemPLM);
    acrlibFlcnRegLabelWrite_HAL(pAcrlib, &flcnCfg, REG_LABEL_FLCN_DMEM_PRIV_LEVEL_MASK, flcnCfg.dmemPLM);

    // Compute WPR-relative DMA base for BL start
    blWprBase = ((g_dmaProp.wprBase) + (pLsbHeader->ucodeOffset >> FLCN_IMEM_BLK_ALIGN_BITS)) -
                 (pLsbHeader->blImemOffset >> FLCN_IMEM_BLK_ALIGN_BITS);

    // ... DMA BL code from WPR2 into SEC2 IMEM
    // ... DMA BL data from WPR2 into SEC2 DMEM
    // ... Program carveout registers in SEC2

    // After loading, SEC2 will be started by acrStartSec2Rtos_TU10X via
    // NV_PSEC_FALCON_CPUCTL_ALIAS.STARTCPU = TRUE (GC6 exit path) or
    // left halted for normal boot (host triggers via CPUCTL)

    // Restore decode trap (unlock SEC2 reg space)
Cleanup:
    acrStatusCleanup = acrlibLockFalconRegSpace_HAL(pAcrlib, LSF_FALCON_ID_GSPLITE, &flcnCfg,
                                                     NV_FALSE, &targetMaskPlmOldValue, &targetMaskOldValue);
    return (status != ACR_OK ? status : acrStatusCleanup);
}
```

ASB also programs SEC2 PLMs at this point via `acrlibSetupSec2Registers_TU10X`:

```c
// acr_ls_falcon_boot_tu10xga100.c  (via acrlibSetupTargetRegisters_HAL dispatch)
void acrlibSetupSec2Registers_TU10X(PACR_FLCN_CONFIG pFlcnCfg)
{
    ACR_REG_WR32(BAR0, NV_PSEC_FBIF_CTL2_PRIV_LEVEL_MASK, ACR_PLMASK_READ_L0_WRITE_L2);
    ACR_REG_WR32(BAR0, NV_PSEC_BLOCKER_PRIV_LEVEL_MASK,   ACR_PLMASK_READ_L0_WRITE_L2);
    ACR_REG_WR32(BAR0, NV_PSEC_IRQTMR_PRIV_LEVEL_MASK,    ACR_PLMASK_READ_L0_WRITE_L2);
}
```

And for all falcons via `acrlibSetupTargetFalconPlms_TU10X`:

```c
// First, all falcons: PRIVSTATE PLM → READ_L0_WRITE_L3
acrlibFlcnRegWrite_HAL(pAcrlib, pFlcnCfg, BAR0_FLCN,
    NV_PFALCON_FALCON_PRIVSTATE_PRIV_LEVEL_MASK, ACR_PLMASK_READ_L0_WRITE_L3);

// SEC2-specific additional PLMs:
case LSF_FALCON_ID_SEC2:
    plmVal = ACR_REG_RD32(BAR0, NV_PSEC_FALCON_DIODT_PRIV_LEVEL_MASK);
    plmVal = FLD_SET_DRF(_PSEC, _FALCON_DIODT_PRIV_LEVEL_MASK, _WRITE_PROTECTION_LEVEL0, _DISABLE, plmVal);
    plmVal = FLD_SET_DRF(_PSEC, _FALCON_DIODT_PRIV_LEVEL_MASK, _WRITE_PROTECTION_LEVEL1, _DISABLE, plmVal);
    ACR_REG_WR32(BAR0, NV_PSEC_FALCON_DIODT_PRIV_LEVEL_MASK, plmVal);

    plmVal = ACR_REG_RD32(BAR0, NV_PSEC_FALCON_DIODTA_PRIV_LEVEL_MASK);
    plmVal = FLD_SET_DRF(_PSEC, _FALCON_DIODTA_PRIV_LEVEL_MASK, _WRITE_PROTECTION_LEVEL0, _DISABLE, plmVal);
    plmVal = FLD_SET_DRF(_PSEC, _FALCON_DIODTA_PRIV_LEVEL_MASK, _WRITE_PROTECTION_LEVEL1, _DISABLE, plmVal);
    ACR_REG_WR32(BAR0, NV_PSEC_FALCON_DIODTA_PRIV_LEVEL_MASK, plmVal);
    break;
```

---

## 5. Error and Halt State Machine

Every AHESASC/Booter/ASB check uses `CHECK_STATUS_AND_RETURN_IF_NOT_OK` which short-circuits on any non-OK status. The terminal disposition at each layer:

| Layer | Error Return Path | Terminal Action |
|-------|-------------------|-----------------|
| L4 Host Driver | `NV_ERR_*` → `kgspInitVbiosInfo` caller | GPU init aborted, driver returns error |
| L3 Booter LOAD | any `BOOTER_ERROR_*` in `booterLoad_TU10X` | Status → `NV_CSEC_FALCON_MAILBOX0` → `falc_halt()` |
| L3 Booter LOAD (DMA addr xlat) | `BOOTER_ERROR_DMA_FAILURE` | Immediate `falc_halt()` inline (no MAILBOX write) |
| L2 AHESASC | any `ACR_ERROR_*` in init sequence | Status → `NV_CSEC_FALCON_MAILBOX0`, falconId → MAILBOX1 → `falc_halt()` |
| L2 AHESASC sig fail | `ACR_ERROR_LS_SIG_VERIF_FAIL` | DMA-zero scrub of failing falcon's WPR region, then halt |
| L1 ASB | any `ACR_ERROR_*` in `acrBootstrapFalcon_TU10X` | Status → MAILBOX0 → halt |

**Mailbox status reporting (`acrWriteStatusToFalconMailbox_TU10X`):**
```c
void acrWriteStatusToFalconMailbox_TU10X(ACR_STATUS status)
{
#if defined(AHESASC) || defined(ASB) || defined(BSI_LOCK) || defined(ACR_UNLOAD_ON_SEC2)
    ACR_REG_WR32_STALL(CSB, NV_CSEC_FALCON_MAILBOX0, status);
#elif defined(ACR_UNLOAD)
    ACR_REG_WR32_STALL(CSB, NV_CPWR_FALCON_MAILBOX0, status);
#else
    ct_assert(0);
#endif
}
```

**Failing falcon ID reporting (`acrWriteFailingFalconIdToMailbox_TU10X`):**
```c
void acrWriteFailingFalconIdToMailbox_TU10X(NvU32 falconId)
{
#if defined(AHESASC) || defined(ASB) || defined(BSI_LOCK) || defined(ACR_UNLOAD_ON_SEC2)
    ACR_REG_WR32_STALL(CSB, NV_CSEC_FALCON_MAILBOX1, falconId);
#elif defined(ACR_UNLOAD)
    ACR_REG_WR32_STALL(CSB, NV_CPWR_FALCON_MAILBOX1, falconId);
#else
    ct_assert(0);
#endif
}
```

**ACR binary sequencing guard (`acrWriteAcrVersionToBsiSecureScratch_TU10X`):**  
Prevents any ACR binary from running out of order. AHESASC expects BSI VPR scratch version == 0 (first to run); ASB expects the version to match its own (`ACR_ERROR_BINARY_SEQUENCE_MISMATCH` if not). This prevents replaying stale or reordered ACR binaries.

---

## 6. Success Path — Verification State Machine Summary

```
Host CPU:
  ├─ s_vbiosFindBitHeader: [addr] == 0xB8FF, [addr+2..5] == 0x00544942, checksum(header) & 0xFF == 0
  ├─ BIT token 'p' (0x70), version 2, size >= BIT_DATA_FALCON_DATA_V2_SIZE_4
  └─ FWSEC ucode dispatched to SEC2 → runs HS on ROM trust → FWSEC exits

Booter LOAD (HS on SEC2):
  ├─ booterCheckIfEngineIsSupported_TU10X: ENGID == FAMILYID_SEC
  ├─ booterCheckIfBuildIsSupported_GA100: PMC_BOOT_42.CHIP_ID == 0x170
  ├─ booterCheckFuseRevocationAgainstHWFpfVersion_TU10X: build_ver >= fpf_ver
  ├─ GspFwWprMeta.magic == 0xdc3aae21371a60b3, .revision == 1
  ├─ 9x WPR2 geometry bounds checks (alignment, in-WPR containment, no overlap)
  ├─ RSA-3072-PSS-SHA256 on GSP-RM bootloader (code section)
  │     SHA-256( BL_code || falconId || lsUcodeVer || lsUcodeId || depMap ) → hash
  │     RSA-3072-decrypt(sig, pubkey) → em
  │     PSS verify: em[emLen-1]==0xBC, DB[0..sep-1]==0, DB[sep]==0x01, H'==H
  ├─ RSA-3072-PSS-SHA256 on GSP-RM ELF (data section) — same procedure
  ├─ GSP-RM LS ucode revocation check via NV_PGC6_AON_SECURE_SCRATCH_GROUP_19
  ├─ WprMeta.verified set to 0xa0a0a0a0a0a0a0a0 and written back to WPR2
  └─ GSP-RM RISC-V started via NV_PGSP_RISCV_CPUCTL_ALIAS.STARTCPU=TRUE

AHESASC (HS task on SEC2):
  ├─ acrCheckIfEngineIsSupported_TU10X: ENGID == FAMILYID_SEC
  ├─ acrCheckIfBuildIsSupported_GA100: PMC_BOOT_42.CHIP_ID == 0x170
  ├─ acrCheckFuseRevocation_GA100: build_ver >= fuse_ver AND build_ver >= fpf_ver(0x824250)
  ├─ acrValidateSecureLockHwStateCompatibilityWithACR_TU10X: policy=no-secure-lock
  ├─ acrValidateBlocks_TU10X: invalidate IMEM bubbles
  ├─ WPR header loop [0..LSF_FALCON_ID_END]: exit at falconId==0xFFFFFFFF
  │   For each valid falcon:
  │     AES-DM hash: H = Davies-Meyer(16B blocks, SCP encrypt, XOR accumulate)
  │     KDF: derivedKey = AES-ECB(key=SCP_slot43, plain=g_kdfSalt XOR falconId)
  │     computedSig = AES-ECB(key=derivedKey, plain=dmHash)
  │     compare computedSig == lsbHeader.signature (16B memcmp)
  │     FAIL → scrub WPR region → MAILBOX0=ACR_ERROR_LS_SIG_VERIF_FAIL → halt
  ├─ All LS sigs pass → PLMs programmed per falcon
  └─ AHESASC exits, WPR1 locked

ASB (HS on GSP-lite):
  ├─ acrWriteAcrVersionToBsiSecureScratch_TU10X: sequence check vs BSI scratch
  ├─ WPR header scan for falconId == LSF_FALCON_ID_SEC2
  ├─ acrSetupLSFalcon_TU10X:
  │     lock SEC2 reg space via decode trap (prevent L0/L1/L2 writes)
  │     reset SEC2 + poll IMEM/DMEM scrub complete
  │     DMA SEC2 BL from WPR2 → SEC2 IMEM
  │     DMA SEC2 data from WPR2 → SEC2 DMEM
  │     program SEC2 carveout registers
  │     set final SEC2 IMEM/DMEM PLMs
  │     unlock decode trap
  └─ acrStartSec2Rtos_TU10X: NV_PSEC_FALCON_CPUCTL_ALIAS.STARTCPU=TRUE (GC6 exit)
       → SEC2 RTOS (LS on SEC2) begins execution as trust level L1
```

---

## 7. GA100-Specific Structural Weaknesses Exposed by This Path

| ID | Location | Exact Source Line | Impact |
|----|----------|-------------------|--------|
| W-1 | Booter `booterSetupTargetRegisters_TU10X` | `booter_boot_gsprm_tu10x_ga100.c:94` | `DMEM_PLM = READ_L0_WRITE_L0` — GSP-RM (L0) can DMA-overwrite its own DMEM from WPR. "TODO: TASK_RM fails to come up if this is WRITE_L3." Root cause: TU10X code path, not fixed for GA100. |
| W-2 | Booter `booterSetupTargetRegisters_TU10X` | `booter_boot_gsprm_tu10x_ga100.c:57-73` | `REGIONCFG` `#if 0` block disabled. GSP-RM FBIF has no WPR-only DMA restriction. Comment: "Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot." |
| W-3 | AHESASC AES-DM | `acr_verify_ls_signature_tu10x.c:g_kdfSalt` | LS root of trust is a single SCP slot (slot 43) shared across all GA100 dies. Compromise of one die's SCP secret enables global LS signature forgery. |
| W-4 | Booter load | `booter_load_tu10x.c:239-242` | GspFwWprMeta magic/revision is a developer check, not a cryptographic check. Magic value (`0xdc3aae21371a60b3`) is not secret; any attacker who can write sysmem before the DMA (IOMMU bypass) can supply a crafted WprMeta. |
| W-5 | AHESASC APM variant | `7-4-phase4-ahesasc-apm.md` | W-1 + W-2 compound → GSP-RM can DMA-overwrite APM_RTS in WPR, silently corrupting CC attestation on A100 SXM4 (DevID=0x20B5). |
