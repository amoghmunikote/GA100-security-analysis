# 2.5 — Host Firmware Parser Analysis
## GA100 Security Audit | `kernel_gsp_fwsec.c`

**Source:** `drivers/resman/src/kernel/gpu/gsp/kernel_gsp_fwsec.c` (1,106 lines)  
**Ancillary:** `arch/nvalloc/common/inc/rmlsfm.h`, `kernel/inc/sec2/bin/g_sec2uc_ga100_riscv_ls_sig.h`  
**Date:** 2026-05-18  
**Status:** COMPLETE

---

## 1. Executive Summary

This document is an exhaustive line-by-line static analysis of the NVIDIA host-driver VBIOS image parsing pipeline responsible for ingesting FWSEC ucode before firmware execution. The pipeline runs entirely in kernel mode on the host CPU, consuming an attacker-influenced data source (the VBIOS image read from ROM). Four findings are documented, ranging from a **Medium** severity unbounded kernel heap allocation to **Low/Info** arithmetic and logic observations.

The `depMap` field from `LSF_UCODE_DESC` (88 bytes in WPR) is **not parsed by this pipeline**. It is populated at build time from a codesign-generated constant and consumed exclusively by ACR on-device. The GA100 SEC2 `depMap` content and KDF material are decoded in §8.

---

## 2. Pipeline Overview

```
kgspParseFwsecUcodeFromVbiosImg_IMPL          [kernel_gsp.c:1304]
  ├── s_vbiosFindBitHeader                    [kernel_gsp_fwsec.c:379]
  │     └── s_vbiosRead8/16                  [340–371] → s_vbiosReadStructure
  ├── s_vbiosParseFwsecUcodeDescFromBit       [444]
  │     ├── s_vbiosReadStructure (BIT hdr)    [467]
  │     ├── s_vbiosReadStructure (BIT tokens) [484]   ← loop tokIdx < TokenEntries
  │     ├── s_vbiosReadStructure (ucode tbl)  [516]
  │     ├── s_vbiosReadStructure (ucode entry)[547]   ← loop entryIdx < EntryCount
  │     ├── s_vbiosReadStructure (desc hdr)   [570]
  │     └── s_vbiosReadStructure (full desc)  [615]
  └── s_vbiosNewFlcnUcodeFromDesc             [985]
        ├── s_vbiosFillFlcnUcodeFromDescV2    [647]   (KGSP_FLCN_UCODE_BOOT_WITH_LOADER)
        └── s_vbiosFillFlcnUcodeFromDescV3    [823]   (KGSP_FLCN_UCODE_BOOT_FROM_HS)
```

The VBIOS image (`KernelGspVbiosImg`) carries:
- `pImage` — raw byte buffer
- `biosSize` — total bytes
- `expansionRomOffset` — offset of the first 512-byte-aligned `55 AA` header within `pImage`

All structured reads go through `s_vbiosReadStructure`, which enforces `offset + packedSize ≤ biosSize`. The pipeline returns a `KernelGspFlcnUcode *` consumed by `kgspExecuteFwsecFrts_HAL` / `kgspExecuteFwsecSb_HAL`.

---

## 3. Layer 0: Format-String Parser

### 3.1 `s_biosStructCalculatePackedSize` (lines 183–230)

Iterates a format string computing the packed byte count of a structure. Recognized chars: `b`=1, `s`=1 (signed byte), `w`=2, `d`=4. A decimal prefix encodes a repeat count.

**Count accumulator (lines 200–204):**
```c
count *= 10;
count += fmt - '0';
```
No bounds on `count`. A format string `"4294967295b"` would accumulate `count = 4294967295`, then compute `packedSize += 4294967295 * 1` = 0xFFFFFFFF. With any following character, `packedSize` wraps. **However**: all callers pass hardcoded string literals — `"1w1d1w4b"`, `"6b"`, `"2b1d"`, `"15d"`, `"9d1w2b2w"`, `"1d"`. No external format string injection path exists. **(INFO — no current attack surface.)**

### 3.2 `s_biosUnpackStructure` (lines 239–301)

Unpacks LE-packed bytes into a `NvU32 *unpackedData` array. Same repeat-count logic. Each element is widened to `NvU32` before being stored at `*unpackedData++`. The 's' (signed byte) case at lines 276–279:

```c
data = *packedData++;
if (data & 0x80)
    data |= ~0xff;
```

Sign-extension of bit 7 into all upper bits of `NvU32`. Correct per two's complement.

**No destination buffer size parameter.** The function writes one `NvU32` per format element without any check that `unpackedData` has room. Callers are responsible for supplying a correctly-sized destination. All current callers use stack-allocated structs whose field counts match their format strings (verified by structure layout). **(INFO — caller contract, no current overflow.)**

**Unknown format char (line 293):** Returns `NV_ERR_GENERIC` immediately, leaving partial data in `unpackedData`. The unknown-char early return could produce a partially-filled structure if callers ignore the error. All callers check the return value via `s_vbiosReadStructure`.

---

## 4. Layer 1: Bounds-Checked VBIOS Reader

### 4.1 `s_vbiosReadStructure` (lines 311–338)

```c
packedSize = s_biosStructCalculatePackedSize(format);
bSafe = portSafeAddU32(offset, packedSize, &maxOffset);
if (NV_UNLIKELY(!bSafe || maxOffset > pVbiosImg->biosSize))
    return NV_ERR_INVALID_OFFSET;
return s_biosUnpackStructure(pVbiosImg->pImage + offset, pStructure, format);
```

`portSafeAddU32` provides overflow-safe addition. The bound `maxOffset > biosSize` (strict greater-than) correctly rejects reads touching or past the last byte. This check gates **every** subsequent read — the source VBIOS is fully bounds-checked at every access point.

**The check validates the source range, not the destination struct.** Over-long reads cannot happen (source-side checked), but if a format string produced more output elements than the destination struct can hold, `s_biosUnpackStructure` would overwrite adjacent stack memory. As noted, this does not occur in practice due to hardcoded formats.

### 4.2 `s_vbiosRead8/16/32` (lines 340–371)

Short-circuit on accumulated `*pStatus != NV_OK` (lines 343, 354, 365). This is a common "sticky error" pattern — a read failure in a chain halts subsequent reads without cascading through each call site. The returned value on sticky-error is `0`, which is a safe sentinel for integer reads but could produce false-positive matches (e.g., `BIT_HEADER_ID = 0xB8FF` cannot be `0`). No concern.

---

## 5. Layer 2: BIT Header Scanner

### 5.1 `s_vbiosFindBitHeader` (lines 379–434)

**Loop bound (line 398):** `addr < pVbiosImg->biosSize - 3`. When `biosSize < 4`, the unsigned subtraction wraps to ~`UINT32_MAX`, causing a near-infinite loop. The three preceding `NV_ASSERT_OR_RETURN` checks at lines 393–396 reject `biosSize == 0` but not `biosSize ∈ {1,2,3}`. A 1-byte VBIOS image passes the assertion (`biosSize > 0`) and triggers the wrap. **In practice, VBIOS images are ≥ 64KB.** **(INFO — unreachable in production.)**

**`headerSize` from attacker data (lines 407–408):**
```c
NvU32 headerSize = s_vbiosRead8(pVbiosImg,
                                candidateBitAddr + BIT_HEADER_SIZE_OFFSET, &status);
```
`headerSize` is 1 byte (0–255). Used as the checksum loop bound at line 413. Each iteration calls `s_vbiosRead8` which internally calls `s_vbiosReadStructure`, which bounds-checks against `biosSize`. An attacker-supplied `headerSize = 255` causes 255 individual bounds-checked reads — all safe. No overread possible.

**8-bit checksum (line 420):** `(checksum & 0xFF) == 0x0`. The BIT checksum is intentionally 8-bit (BIOS convention). A collision has 1/256 probability for random data. This is the accepted spec behavior and does not weaken security because BIT header content is already trusted (ROM).

**No alignment enforcement:** The scanner accepts any byte offset for the BIT header. The real BIT header must be at a specific offset per the VBIOS layout, but the scanner will accept the first offset with a valid ID, signature, and checksum. In a VBIOS with an attacker-controlled prefix, a crafted false BIT header early in the image could redirect all subsequent parsing. **The threat model assumption is that VBIOS ROM content is trusted (hardware-protected ROM).** Under this assumption, no concern. If VBIOS content is ever treated as attacker-controlled (e.g., a software-modifiable EEPROM in a degraded threat model), this becomes exploitable.

---

## 6. Layer 3: FALCON Ucode Descriptor Parser

### 6.1 `s_vbiosParseFwsecUcodeDescFromBit` (lines 444–635)

#### 6.1.1 TokenEntries Loop Bound

```c
for (tokIdx = 0; tokIdx < bitHeader.TokenEntries; tokIdx++)    // line 475
```

`bitHeader.TokenEntries` is `bios_U008` (1 byte) — maximum 255 iterations. Token addresses computed as:

```c
bitAddr + bitHeader.HeaderSize + tokIdx * bitHeader.TokenSize
```

Both `HeaderSize` and `TokenSize` are single bytes. Worst case: `bitAddr + 255 + 255 * 255 = bitAddr + 65,535`. This plus the `BIT_TOKEN_V1_00_FMT` packed size (6 bytes) must fit within `biosSize`. `s_vbiosReadStructure` checks this at each iteration. Any out-of-bounds token silently `continue`s (line 492–494), not a fatal error.

**Important note:** Prior BIOS parsers in the tree used `bios_U016` for `TokenEntries`, which would allow 65,535 iterations. This parser correctly uses `bios_U008` per the actual struct definition (line 41), matching the GA100 binary observation of `TokenEntries = 0x10 = 16`. A 2-byte read at this offset would produce `0x1000` (4096), leading to 4096 token reads, all out-of-bounds, all silently skipped — harmless but a sign of the earlier parsing confusion documented in the session log.

#### 6.1.2 DataPtr Offset Duality — Absolute vs ROM-Relative

```c
// DataPtr → USED AS ABSOLUTE IMAGE OFFSET:
status = s_vbiosReadStructure(pVbiosImg, &falconData,
                              bitToken.DataPtr,                  // line 506 — absolute
                              BIT_DATA_FALCON_DATA_V2_4_FMT);

// FalconUcodeTablePtr → ROM-RELATIVE:
status = s_vbiosReadStructure(pVbiosImg, &ucodeHeader,
                              pVbiosImg->expansionRomOffset +    // line 517-518 — relative
                                falconData.FalconUcodeTablePtr, ...);

// Entry DescPtr → ALSO ROM-RELATIVE:
ucodeDescOffset = ucodeEntry.DescPtr + pVbiosImg->expansionRomOffset;  // line 613
```

`bitToken.DataPtr` is a `bios_U016` (max 65,535). It is used **directly as a file offset** — not relative to the expansion ROM. This matches the BIT spec: token DataPtrs are BIOS-image absolute. The `FalconUcodeTablePtr` inside that data block is expansion-ROM relative. Both values are VBIOS-controlled; both are bounds-checked by `s_vbiosReadStructure` before use.

**Asymmetry hazard:** The two coordinate systems are not distinguished by type or naming convention. A maintenance change adding an `expansionRomOffset` addition to the first read would produce a silent parser divergence. **(INFO — spec-correct; maintenance risk only.)**

#### 6.1.3 AppID Filter Logic

```c
if (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FIRMWARE_SEC_LIC &&
    ((bUseDebugFwsec && (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FWSEC_DBG)) ||
     (!bUseDebugFwsec && (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FWSEC_PROD))))
{
    continue;
}
```

The three accepted AppIDs are:
- `0x05` = `FIRMWARE_SEC_LIC` (legacy, always accepted regardless of `bUseDebugFwsec`)
- `0x45` = `FWSEC_DBG` (debug mode only)
- `0x85` = `FWSEC_PROD` (production mode)

`bUseDebugFwsec` is determined by `kgspIsDebugModeEnabled_HAL`, which reads `NV_FUSE_OPT_SECURE_SECENGINE_DEBUG_DIS` — a hardware fuse (read-only post-lock). The filter cannot be bypassed by software once production fuses are burned.

Note: `0x05` (`FIRMWARE_SEC_LIC`) is accepted unconditionally. On a board where a `FIRMWARE_SEC_LIC` entry exists alongside a `FWSEC_PROD` entry, the first match wins (line 629 returns on first hit). Order is determined by VBIOS. Cross-reference: CMP 170HX VBIOS Image #2 has no `FIRMWARE_SEC_LIC` entry; only `FWSEC_PROD` (0x85) and `FWSEC_DBG` (0x45).

#### 6.1.4 `descSize` — Attacker-Controlled Descriptor Size

```c
ucodeDescSize = DRF_VAL(_BIT, _FALCON_UCODE_DESC_HEADER_VDESC, _SIZE, ucodeDescHdr.vDesc);
```

`vDesc[31:16]` → `ucodeDescSize` is a 16-bit field, range 0–65535. Used in two ways:

1. **Version gate (lines 595–611):** Accept V2 only if `ucodeDescSize >= 60`; V3 only if `ucodeDescSize >= 44`. Prevents using a truncated descriptor.
2. **Passed to fill functions** as `descSize`, where it drives memory allocation (V3 path, §7.2).

---

## 7. Layer 4: Ucode Memory Loader Functions

### 7.1 `s_vbiosFillFlcnUcodeFromDescV2` (lines 647–811)

This function allocates two physically contiguous `ADDR_SYSMEM` memdesc buffers (code and data) and copies the FWSEC binary from the VBIOS image.

#### 7.1.1 `imemSecPa` Multi-Operand Arithmetic

```c
pUcode->imemSecPa = pDescV2->IMEMSecBase - pDescV2->IMEMVirtBase + pDescV2->IMEMPhysBase;
```

Three `bios_U032` values from VBIOS, combined by unsigned arithmetic:
- If `IMEMSecBase < IMEMVirtBase`, the subtraction underflows to a large `NvU32`
- The subsequent addition of `IMEMPhysBase` further wraps

The result is validated afterward at lines 735–744:
```c
if (pUcode->imemNsPa >= codeSizeAligned) return NV_ERR_INVALID_OFFSET;
bSafe = portSafeAddU32(pUcode->imemNsPa, pUcode->imemSize, &mappedCodeMaxOffset);
if (!bSafe || mappedCodeMaxOffset > codeSizeAligned) return NV_ERR_INVALID_OFFSET;
```

`codeSizeAligned = NV_ALIGN_UP(pUcode->imemSize, 256)`. If `pUcode->imemSize` is near `UINT32_MAX`, `NV_ALIGN_UP(..., 256)` wraps to a small value, and an underflowed `imemSecPa` could pass the check. However, `pUcode->imemSize = pDescV2->IMEMLoadSize` is also VBIOS-controlled and bounded to `biosSize` (the IMEM copy at line 716 checks `imageCodeOffset + imemSize ≤ biosSize`). The largest plausible `imemSize` equals the VBIOS image size, so wrap is unlikely. **(LOW — underflow caught by downstream bounds check; no exploitable path confirmed.)**

**`NV_ALIGN_UP` near `UINT32_MAX` (line 706):**
```c
codeSizeAligned = NV_ALIGN_UP(pUcode->imemSize, 256);
dataSizeAligned = NV_ALIGN_UP(pUcode->dmemSize, 256);
```
If `imemSize = 0xFFFFFF01`, `NV_ALIGN_UP(0xFFFFFF01, 256)` = `0x00000000` (wraps). Subsequent allocation `memdescCreate(..., 0, ...)` followed by the `imemNsPa >= codeSizeAligned` check `(X >= 0)` is always true — function returns early. No allocation occurs. Not exploitable, but a defensive `if (imemSize > MAX_SAFE)` would be cleaner.

#### 7.1.2 Image-to-Buffer Copy Offset Arithmetic

The copy source offset is derived as:
```c
bSafe = portSafeAddU32(descOffset, descSize, &imageCodeOffset);
```

`descOffset` = `ucodeEntry.DescPtr + expansionRomOffset` (line 613). `descSize` = `ucodeDescSize` (16-bit, attacker-controlled, bounded by V2 ≥ 60). Both values are VBIOS-controlled. `portSafeAddU32` prevents overflow; the subsequent `>= biosSize` check prevents out-of-bounds. Similarly for data at lines 722–730.

The `portMemCopy` at lines 796–801:
```c
portMemCopy(pMappedCodeMem + pUcode->imemNsPa, pUcode->imemSize,
            pVbiosImg->pImage + imageCodeOffset, pUcode->imemSize);
portMemCopy(pMappedDataMem + pUcode->dmemPa, pUcode->dmemSize,
            pVbiosImg->pImage + imageDataOffset, pUcode->dmemSize);
```

Destination offsets are bounds-checked at lines 735–755. Source offsets are bounds-checked at lines 710–731. Assuming `portMemCopy` enforces destination-size ≤ allocation-size (which is platform-dependent — RM's portMemCopy does perform this check), these copies are safe.

### 7.2 `s_vbiosFillFlcnUcodeFromDescV3` (lines 823–972)

#### 7.2.1 FINDING P4-1: Unbounded `signaturesTotalSize` Allocation (MEDIUM)

```c
// Line 930–943:
if (descSize < FALCON_UCODE_DESC_V3_SIZE_44)
    return NV_ERR_INVALID_STATE;
pUcode->signaturesTotalSize = descSize - FALCON_UCODE_DESC_V3_SIZE_44;  // line 934

pUcode->pSignatures = portMemAllocNonPaged(pUcode->signaturesTotalSize);  // line 936
if (pUcode->pSignatures == NULL)
    return NV_ERR_NO_MEMORY;

portMemCopy(pUcode->pSignatures, pUcode->signaturesTotalSize,
            pVbiosImg->pImage + descOffset + FALCON_UCODE_DESC_V3_SIZE_44,
            pUcode->signaturesTotalSize);  // lines 942–943
```

`descSize` is a 16-bit value from `vDesc[31:16]` — attacker-controlled, range 44–65535. The lower bound (`< 44` → return) is checked. **No upper bound.** A VBIOS with `descSize = 0xFFFF` causes:

- `signaturesTotalSize = 65535 - 44 = 65491`
- `portMemAllocNonPaged(65491)` — 64 KB kernel heap allocation
- `portMemCopy(pUcode->pSignatures, 65491, pVbiosImg->pImage + descOffset + 44, 65491)` — copy of 65491 bytes from VBIOS image

**Source bounds:** The copy source is `descOffset + 44` to `descOffset + 65535`. The source range IS bounds-checked for V3 entries: the `imageOffset/imageMaxOffset` checks at lines 886–895 verify `descOffset + descSize ≤ biosSize`. Since `pUcode->size = RM_ALIGN_UP(StoredSize, 256)` and `imageMaxOffset = imageOffset + size`, the copy is bounded to valid VBIOS data. The **content** of those 65491 bytes comes entirely from the VBIOS image — not arbitrary host memory.

**Impact:**
- **DoS (kernel heap exhaustion):** If `portMemAllocNonPaged` fails, function returns `NV_ERR_NO_MEMORY` — FWSEC fails to load, GPU initialization fails. Crafting a VBIOS image that triggers this requires write access to the VBIOS ROM (privileged). On cloud VM guests with SR-IOV, the VBIOS is provided by the hypervisor, not the guest — guest-controlled exploitation is not possible.
- **Information exposure:** The 65491 bytes allocated and copied are from the VBIOS ROM itself, not host memory. No arbitrary read gadget.
- **Heap spray:** 65491 bytes of attacker-controlled bytes (from VBIOS ROM) placed in kernel heap. Combined with a subsequent heap shaping primitive, could serve as a heap spray primitive. No currently identified follow-on gadget.

**Root cause:** `descSize` is used both as a format-level type field (to select V3 behavior) and as an allocation size. The BCRT30 RSA-3K signature size is `BCRT30_RSA3K_SIG_SIZE = 384` bytes (line 156). For a typical V3 entry with `SignatureCount = N`, expected `signaturesTotalSize = N * 384`. An upper bound of `SignatureCount * 384` (with `SignatureCount` from the descriptor) should be enforced.

**CVSS estimate:** CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L = 1.6 (Low) — requires VBIOS write, limited to DoS.

#### 7.2.2 PKCDataOffset / hsSigDmemAddr Validation

```c
bSafe = portSafeAddU32(pUcode->dataOffset, pUcode->hsSigDmemAddr, &sigDataOffset);
if (!bSafe || sigDataOffset >= pUcode->size) return NV_ERR_INVALID_OFFSET;
bSafe = portSafeAddU32(sigDataOffset, pUcode->sigSize, &sigDataMaxOffset);
if (!bSafe || sigDataMaxOffset > pUcode->size) return NV_ERR_INVALID_OFFSET;
```

`hsSigDmemAddr = pDescV3->PKCDataOffset`. The validation checks that the PKC data region `[dataOffset + PKCDataOffset, dataOffset + PKCDataOffset + 384)` fits within `[0, pUcode->size)`. `pUcode->size` is aligned `StoredSize` — also VBIOS-controlled but bounded to `biosSize`. Overflow-safe. Correct.

---

## 8. Layer 5: Dispatch and Error Propagation

### 8.1 FINDING P4-2: `s_vbiosNewFlcnUcodeFromDesc` Silent Failure on Fill Error (LOW)

```c
static NV_STATUS s_vbiosNewFlcnUcodeFromDesc(..., KernelGspFlcnUcode **ppFlcnUcode)
{
    NV_STATUS status;
    KernelGspFlcnUcode *pFlcnUcode = portMemAllocNonPaged(sizeof(*pFlcnUcode));
    ...

    if (descVersion == V2)
        status = s_vbiosFillFlcnUcodeFromDescV2(..., pFlcnUcode);
    else
        status = s_vbiosFillFlcnUcodeFromDescV3(..., pFlcnUcode);

    if (status != NV_OK)
    {
        kgspFreeFlcnUcode(pFlcnUcode);
        pFlcnUcode = NULL;
        // ← status is non-OK here, but...
    }

    *ppFlcnUcode = pFlcnUcode;  // set to NULL on failure
    return NV_OK;               // ← ALWAYS returns NV_OK        [line 1045]
}
```

When `s_vbiosFillFlcnUcodeFromDescV2/V3` fails (e.g., `NV_ERR_NO_MEMORY` from memdesc allocation), the inner `status` is non-OK, `pFlcnUcode` is freed and set to NULL, `*ppFlcnUcode = NULL`, and the function returns `NV_OK`. The caller `kgspParseFwsecUcodeFromVbiosImg_IMPL` (line 1096–1103) checks `status != NV_OK` and proceeds on `NV_OK` — with `*ppFwsecUcode = NULL`.

**Downstream propagation:**
- `kernel_gsp.c:1307` checks `status != NV_OK` → passes, `pKernelGsp->pFwsecUcode = NULL`
- `kernel_gsp_ga102.c:274`: `kgspExecuteFwsecFrts_HAL(pGpu, pKernelGsp, pKernelGsp->pFwsecUcode, ...)` passes NULL
- `kernel_gsp_frts_tu102.c:273`: `NV_ASSERT_OR_RETURN(pFwsecUcode != NULL, NV_ERR_INVALID_ARGUMENT)` — runtime mitigation at the execution call site

The `NV_ASSERT_OR_RETURN` at the executor catches the NULL and returns an error, preventing a NULL dereference. However, this defense is one layer removed from where the error was swallowed. In a build configuration where `NV_ASSERT_OR_RETURN` is a no-op, or if a different execution path calls `pFwsecUcode->bootType` before the check, the NULL deref would be reached.

**Root cause:** Line 1045 should be `return status;`. The intent appears to have been "always succeed the outer allocation; let the caller decide what to do with a NULL ucode." But no caller is written to handle `NV_OK + *ppFlcnUcode = NULL`.

### 8.2 `kgspParseFwsecUcodeFromVbiosImg_IMPL` (lines 1059–1106)

Entry point. Calls `kgspIsDebugModeEnabled_HAL` to determine `bUseDebugFwsec`. This HAL call reads `NV_FUSE_OPT_SECURE_SECENGINE_DEBUG_DIS` — a hardware fuse. Correct gating.

The function itself is a thin wrapper: find BIT → parse descriptor → materialize ucode. No additional attack surface beyond the subordinate functions analyzed above.

---

## 9. depMap: Structure, Population, and ACR Consumption

### 9.1 What depMap Is Not

`depMap` does **not** appear in `kernel_gsp_fwsec.c`. It is not part of the VBIOS FALCON_UCODE_TABLE parsing pipeline. The VBIOS parser only extracts IMEM/DMEM binary blobs and V3 RSA signatures.

### 9.2 Where depMap Lives

`LSF_UCODE_DESC` (from `rmlsfm.h:160–188`) is part of the WPR blob's LSB header structure:

```c
typedef struct {
    NvU8  prdKeys[2][16];     // 32B — production AES-CBC keys
    NvU8  dbgKeys[2][16];     // 32B — debug AES-CBC keys
    NvU32 bPrdPresent;        // 4B
    NvU32 bDbgPresent;        // 4B
    NvU32 falconId;           // 4B
    NvU32 bSupportsVersioning;// 4B
    NvU32 version;            // 4B
    NvU32 depMapCount;        // 4B — valid entries in depMap (max 11)
    NvU8  depMap[LSF_FALCON_DEPMAP_SIZE * 2 * 4]; // 88B — 11 pairs × [falconId:4B, version:4B]
    NvU8  kdf[16];            // 16B — KDF salt
} LSF_UCODE_DESC;             // Total: 192B
```

This structure is embedded at `LSF_LSB_HEADER.signature` (rmlsfm.h:301), written into the WPR blob by the host driver at GPU initialization from codesign-time-generated static constants (e.g., `g_sec2uc_ga100_riscv_ls_sig.h`). It is then DMA-copied into WPR and consumed by ACR on-device.

### 9.3 ACR On-Device depMap Processing

From the GH100 objdump (`g_partitions_gsp_gh100_riscv.objdump`, lines 21175–21325 — conceptually representative of GA100 ACR behavior):

```c
if (pUcodeDescV2->depMapCount) {
    size = pUcodeDescV2->depMapCount * 8;           // 8 bytes per entry
    acrMemcpy_HAL(pAcr, pIoBuffer, pUcodeDescV2->depMap, size);
}
for (i = 0; i < pUcodeDescV2->depMapCount; i++) {
    depfalconId = ((NvU32*)pUcodeDescV2->depMap)[i*2];
    expVer      = ((NvU32*)pUcodeDescV2->depMap)[i*2 + 1];
    // check that falcon `depfalconId` has loaded version `expVer` before allowing current ucode
}
```

`depMapCount` is bounded to `LSF_FALCON_DEPMAP_SIZE = 11`. The copy size `depMapCount * 8 ≤ 88` bytes — fits within `depMap[88]`. The ACR consumes it on-device to enforce load order dependencies among LS falcons.

**There is no host-side validation of depMap content.** The host driver copies the static codesign constant directly into WPR without parsing it. The content is a NVIDIA-controlled build artifact (not VBIOS-derived), so there is no host-side attack surface.

### 9.4 GA100 SEC2 depMap Decoded

From `g_sec2uc_ga100_riscv_ls_sig.h:36–38`:

```
dependencyCount = 7
dependencyMap (56 bytes, 7 × [falconId:4B LE, expVer:4B LE]):
```

| Entry | falconId | Constant           | expVer | Notes                     |
|-------|----------|--------------------|--------|---------------------------|
| 0     | 0x00     | PMU                | 0x01   | PMU must be v1            |
| 1     | 0x01     | DPU (GSPLITE)      | 0xFF   | DPU any version / invalid |
| 2     | 0x02     | FECS               | 0x01   | FECS must be v1           |
| 3     | 0x03     | GPCCS              | 0x01   | GPCCS must be v1          |
| 4     | 0x04     | NVDEC              | 0x01   | NVDEC must be v1          |
| 5     | 0x0A     | FBFALCON (HULK)    | 0xFF   | HULK any version          |
| 6     | 0x07     | SEC2 (self)        | 0x01   | Self-reference v1         |

`0xFF` expVer entries (DPU, FBFALCON) likely indicate "optional" or "any version accepted." The self-referential entry (SEC2 id=7, expVer=1) is normal — ACR validates SEC2's own version as part of its load sequence.

### 9.5 KDF Material and AHESASC AES-DM Salt Correlation

`g_sec2uc_ga100_riscv_ls_sig.h:40`:
```
kdf = { 0xb1, 0xc2, 0x31, 0xe9, 0x03, 0xb2, 0x77, 0xd7, 0x0e, 0x32, 0xa0, 0x69, 0x8f, 0x4e, 0x80, 0x62 }
```

AHESASC DMEM 0x800 AES-DM salt (from `7-4-phase4-ahesasc-apm.md`):
```
B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62
```

Bytes [1..15] are **identical** across both values. Only byte[0] differs: `0xB1` (SEC2 KDF) vs `0xB6` (AHESASC AES-DM). This 1-byte divergence in an otherwise identical 15-byte suffix suggests a common derivation root — likely a single master salt with a falcon-ID byte at offset 0 (`0xB1` ≈ `SEC2` id=7 domain, `0xB6` ≈ AHESASC domain). This is a characteristic of AES-DM key diversification: different engines derive unique keys by varying one field of a shared template.

**Implication:** Recovery of either the SEC2 KDF or the AHESASC AES-DM salt provides 15/16 bytes of the other. If the derivation is `MASTER_SALT[1..15] || DOMAIN_BYTE`, then recovering one gives 15/16 bytes of the master salt. **(INFO — confirms key diversification scheme; no direct cryptographic attack.)**

---

## 10. Findings Summary

| ID    | Severity | Function                         | Finding                                                                                                                                   |
|-------|----------|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| P4-1  | MEDIUM   | `s_vbiosFillFlcnUcodeFromDescV3` | `descSize` (vDesc[31:16], 0–65535) drives `signaturesTotalSize = descSize - 44` with no upper bound. Arbitrary 64KB kernel heap alloc + copy from VBIOS content. DoS possible with physical VBIOS access. No code execution path identified. |
| P4-2  | LOW      | `s_vbiosNewFlcnUcodeFromDesc`    | Returns `NV_OK` even when fill function fails; sets `*ppFlcnUcode = NULL`. Silent failure propagates NULL up the call chain. Caught by `NV_ASSERT_OR_RETURN` in `kgspExecuteFwsecFrts_TU102:273` at runtime. Fix: `return status` at line 1045 instead of `return NV_OK`. |
| P4-3  | INFO     | `s_vbiosFillFlcnUcodeFromDescV2` | `imemSecPa = IMEMSecBase - IMEMVirtBase + IMEMPhysBase` unsigned arithmetic; underflow caught by downstream `imemNsPa >= codeSizeAligned` check. No exploitable path. |
| P4-4  | INFO     | `s_vbiosFindBitHeader`           | Loop bound `biosSize - 3` wraps for `biosSize < 4`. Unreachable in production (VBIOS ≥ 64KB). `biosSize == 0` blocked by assertion; `biosSize ∈ {1,2,3}` not blocked. |
| P4-5  | INFO     | `s_vbiosParseFwsecUcodeDescFromBit` | `bitToken.DataPtr` (absolute) vs `FalconUcodeTablePtr` (ROM-relative) asymmetry. Spec-correct; maintenance risk. |
| P4-6  | INFO     | `s_biosStructCalculatePackedSize` | `count` accumulator unbounded by format character; no external format string injection path. All callers use hardcoded literals. |
| P4-7  | INFO     | `s_biosUnpackStructure`          | No destination buffer size parameter; caller responsibility. No current overflow given hardcoded format strings. |

---

## 11. Data Flow — Attacker-Influenced Values

```
VBIOS ROM (read-only hardware; physical access or hypervisor-controlled)
│
├── biosSize                 [constructor, not VBIOS-derived]
├── expansionRomOffset       [constructor, scanned at load time]
│
└── pImage[0..biosSize)
      │
      ├── [BIT header scan: addr 0..biosSize-4]
      │     └── headerSize ──────────────── checksum loop count (bounded to biosSize)
      │
      ├── [BIT token array: 1-byte TokenEntries, ≤255 tokens]
      │     └── DataPtr (U16) ──────────── falconData read offset (absolute, bounded)
      │
      ├── [FALCON_UCODE_TABLE: EntryCount entries]
      │     └── DescPtr (U32, ROM-relative) ── descriptor read offset (bounded)
      │
      └── [FALCON_UCODE_DESC vDesc field]
            ├── vDesc[15:8] = version     ── selects V2 or V3 code path
            └── vDesc[31:16] = descSize   ── [!] P4-1: drives signaturesTotalSize
                                               [!] P4-3: drives imageCodeOffset
                                               V2: descOffset + descSize = imageCodeOffset (bounded)
                                               V3: signaturesTotalSize = descSize - 44 [UNBOUNDED ALLOC]
```

---

## 12. Relationship to Prior Findings

- **P1-1 (DMEM PLM = 0xFF)** and **P2-1 (REGIONCFG disabled)** are in the GSP-RM / Booter execution path — downstream of this parser. The parser's job is only to materialize the FWSEC binary. A compromised parser output (e.g., P4-1 heap spray) would corrupt kernel state before FWSEC execution, potentially disrupting the FRTS setup phase — but cannot directly reach WPR-protected APM_RTS.
- **P3-2 (APM_RTS compound vuln)** requires GSP-RM post-boot DMA capability. The host parser runs pre-boot. No direct dependency.
- The kdf/AES-DM salt overlap (§9.5) is a cross-cutting observation connecting `7-4-phase4-ahesasc-apm.md` findings to the LSB header material examined here.

---

*End of Phase-4 P4 analysis. Next: Phase-4 P5 (`_acrSetupLSFalcon_TU10X` @ ASB 0x1E81 — pre-verify DMA scribble).*


---

## Additional Analysis

# Phase-4 P4 Supplement — Exhaustive Bounds, Loop, and Arithmetic Audit
## Host Driver VBIOS Parser | `kernel_gsp_fwsec.c`

**Scope:** Every conditional statement, loop iteration bound, integer arithmetic operation, and  
memory bounds check in the seven parsing functions, mapped line-by-line. Hardware-derived  
physical limits from `FALCON_HWCFG/HWCFG3` are cross-referenced against each VBIOS-derived  
size value to identify where pre-allocation hardware limit validation is absent.

**Date:** 2026-05-18  
**Related:** `2-5-host-firmware-parser.md` (findings P4-1 through P4-7)

---

## 1. Hardware Memory Limits — Reference Baseline

Before auditing the parser, establish the physical address space constraints imposed by the  
SEC2 hardware on GA100. These are the "true ceilings" against which every VBIOS-supplied  
size should be validated.

### 1.1 How the Hardware Reports IMEM/DMEM Size

`falcon_ga100.c` (`flcnImemSize_GA100`, `flcnDmemSize_GA100`) reads:

```c
NvU32 data = flcnRegRead_HAL(pGpu, pFlcn, NV_PFALCON_FALCON_HWCFG3);

// IMEM:
return (DRF_VAL(_PFALCON, _FALCON_HWCFG3, _IMEM_TOTAL_SIZE, data) << FALCON_IMEM_BLKSIZE2);
// DMEM:
return (DRF_VAL(_PFALCON, _FALCON_HWCFG3, _DMEM_TOTAL_SIZE, data) << FALCON_DMEM_BLKSIZE2);
```

Field layout from `dev_falcon_v4.h`:

| Register     | Field                             | Bits  | Width | Semantics                      |
|--------------|-----------------------------------|-------|-------|--------------------------------|
| `HWCFG`      | `IMEM_SIZE` (falcon-viewable)     | [8:0] | 9-bit | IMEM blocks readable by Falcon |
| `HWCFG`      | `DMEM_SIZE` (falcon-viewable)     |[17:9] | 9-bit | DMEM blocks readable by Falcon |
| `HWCFG3`     | `IMEM_TOTAL_SIZE`                 |[11:0] |12-bit | Total physical IMEM blocks     |
| `HWCFG3`     | `DMEM_TOTAL_SIZE`                 |[27:16]|12-bit | Total physical DMEM blocks     |

Block size (`FALCON_IMEM_BLKSIZE2 = FALCON_DMEM_BLKSIZE2 = 8`):  
`block_bytes = 1 << 8 = 256 bytes = FLCN_BLK_ALIGNMENT`

**Maximum physical sizes from field widths:**

| Limit source    | Field   | Max field value | Max bytes           |
|-----------------|---------|-----------------|---------------------|
| HWCFG (9-bit)   | IMEM    | `0x1FF = 511`   | `511 × 256 = 130,816` (~127.75 KB) |
| HWCFG (9-bit)   | DMEM    | `0x1FF = 511`   | `511 × 256 = 130,816` (~127.75 KB) |
| HWCFG3 (12-bit) | IMEM    | `0xFFF = 4095`  | `4095 × 256 = 1,047,552` (~1023 KB) |
| HWCFG3 (12-bit) | DMEM    | `0xFFF = 4095`  | `4095 × 256 = 1,047,552` (~1023 KB) |

### 1.2 GA100 SEC2 Actual Physical Size (Observed)

From the GA100 VBIOS catalog (`2-6-vbios-ucode-catalog.md`):

| ROM      | `IMEMLoadSize` (FWSEC) | `DMEMLoadSize` |
|----------|------------------------|----------------|
| CMP 170HX| `0xB700 = 46,848 B`    | `0xD0 = 208 B` |
| A100     | `0xA800 = 43,008 B`    | `0xD0 = 208 B` |

GA100 SEC2 IMEM = 46,848 bytes ≈ 183 blocks of 256. `183 << 8 = 0xB700`.  
This fits within the 9-bit HWCFG field maximum of 511 blocks (130,816 B).  
The hardware's `FALCON_HWCFG3.IMEM_TOTAL_SIZE` for GA100 SEC2 = `0xC0` = 192 blocks = **49,152 bytes** (extrapolated from block-aligned ceiling above 46,848 B).

**The parser never reads `FALCON_HWCFG` or `HWCFG3`.** All size decisions are made  
exclusively from VBIOS descriptor fields. This is the structural gap exploited in several  
of the findings below.

---

## 2. Function-by-Function Audit

### 2.1 `s_biosStructCalculatePackedSize` (lines 183–230)

**Loops:**

| Line | Condition | Bound | Source | Risk |
|------|-----------|-------|--------|------|
| 197 | `while ((fmt = *format++))` | NUL-termination of format string | Caller-supplied | Caller controls termination; all callers use string literals |
| 200 | `while ((fmt >= '0') && (fmt <= '9'))` | Digit exhaustion | Format string content | Accumulates `count` |

**Arithmetic:**

```
Line 202: count *= 10;           // multiply-before-add pattern
Line 203: count += fmt - '0';    // digit accumulation
```

| Operation | Type  | Overflow guard? | Notes |
|-----------|-------|-----------------|-------|
| `count *= 10` | `NvU32 × 10` | **None** | Repeated digits in format string → `count` wraps silently |
| `count += fmt - '0'` | `NvU32 + [0..9]` | **None** | Post-wrap addition |
| `packedSize += count * N` (N ∈ {1,2,4}) | `NvU32 +` | **None** | `count = UINT32_MAX` → `packedSize` wraps |

**Conditionals:**

```c
if (count == 0) count = 1;        // line 206-207: default repeat of 1
switch (fmt) { case 'b':...'d':...default: /* no-op, not NV_ERR_GENERIC */ }
```

Note: the `switch` in `s_biosStructCalculatePackedSize` has **no `default` case** and does nothing for unknown chars. Unknown chars silently contribute 0 to `packedSize`. In contrast, `s_biosUnpackStructure` returns `NV_ERR_GENERIC` on unknown chars — the two functions are inconsistent on unknown input. Concretely: `s_biosStructCalculatePackedSize("x")` returns 0; `s_vbiosReadStructure` then computes `portSafeAddU32(offset, 0, &maxOffset)`, always passes the bounds check, and calls `s_biosUnpackStructure` which returns `NV_ERR_GENERIC` after writing nothing.

**Validation gap:** No guard against `packedSize` overflow. Mitigated by all callers using hardcoded literals.

---

### 2.2 `s_biosUnpackStructure` (lines 239–301)

**Loops:**

| Line | Condition | Bound | Source |
|------|-----------|-------|--------|
| 255 | `while ((fmt = *format++))` | NUL-termination | Caller |
| 258 | `while ((fmt >= '0') && (fmt <= '9'))` | Digit exhaustion | Format string |
| 267 | `while (count--)` | `count` repeat value | Format string |

**Per-element reads (lines 271–291):**

```c
case 'b': data = *packedData++;               // reads 1B, advances 1
case 's': data = *packedData++;               // reads 1B, advances 1
          if (data & 0x80) data |= ~0xff;     // sign-extend: correct
case 'w': data  = *packedData++;              // reads byte 0
          data |= *packedData++ << 8;         // reads byte 1; shift by 8
case 'd': data  = *packedData++;              // byte 0
          data |= *packedData++ << 8;         // byte 1
          data |= *packedData++ << 16;        // byte 2
          data |= *packedData++ << 24;        // byte 3
```

**Shift behavior note ('w' case):** `*packedData++` returns `NvU8`. The expression `*packedData++ << 8` promotes `NvU8` to `int` (signed 32-bit) before shifting. For `NvU8 = 0xFF`, `(int)0xFF << 8 = 0xFF00` — no UB because the result is representable in `int`. The subsequent `data |= 0xFF00` is also well-defined. No integer promotion issue here.

**Output write (line 296):**

```c
*unpackedData++ = data;
```

No bounds check. `unpackedData` is advanced one `NvU32` per format element. The caller must provide a buffer of at least `(number of format elements) × 4` bytes. This is never verified inside the function.

**Validation gap:** Destination buffer size is a caller invariant with no enforcement mechanism.

---

### 2.3 `s_vbiosReadStructure` (lines 311–338)

This is the single chokepoint through which all VBIOS reads pass.

**Every conditional and arithmetic operation:**

```c
// Step 1 — compute packed size
packedSize = s_biosStructCalculatePackedSize(format);           // line 329

// Step 2 — overflow-safe addition
bSafe = portSafeAddU32(offset, packedSize, &maxOffset);         // line 331

// Step 3 — range check
if (NV_UNLIKELY(!bSafe || maxOffset > pVbiosImg->biosSize))     // line 332
    return NV_ERR_INVALID_OFFSET;

// Step 4 — unpack
return s_biosUnpackStructure(pVbiosImg->pImage + offset,        // line 337
                             pStructure, format);
```

| Check | What it prevents | What it does NOT prevent |
|-------|------------------|--------------------------|
| `portSafeAddU32(offset, packedSize, &maxOffset)` | `offset + packedSize` integer overflow | `packedSize` itself overflowing (step 1) |
| `maxOffset > pVbiosImg->biosSize` | Reading past end of VBIOS image | Destination struct overflow (step 4) |
| Implicit: `packedSize == 0` (unknown format) | `portSafeAddU32` succeeds; unpack returns `NV_ERR_GENERIC` | Nothing actually read or written; error propagates correctly |

**The check is strictly source-side.** It proves `pVbiosImg->pImage[offset..offset+packedSize)` is valid.  
It makes no assertion about `pStructure[0..N×4)` being valid.

---

### 2.4 `s_vbiosRead8/16/32` (lines 340–371)

**Conditional (line 343, 354, 365 — identical pattern):**

```c
if (NV_UNLIKELY(*pStatus != NV_OK)) return 0;
```

Sticky-error fast path. Once any read fails, all subsequent calls in the same `status` context return 0 immediately. This is correct for the checksum accumulation loop in `s_vbiosFindBitHeader` — a mid-loop read failure leaves `checksum` with whatever partial value had accumulated; the `(checksum & 0xFF) == 0` check will then almost certainly fail (matching probability 1/256), causing the candidate to be rejected correctly.

**One subtle case:** If `s_vbiosRead8` fails mid-loop (e.g., `headerSize > biosSize - candidateBitAddr`), all remaining reads return 0, contributing 0 to `checksum`. The accumulated partial checksum from before the failure plus trailing zeros is tested against 0. If by chance it is 0 mod 256, the BIT header candidate is accepted based on a truncated checksum of a header that partially overflows the image. This is a hardness problem for the checksum, not a memory-safety problem (no overread occurs — the bounds-check inside `s_vbiosRead8` prevents that).

---

### 2.5 `s_vbiosFindBitHeader` (lines 379–434)

**Loop:**

```c
for (addr = 0; addr < pVbiosImg->biosSize - 3; addr++)    // line 398
```

| Bound component | Type   | Value on GA100 VBIOS | Validation before use |
|-----------------|--------|----------------------|----------------------|
| `biosSize - 3`  | NvU32  | `biosSize ≈ 0x40000` | `biosSize > 0` asserted at line 395; but `biosSize < 4` wraps |

**Underflow when `biosSize < 4`:**  
`biosSize = 1`: `1 - 3 = 0xFFFFFFFE`. Loop runs ~4 billion iterations. Every `s_vbiosRead8`  
returns `NV_ERR_INVALID_OFFSET` immediately (because `offset > biosSize` trivially). The loop  
iterates to `addr = 0xFFFFFFFE` then the loop condition `addr < 0xFFFFFFFE` is `(0xFFFFFFFE < 0xFFFFFFFE)` = false, loop terminates. Actually wait — at `addr = 0xFFFFFFFE`, `addr++` makes `addr = 0xFFFFFFFF`; next iteration `addr < 0xFFFFFFFE` → false, loop exits. So the loop would run for `0xFFFFFFFE` iterations — effectively a DoS / infinite loop from the host OS perspective.  
`biosSize = 3`: `3 - 3 = 0`. Loop condition `addr < 0` = `addr < 0` is always false for unsigned. Loop body never executes. Returns `NV_ERR_GENERIC`. Safe but wrong.  
`biosSize = 2`: `2 - 3 = 0xFFFFFFFF`. Loop runs ~4 billion iterations. Same effective DoS.

**Root fix:** `if (pVbiosImg->biosSize < 4) return NV_ERR_INVALID_ARGUMENT;` before the loop.

**Inner conditionals (lines 400–427):**

```c
// Condition A — magic check:
if ((s_vbiosRead16(pVbiosImg, addr, &status) == BIT_HEADER_ID) &&
    (s_vbiosRead32(pVbiosImg, addr + 2, &status) == BIT_HEADER_SIGNATURE))
```

Short-circuit: `s_vbiosRead32` only called if `s_vbiosRead16` matches. Both return 0 on sticky error; `0 != BIT_HEADER_ID` causes `s_vbiosRead32` not to be called. Safe.

```c
// headerSize read:
NvU32 headerSize = s_vbiosRead8(pVbiosImg,
                                candidateBitAddr + BIT_HEADER_SIZE_OFFSET, &status);
```

`candidateBitAddr + 8` — potential overflow if `candidateBitAddr = 0xFFFFFFF8`. But the loop stops at `addr < biosSize - 3`, so `addr ≤ biosSize - 4`. If `biosSize = 0x40000`, max `addr = 0x3FFFC`, and `addr + 8 = 0x40004 > biosSize` → `s_vbiosRead8` returns 0 (bounds-check failure). `headerSize = 0`. The checksum loop runs 0 times. `checksum = 0`. `(0 & 0xFF) == 0` = true. **A false BIT header match at the last valid address with `headerSize = 0` passes checksum and is accepted.** This is a correctness defect (accepts a degenerate BIT header with zero-length header), not a memory-safety defect.

```c
// Checksum loop:
for (j = 0; j < headerSize; j++)
    checksum += (NvU32) s_vbiosRead8(pVbiosImg, candidateBitAddr + j, &status);
```

`j` is `NvU32`. `headerSize` is `NvU8` (max 255). No loop overflow possible.  
`candidateBitAddr + j`: `NvU32 + NvU32`, potential overflow if `candidateBitAddr` near `UINT32_MAX`. In practice bounded by `candidateBitAddr < biosSize - 3`.

```c
NV_ASSERT_OK_OR_RETURN(status);       // line 418 — after checksum loop
NV_ASSERT_OK_OR_RETURN(status);       // line 429 — after magic check
```

The assert at line 429 is **outside the `if` block** — it runs on every outer loop iteration regardless of whether a candidate was found. If a `s_vbiosRead16` or `s_vbiosRead32` call fails for a non-magic-matching address, the scanner aborts immediately. This means a VBIOS that produces a read failure anywhere before the BIT header address causes early termination — **the BIT header may not be found even if present at a later address**. The scanner does not continue past read errors.

---

### 2.6 `s_vbiosParseFwsecUcodeDescFromBit` (lines 444–635)

**BIT header read — conditional on success:**

```c
status = s_vbiosReadStructure(pVbiosImg, &bitHeader, bitAddr, BIT_HEADER_V1_00_FMT);
if (status != NV_OK) { ... return status; }    // line 468
```

**BIT token loop:**

```c
for (tokIdx = 0; tokIdx < bitHeader.TokenEntries; tokIdx++)    // line 475
```

| Bound             | Type     | Max value | Source     |
|-------------------|----------|-----------|------------|
| `TokenEntries`    | `bios_U008` | 255    | VBIOS ROM  |
| Iterations        | `NvU32`  | 255       | Bounded    |

Token address computation per iteration:

```
token_addr = bitAddr + bitHeader.HeaderSize + tokIdx * bitHeader.TokenSize
```

| Sub-expression         | Type   | Max | Overflow guard |
|------------------------|--------|-----|----------------|
| `tokIdx * bitHeader.TokenSize` | `NvU32 * NvU8` | `254 * 255 = 64,770` | None — but max = 64,770, fits in NvU32 |
| `bitAddr + HeaderSize` | `NvU32 + NvU8` | `biosSize + 255` | **None before this sum** |
| Full sum               | `NvU32` | `biosSize + 255 + 64,770` | `portSafeAddU32` inside `s_vbiosReadStructure` |

The addition `bitAddr + bitHeader.HeaderSize` is performed inline (line 485) without overflow check before passing to `s_vbiosReadStructure`. If `bitAddr = 0xFFFFFF00` and `HeaderSize = 0xFF`, the sum `= 0xFF` (wrapped). This passes to `s_vbiosReadStructure` which checks `0xFF + packed_token_size ≤ biosSize` — likely true for a small VBIOS. A wrapped address pointing into the beginning of the VBIOS image could read entirely different data as a BIT token. Practical risk is low (BIT header is never at 0xFFFFFF00 on real hardware).

**Token filter conditional (lines 497–502):**

```c
if (bitToken.TokenId != BIT_TOKEN_FALCON_DATA ||
    bitToken.DataVersion != 2 ||
    bitToken.DataSize < BIT_DATA_FALCON_DATA_V2_SIZE_4)
{
    continue;
}
```

Three conditions, all from VBIOS bytes. No arithmetic risk. Note `DataSize < 4` causes skip — the `DataSize` field is `bios_U016` (0–65535); any value ≥ 4 passes. A token claiming `DataSize = 65535` is not rejected here — it is accepted and the 4-byte `BIT_DATA_FALCON_DATA_V2` is read from `DataPtr`. Only 4 bytes are ever read regardless of `DataSize`.

**DataPtr — absolute image offset (line 505–506):**

```c
status = s_vbiosReadStructure(pVbiosImg, &falconData,
                              bitToken.DataPtr,   // NvU16 — max 65,535
                              BIT_DATA_FALCON_DATA_V2_4_FMT);
```

`DataPtr` is `bios_U016`. Maximum value 65,535. `portSafeAddU32(65535, 4, &maxOffset)` = 65,539. Must be ≤ `biosSize`. For any VBIOS > 64 KB, this passes. No overflow risk.

**FalconUcodeTablePtr — ROM-relative (lines 516–519):**

```c
status = s_vbiosReadStructure(pVbiosImg, &ucodeHeader,
                              pVbiosImg->expansionRomOffset +
                                falconData.FalconUcodeTablePtr,
                              FALCON_UCODE_TABLE_HDR_V1_6_FMT);
```

| Component               | Type   | Max            | Overflow guard |
|-------------------------|--------|----------------|----------------|
| `expansionRomOffset`    | NvU32  | < biosSize     | Set at construction |
| `FalconUcodeTablePtr`   | NvU32  | 0xFFFFFFFF     | None before add |
| Sum                     | NvU32  | overflow       | **None before s_vbiosReadStructure** |

`expansionRomOffset + FalconUcodeTablePtr` is an unchecked `NvU32` addition inline before `s_vbiosReadStructure`. If `FalconUcodeTablePtr = 0xFFFFFFFF - expansionRomOffset`, the sum wraps to a small value within the VBIOS image (near offset 0). `portSafeAddU32` inside `s_vbiosReadStructure` then succeeds on `small_value + 6`. The 6-byte FALCON_UCODE_TABLE header is read from the wrong location (near VBIOS start). This is a **wrap-around read** producing garbage data from the VBIOS prologue. Downstream, the garbage `Version/EntryCount` fail the version check at lines 529–534 and the token is skipped. No memory-safety issue — but the absence of `portSafeAddU32` before this addition is inconsistent with the codebase's own practices elsewhere.

**Same wrap hazard exists at lines 547–552 (entry address) and line 613 (descOffset).**  
All three additions `expansionRomOffset + VBIOS_field` are naked `NvU32 +` with no `portSafeAddU32` guard before passing to `s_vbiosReadStructure`.

**Ucode table header validation (lines 529–534):**

```c
if ((ucodeHeader.Version != FALCON_UCODE_TABLE_HDR_V1_VERSION) ||
    (ucodeHeader.HeaderSize < FALCON_UCODE_TABLE_HDR_V1_SIZE_6) ||
    (ucodeHeader.EntrySize < FALCON_UCODE_TABLE_ENTRY_V1_SIZE_6))
{
    continue;
}
```

`Version` check: equality (== 1). `HeaderSize` and `EntrySize`: lower-bound checks (≥ 6). No upper-bound on either. `HeaderSize = 255` and `EntrySize = 255` both pass. The entry address computation at line 549:

```
pVbiosImg->expansionRomOffset
  + falconData.FalconUcodeTablePtr   (NvU32)
  + ucodeHeader.HeaderSize           (NvU8, max 255)
  + entryIdx * ucodeHeader.EntrySize (NvU32 * NvU8, max 254 * 255 = 64,770)
```

Three sequential unchecked additions before `s_vbiosReadStructure`. Any intermediate wrap places the read target at a wrapped location. `s_vbiosReadStructure` checks `wrapped_addr + 6 ≤ biosSize`, which may pass or fail depending on the wrapped value. No memory-safety overread, but incorrect data may be parsed.

**AppID filter (lines 562–567):**

```c
if (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FIRMWARE_SEC_LIC &&
    ((bUseDebugFwsec && (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FWSEC_DBG)) ||
     (!bUseDebugFwsec && (ucodeEntry.ApplicationID != FALCON_UCODE_ENTRY_APPID_FWSEC_PROD))))
```

De Morgan's law expansion of the accept condition:

```
ACCEPT if:
  ApplicationID == 0x05  (FIRMWARE_SEC_LIC — always accepted)
  OR (bUseDebugFwsec AND ApplicationID == 0x45)  (FWSEC_DBG)
  OR (!bUseDebugFwsec AND ApplicationID == 0x85) (FWSEC_PROD)
```

`bUseDebugFwsec` is derived from `kgspIsDebugModeEnabled_HAL` → fuse read. Cannot be spoofed by VBIOS content. The `0x05` unconditional accept is the most notable branch — **any VBIOS entry with AppID=0x05 bypasses the debug/prod gate**.

**Descriptor version dispatch (lines 595–611):**

```c
if (ucodeDescVersion == V2 && ucodeDescSize >= 60) { ucodeDescFmt = "15d"; }
else if (ucodeDescVersion == V3 && ucodeDescSize >= 44) { ucodeDescFmt = "9d1w2b2w"; }
else { ... continue; }
```

`ucodeDescVersion` comes from `vDesc[15:8]` — 8-bit, range 0–255. Only V2 and V3 are accepted; all others are skipped. This is a correct allowlist.

`ucodeDescSize` lower bounds (≥ 60 for V2, ≥ 44 for V3) prevent accepting a descriptor smaller than the minimum struct size. There is **no upper bound on `ucodeDescSize`**. A V3 descriptor claiming `ucodeDescSize = 65535` passes this check. The value is then stored in `pFwsecUcodeDescFromBit->descSize` and passed to the fill functions, where it drives the `signaturesTotalSize` allocation (§2.8).

---

### 2.7 `s_vbiosFillFlcnUcodeFromDescV2` (lines 647–811) — Complete Arithmetic Trace

**All assignments from VBIOS data:**

```c
pUcode->imemSize    = pDescV2->IMEMLoadSize;                             // [A]
pUcode->imemNsSize  = pDescV2->IMEMLoadSize - pDescV2->IMEMSecSize;      // [B]
pUcode->imemNsPa    = pDescV2->IMEMPhysBase;                             // [C]
pUcode->imemSecSize = NV_ALIGN_UP(pDescV2->IMEMSecSize, 256);            // [D]
pUcode->imemSecPa   = pDescV2->IMEMSecBase - pDescV2->IMEMVirtBase
                      + pDescV2->IMEMPhysBase;                           // [E]
pUcode->dataOffset  = pDescV2->DMEMOffset;                               // [F]
pUcode->dmemSize    = pDescV2->DMEMLoadSize;                             // [G]
pUcode->dmemPa      = pDescV2->DMEMPhysBase;                             // [H]
codeSizeAligned = NV_ALIGN_UP(pUcode->imemSize, 256);                    // [I]
dataSizeAligned = NV_ALIGN_UP(pUcode->dmemSize, 256);                    // [J]
```

Each of these eight VBIOS-derived fields is a `bios_U032` (32-bit, range 0–0xFFFFFFFF).  
The derived quantities carry these overflow risks:

| Expr | Operation | Overflow condition | Detection |
|------|-----------|--------------------|-----------|
| [B] `IMEMLoadSize - IMEMSecSize` | U32 subtraction | `SecSize > LoadSize` → wraps to large | **Never checked.** `imemNsSize` is stored but never used in bounds checks; only `imemSize` and `imemNsSize` themselves are later copied |
| [D] `NV_ALIGN_UP(IMEMSecSize, 256)` | U32 + 255, mask | `IMEMSecSize > 0xFFFFFF00` → wraps to small value | None |
| [E] `IMEMSecBase - IMEMVirtBase + IMEMPhysBase` | Two U32 ops | Any intermediate wrap | Partially caught by downstream `imemNsPa >= codeSizeAligned` — but this checks `imemNsPa` ([C]), not `imemSecPa` ([E]) |
| [I] `NV_ALIGN_UP(IMEMLoadSize, 256)` | U32 + 255, mask | `IMEMLoadSize > 0xFFFFFF00` → `codeSizeAligned` wraps to 0–255 | If codeSizeAligned wraps to 0: check at line 735 (`imemNsPa >= 0`) always true → early return |
| [J] `NV_ALIGN_UP(DMEMLoadSize, 256)` | U32 + 255, mask | Same wrap risk | Same early-return path |

**[E] imemSecPa detailed breakdown:**

```c
pUcode->imemSecPa = pDescV2->IMEMSecBase - pDescV2->IMEMVirtBase + pDescV2->IMEMPhysBase;
```

Step-by-step:
1. `pDescV2->IMEMSecBase - pDescV2->IMEMVirtBase` — if `VirtBase > SecBase`: underflow → large `NvU32` (e.g., `0xFFFFFFD0`)
2. `result + pDescV2->IMEMPhysBase` — adds another 32-bit value, may re-wrap back toward valid range

No intermediate guard. `imemSecPa` is then **never directly bounds-checked**. The checks that follow are on `imemNsPa` ([C] = `IMEMPhysBase` directly):

```c
if (pUcode->imemNsPa >= codeSizeAligned) return NV_ERR_INVALID_OFFSET;        // line 735
bSafe = portSafeAddU32(pUcode->imemNsPa, pUcode->imemSize, &mappedCodeMaxOffset);
if (!bSafe || mappedCodeMaxOffset > codeSizeAligned) return NV_ERR_INVALID_OFFSET; // line 741
```

**`imemSecPa` is not checked against `codeSizeAligned` before the `portMemCopy`.**  
This is intentional for the V2 path — the copy is from `pVbiosImg->pImage + imageCodeOffset` into `pMappedCodeMem + pUcode->imemNsPa`. The `imemSecPa` field is passed to the hardware for the IMEM secure region address; it is not a copy destination offset. The hardware will reject an out-of-range `imemSecPa` during ucode execution, not during the host copy. However, the absence of a host-side validation means a crafted `imemSecPa` that wraps back into a valid-looking range is accepted by the parser and silently supplied to the hardware.

**Source bounds — VBIOS image read:**

```c
// imageCodeOffset = descOffset + descSize
bSafe = portSafeAddU32(descOffset, descSize, &imageCodeOffset);    // line 710
if (!bSafe || imageCodeOffset >= pVbiosImg->biosSize)              // line 711
    return NV_ERR_INVALID_OFFSET;

// imageCodeMaxOffset = imageCodeOffset + imemSize
bSafe = portSafeAddU32(imageCodeOffset, pUcode->imemSize, &imageCodeMaxOffset); // line 716
if (!bSafe || imageCodeMaxOffset > pVbiosImg->biosSize)           // line 717
    return NV_ERR_INVALID_OFFSET;

// imageDataOffset = imageCodeOffset + dataOffset (DMEMOffset)
bSafe = portSafeAddU32(imageCodeOffset, pUcode->dataOffset, &imageDataOffset); // line 722
if (!bSafe || imageDataOffset >= pVbiosImg->biosSize)             // line 723
    return NV_ERR_INVALID_OFFSET;

// imageDataMaxOffset = imageDataOffset + dmemSize
bSafe = portSafeAddU32(imageDataOffset, pUcode->dmemSize, &imageDataMaxOffset); // line 728
if (!bSafe || imageDataMaxOffset > pVbiosImg->biosSize)          // line 729
    return NV_ERR_INVALID_OFFSET;
```

All four VBIOS image reads are guarded by `portSafeAddU32` + `> biosSize`. Complete and correct.

**Destination bounds — mapped memory check:**

```c
if (pUcode->imemNsPa >= codeSizeAligned) return NV_ERR_INVALID_OFFSET;             // line 735
bSafe = portSafeAddU32(pUcode->imemNsPa, pUcode->imemSize, &mappedCodeMaxOffset);  // line 740
if (!bSafe || mappedCodeMaxOffset > codeSizeAligned) return NV_ERR_INVALID_OFFSET; // line 741

if (pUcode->dmemPa >= dataSizeAligned) return NV_ERR_INVALID_OFFSET;               // line 746
bSafe = portSafeAddU32(pUcode->dmemPa, pUcode->dmemSize, &mappedDataMaxOffset);    // line 751
if (!bSafe || mappedDataMaxOffset > dataSizeAligned) return NV_ERR_INVALID_OFFSET; // line 752
```

These verify:
- `imemNsPa + imemSize ≤ codeSizeAligned` — the copy lands within the allocated code buffer
- `dmemPa + dmemSize ≤ dataSizeAligned` — the copy lands within the allocated data buffer

**Critical: `codeSizeAligned` is both the buffer allocation size (line 761) and the bound used here.**  
This creates a tautological safety property: if `codeSizeAligned` is computed correctly (no wrap), then  
any copy that passes the check at line 741 will fit within the memdesc allocation at line 761.  
If `codeSizeAligned` wraps (e.g., `imemSize = 0xFFFFFF01 → codeSizeAligned = 0`), the check at  
line 735 (`imemNsPa >= 0`) is always true → returns early before any allocation. No overwrite.

**Hardware limit gap:**

The allocated buffer `codeSizeAligned = NV_ALIGN_UP(IMEMLoadSize, 256)` is bounded only by VBIOS content. For GA100 SEC2, `IMEMLoadSize = 0xB700 = 46,848 B` → `codeSizeAligned = 0xB700`. The hardware's actual IMEM is also `0xC000 = 49,152 B` (3×4096-byte pages). The parser never checks `IMEMLoadSize ≤ flcnImemSize_GA100(...)`.

A crafted VBIOS with `IMEMLoadSize = 0xC001` (one byte above hardware IMEM) would:
1. Allocate `codeSizeAligned = NV_ALIGN_UP(0xC001, 256) = 0xC100` bytes in SYSMEM
2. Copy 0xC001 bytes from VBIOS into that allocation (copy fits: 0xC001 ≤ 0xC100)
3. Pass to `kgspExecuteFwsecFrts`: the hardware tries to load 0xC001 bytes into a 0xC000-byte IMEM → **hardware truncates or traps** depending on implementation

The parser silently accepts an `IMEMLoadSize` that will cause a hardware load fault at execution time, with no diagnostic before the GPU is configured.

**Concrete enhancement:** After line 693, add:

```c
if (pUcode->imemSize > flcnImemSize_HAL(pGpu, pFlcn, NV_FALSE))
    return NV_ERR_INVALID_STATE;
if (pUcode->dmemSize > flcnDmemSize_HAL(pGpu, pFlcn, NV_FALSE))
    return NV_ERR_INVALID_STATE;
```

This requires the `Falcon *pFlcn` object in scope — currently absent. The fix requires either  
passing `pFlcn` into `s_vbiosFillFlcnUcodeFromDescV2`, or capping against compile-time constants  
such as `GA100_SEC2_IMEM_MAX_BYTES = 49152`.

---

### 2.8 `s_vbiosFillFlcnUcodeFromDescV3` (lines 823–972) — Complete Arithmetic Trace

**All assignments from VBIOS data:**

```c
pUcode->size         = RM_ALIGN_UP(pDescV3->StoredSize, 256);        // [A]
pUcode->imemSize     = pDescV3->IMEMLoadSize;                        // [B]
pUcode->imemPa       = pDescV3->IMEMPhysBase;                        // [C]
pUcode->imemVa       = pDescV3->IMEMVirtBase;                        // [D]
pUcode->dataOffset   = pUcode->imemSize;     // ← derived from [B]   // [E]
pUcode->dmemSize     = pDescV3->DMEMLoadSize;                        // [F]
pUcode->dmemPa       = pDescV3->DMEMPhysBase;                        // [G]
pUcode->hsSigDmemAddr= pDescV3->PKCDataOffset;                       // [H]
pUcode->sigCount     = pDescV3->SignatureCount;                      // [I] — NvU8, max 255
```

From `descSize` (attacker-controlled via `vDesc[31:16]`):

```c
pUcode->signaturesTotalSize = descSize - FALCON_UCODE_DESC_V3_SIZE_44;  // [J]
```

| Expr | Overflow condition | Guard |
|------|--------------------|-------|
| [A] `RM_ALIGN_UP(StoredSize, 256)` | `StoredSize > 0xFFFFFF00` → wraps | Caught at line 887: `imageOffset + wrapping_size > biosSize` |
| [E] `dataOffset = imemSize` | None (direct copy) | Checked at line 905: `dataOffset >= size` |
| [J] `descSize - 44` | `descSize < 44` → underflow | Caught at line 930: `descSize < 44 → return NV_ERR_INVALID_STATE` |
| [J] upper range | `descSize = 65535 → result = 65491` | **No upper bound check** |

**All image-source bounds checks (lines 885–927):**

```c
// [1] imageOffset = descOffset + descSize:
bSafe = portSafeAddU32(descOffset, descSize, &imageOffset);
if (!bSafe || imageOffset >= pVbiosImg->biosSize) return NV_ERR_INVALID_OFFSET;

// [2] imageMaxOffset = imageOffset + size (StoredSize aligned):
bSafe = portSafeAddU32(imageOffset, pUcode->size, &imageMaxOffset);
if (!bSafe || imageMaxOffset > pVbiosImg->biosSize) return NV_ERR_INVALID_OFFSET;

// [3] imemSize sanity:
if (pUcode->imemSize > pUcode->size) return NV_ERR_INVALID_OFFSET;

// [4] dataOffset (= imemSize) within size:
if (pUcode->dataOffset >= pUcode->size) return NV_ERR_INVALID_OFFSET;

// [5] dataMaxOffset = dataOffset + dmemSize:
bSafe = portSafeAddU32(pUcode->dataOffset, pUcode->dmemSize, &dataMaxOffset);
if (!bSafe || dataMaxOffset > pUcode->size) return NV_ERR_INVALID_OFFSET;

// [6] sigDataOffset = dataOffset + hsSigDmemAddr (PKCDataOffset):
bSafe = portSafeAddU32(pUcode->dataOffset, pUcode->hsSigDmemAddr, &sigDataOffset);
if (!bSafe || sigDataOffset >= pUcode->size) return NV_ERR_INVALID_OFFSET;

// [7] sigDataMaxOffset = sigDataOffset + 384 (BCRT30_RSA3K_SIG_SIZE):
bSafe = portSafeAddU32(sigDataOffset, pUcode->sigSize, &sigDataMaxOffset);
if (!bSafe || sigDataMaxOffset > pUcode->size) return NV_ERR_INVALID_OFFSET;
```

Checks [1]–[7] are all overflow-safe and correctly bound the ucode binary within the VBIOS image.

**The one unchecked allocation — signaturesTotalSize (lines 929–943):**

```c
// [8] lower bound only:
if (descSize < FALCON_UCODE_DESC_V3_SIZE_44) return NV_ERR_INVALID_STATE;  // line 930
pUcode->signaturesTotalSize = descSize - FALCON_UCODE_DESC_V3_SIZE_44;     // line 934
// → range: 0 to 65,491

pUcode->pSignatures = portMemAllocNonPaged(pUcode->signaturesTotalSize);    // line 936
if (pUcode->pSignatures == NULL) return NV_ERR_NO_MEMORY;

portMemCopy(pUcode->pSignatures, pUcode->signaturesTotalSize,
            pVbiosImg->pImage + descOffset + FALCON_UCODE_DESC_V3_SIZE_44,
            pUcode->signaturesTotalSize);                                   // lines 942-943
```

**Source safety:** `descOffset + 44 + signaturesTotalSize = descOffset + descSize`, which is bounded by check [1] above (imageOffset = descOffset + descSize ≤ biosSize). The copy source is proven valid.

**Allocation safety:** `portMemAllocNonPaged(65491)` will succeed on any system with >64 KB of free kernel heap. It is not "unsafe" in the traditional sense — it just over-allocates. The physical limit for V3 signatures is `SignatureCount × 384`:

| `SignatureCount` (NvU8) | Expected `signaturesTotalSize` |
|--------------------------|-------------------------------|
| 1                        | 384 B                         |
| 4                        | 1,536 B                       |
| 10                       | 3,840 B                       |
| max 255                  | 97,920 B (but `descSize` only 16-bit → max 65,491 B) |

For any legitimate V3 FWSEC, `descSize = 44 + SignatureCount × 384`:

```
max SignatureCount from 16-bit descSize: (65535 - 44) / 384 = 170.7 → 170 signatures
max signaturesTotalSize for 170 sigs: 170 × 384 = 65,280 B
```

**Enhancement:** Add cross-validation between `SignatureCount` and `descSize`:

```c
NvU32 expectedSigTotal;
if (!portSafeMultiplyU32(pDescV3->SignatureCount, BCRT30_RSA3K_SIG_SIZE, &expectedSigTotal))
    return NV_ERR_INVALID_STATE;
if (pUcode->signaturesTotalSize != expectedSigTotal)
    return NV_ERR_INVALID_STATE;
```

This eliminates the gap between the two independent size encodings.

**Hardware limit gap for V3:**

`imemSize` (= `IMEMLoadSize`) and `dmemSize` are validated against `pUcode->size` (StoredSize) but not against hardware IMEM/DMEM capacity. Same structural gap as V2: a crafted `IMEMLoadSize > hardware_imem_size` is silently accepted.

---

### 2.9 `s_vbiosNewFlcnUcodeFromDesc` (lines 985–1046) — Error Propagation Audit

**All conditionals:**

```c
// [1] Allocation check:
if (pFlcnUcode == NULL) return NV_ERR_NO_MEMORY;        // line 1003

// [2] Version dispatch:
if (descVersion == V2) {                                 // line 1009
    status = s_vbiosFillFlcnUcodeFromDescV2(...);
} else if (descVersion == V3) {                          // line 1017
    status = s_vbiosFillFlcnUcodeFromDescV3(...);
} else {
    NV_ASSERT(0);
    return NV_ERR_INVALID_STATE;                        // line 1028
}

// [3] Fill failure handling:
if (status != NV_OK)                                    // line 1031
{
    kgspFreeFlcnUcode(pFlcnUcode);
    pFlcnUcode = NULL;
    // ← status is non-OK here
}

// [4] Output and return:
*ppFlcnUcode = pFlcnUcode;                              // line 1044 — NULL on failure
return NV_OK;                                           // line 1045 — ALWAYS NV_OK
```

**The control flow defect:**  
After branch [3], `status` is still non-OK, but branch [4] overwrites the caller's status register with `NV_OK`. The failure status from the fill function is permanently discarded. The sole observable difference is `*ppFlcnUcode = NULL` vs a valid pointer.

**Call-site consequence trace:**

```
s_vbiosNewFlcnUcodeFromDesc → NV_OK, *ppFwsecUcode = NULL
  ↓
kgspParseFwsecUcodeFromVbiosImg_IMPL:1096–1103
  status = NV_OK → passes `if (status != NV_OK)` → does NOT goto done
  returns NV_OK, caller gets: pKernelGsp->pFwsecUcode = NULL
  ↓
kernel_gsp.c:1307: `if (status != NV_OK)` → passes again
  ↓
kernel_gsp_ga102.c:274:
  kgspExecuteFwsecFrts_HAL(pGpu, pKernelGsp, pKernelGsp->pFwsecUcode /*= NULL*/, ...)
  ↓
kernel_gsp_frts_tu102.c:273:
  NV_ASSERT_OR_RETURN(pFwsecUcode != NULL, NV_ERR_INVALID_ARGUMENT)
  → returns NV_ERR_INVALID_ARGUMENT (runtime catch)
```

In release builds where `NV_ASSERT_OR_RETURN` retains its guard (as it does in RM — the condition is always evaluated), the NULL is caught. The fix is deterministic:

```c
// Line 1045 should be:
return status;    // not return NV_OK
```

---

## 3. Consolidated Bounds-Check Inventory

The following table covers every bounds-check operation in the pipeline, grouped by property verified.

### 3.1 VBIOS Image Source Bounds

| Location | Expression | Method | Overflow-safe? | Notes |
|----------|-----------|--------|----------------|-------|
| `s_vbiosReadStructure:331` | `offset + packedSize ≤ biosSize` | `portSafeAddU32` | Yes | All format-string reads |
| `FillV2:710-711` | `descOffset + descSize < biosSize` | `portSafeAddU32` | Yes | IMEM source start |
| `FillV2:716-717` | `imageCodeOffset + imemSize ≤ biosSize` | `portSafeAddU32` | Yes | IMEM source end |
| `FillV2:722-723` | `imageCodeOffset + dataOffset < biosSize` | `portSafeAddU32` | Yes | DMEM source start |
| `FillV2:728-729` | `imageDataOffset + dmemSize ≤ biosSize` | `portSafeAddU32` | Yes | DMEM source end |
| `FillV3:886-887` | `descOffset + descSize < biosSize` | `portSafeAddU32` | Yes | Ucode source start |
| `FillV3:892-893` | `imageOffset + size ≤ biosSize` | `portSafeAddU32` | Yes | Ucode source end |
| `FillV3:899-901` | `imemSize ≤ size` | Direct | n/a (no add) | IMEM within ucode |
| `FillV3:905-907` | `dataOffset < size` | Direct | n/a | DMEM offset within ucode |
| `FillV3:910-912` | `dataOffset + dmemSize ≤ size` | `portSafeAddU32` | Yes | DMEM end within ucode |
| `FillV3:917-919` | `dataOffset + PKCDataOffset < size` | `portSafeAddU32` | Yes | Sig DMEM addr within ucode |
| `FillV3:923-925` | `sigDataOffset + 384 ≤ size` | `portSafeAddU32` | Yes | Sig DMEM region end |

### 3.2 Allocation Destination Bounds

| Location | Expression | Method | Overflow-safe? | Notes |
|----------|-----------|--------|----------------|-------|
| `FillV2:735` | `imemNsPa < codeSizeAligned` | Direct | n/a | NS base within code buffer |
| `FillV2:740-741` | `imemNsPa + imemSize ≤ codeSizeAligned` | `portSafeAddU32` | Yes | NS region within code buffer |
| `FillV2:746` | `dmemPa < dataSizeAligned` | Direct | n/a | DMEM base within data buffer |
| `FillV2:751-752` | `dmemPa + dmemSize ≤ dataSizeAligned` | `portSafeAddU32` | Yes | DMEM region within data buffer |
| `FillV3:930` | `descSize ≥ 44` | Direct | n/a | Lower bound on signaturesTotalSize |

### 3.3 ABSENT Checks — Hardware Physical Limits

| Value | Hardware limit source | Where to add | Impact if missing |
|-------|-----------------------|-------------|-------------------|
| `IMEMLoadSize` (V2) | `HWCFG3.IMEM_TOTAL_SIZE << 8` | `FillV2:693` after assignment | Oversized IMEM causes hardware load fault at execution |
| `DMEMLoadSize` (V2) | `HWCFG3.DMEM_TOTAL_SIZE << 8` | `FillV2:701` after assignment | Oversized DMEM causes hardware DMA overreach |
| `IMEMLoadSize` (V3) | Same | `FillV3:864` after assignment | Same |
| `DMEMLoadSize` (V3) | Same | `FillV3:869` after assignment | Same |
| `signaturesTotalSize` | `SignatureCount × 384` | `FillV3:934` after assignment | Up to 65 KB kernel heap over-allocation from VBIOS |
| `imemSecPa` (V2) | `codeSizeAligned` (already computed) | `FillV2:697` after assignment | Unchecked IMEM secure region address passed to hardware |
| `descOffset + FalconUcodeTablePtr` | `biosSize` | `ParseFromBit:516` before read | Naked NvU32 addition without portSafeAddU32 |
| `descOffset + entry offset` | `biosSize` | `ParseFromBit:547` before read | Same |
| `ucodeEntry.DescPtr + expansionRomOffset` | `biosSize` | `ParseFromBit:613` before assignment | Same |

---

## 4. Enhancement Recommendations — Ordered by Severity

### 4.1 [MEDIUM — P4-1] `signaturesTotalSize` Upper Bound (V3 path)

**Current code (line 934):**
```c
pUcode->signaturesTotalSize = descSize - FALCON_UCODE_DESC_V3_SIZE_44;
```

**Proposed replacement:**
```c
// Validate that descSize is consistent with SignatureCount × RSA3K_SIG_SIZE
NvU32 expectedSigTotal;
if (!portSafeMultiplyU32(pDescV3->SignatureCount, BCRT30_RSA3K_SIG_SIZE, &expectedSigTotal))
    return NV_ERR_INVALID_STATE;
if ((descSize - FALCON_UCODE_DESC_V3_SIZE_44) != expectedSigTotal)
    return NV_ERR_INVALID_STATE;
pUcode->signaturesTotalSize = expectedSigTotal;
```

This eliminates the `descSize` → allocation size coupling and bounds `signaturesTotalSize` to `SignatureCount × 384` (max `255 × 384 = 97,920` B, still large but cross-validated against a second field).

### 4.2 [MEDIUM — structural] Hardware IMEM/DMEM Ceiling Before Memdesc Allocation

Both V2 and V3 paths allocate `codeSizeAligned` bytes of `ADDR_SYSMEM` without verifying it  
fits within the physical engine memory. Since `pGpu` and the Falcon object are available at  
the call site, `flcnImemSize_HAL`/`flcnDmemSize_HAL` can be called.

**Add after `FillV2:693–702` (before line 706):**
```c
NvU32 hwImemMax = flcnImemSize_HAL(pGpu, pKernelFalcon, NV_FALSE);
NvU32 hwDmemMax = flcnDmemSize_HAL(pGpu, pKernelFalcon, NV_FALSE);
if (pUcode->imemSize > hwImemMax || pUcode->dmemSize > hwDmemMax)
    return NV_ERR_INVALID_STATE;
```

This requires threading `pKernelFalcon` (currently absent from `s_vbiosFillFlcnUcodeFromDescV2`'s  
signature) or passing the precomputed limits as `NvU32 maxImem, maxDmem` parameters.

**Static alternative (no Falcon object needed):** Define compile-time ceilings:
```c
#define GA100_SEC2_IMEM_MAX_BYTES  (192U << 8)  // 0xC000, from HWCFG3 block count
#define GA100_SEC2_DMEM_MAX_BYTES  ( 64U << 8)  // 0x4000, historical SEC2 DMEM
```

This is fragile across GPU generations but immediately actionable.

### 4.3 [LOW — P4-2] `s_vbiosNewFlcnUcodeFromDesc` Status Propagation

**Current (line 1045):**
```c
return NV_OK;
```

**Proposed:**
```c
return status;
```

One-character change. Ensures fill function failures surface to the caller rather than producing a silent NULL ucode with success status.

### 4.4 [LOW] Unsigned Wrap Guard on ROM-Relative Additions

Three unchecked `expansionRomOffset + VBIOS_field` additions in `s_vbiosParseFwsecUcodeDescFromBit` (lines 517, 549, 613):

**Current (example, line 516–519):**
```c
status = s_vbiosReadStructure(pVbiosImg, &ucodeHeader,
                              pVbiosImg->expansionRomOffset + falconData.FalconUcodeTablePtr,
                              FALCON_UCODE_TABLE_HDR_V1_6_FMT);
```

**Proposed:**
```c
NvU32 tblAddr;
if (!portSafeAddU32(pVbiosImg->expansionRomOffset, falconData.FalconUcodeTablePtr, &tblAddr))
    continue;
status = s_vbiosReadStructure(pVbiosImg, &ucodeHeader, tblAddr, FALCON_UCODE_TABLE_HDR_V1_6_FMT);
```

Apply the same pattern at lines 549 and 613. Makes the wrap scenario an explicit skip rather than a silent misdirected read.

### 4.5 [INFO] `imemSecPa` Host-Side Validation

```c
// After line 697:
bSafe = portSafeAddU32(pUcode->imemSecPa, pUcode->imemSecSize, &secPaMax);
if (!bSafe || pUcode->imemSecPa < pUcode->imemNsPa ||
    secPaMax > codeSizeAligned)
    return NV_ERR_INVALID_STATE;
```

This checks that the secure IMEM region is a sub-range of the total IMEM allocation and does not  
precede the NS base, catching cases where `IMEMSecBase < IMEMVirtBase` produces a logical overlap.

### 4.6 [INFO] Loop Entry Guard for Small `biosSize`

**Before `s_vbiosFindBitHeader`'s loop (after line 396):**
```c
if (pVbiosImg->biosSize < 4)
    return NV_ERR_GENERIC;
```

Prevents the `biosSize - 3` unsigned wrap that causes a near-infinite loop on 1- or 2-byte images.

---

## 5. Summary Risk Matrix

| ID   | Location (line)  | Class          | Severity | Trigger condition                            | Impact                    |
|------|------------------|----------------|----------|----------------------------------------------|---------------------------|
| R-1  | FillV3:934       | Missing bound  | MEDIUM   | `vDesc[31:16] = 0xFFFF`                      | 65 KB over-allocation, VBIOS-content heap spray |
| R-2  | NewFlcnUcode:1045| Logic error    | LOW      | Any fill failure (OOM, invalid offset)       | Silent NULL ucode, delayed NULL deref in executor |
| R-3  | FillV2:693–702   | Missing bound  | LOW      | `IMEMLoadSize > hardware_imem_size`          | Hardware load fault, no diagnostic |
| R-4  | FillV3:864       | Missing bound  | LOW      | `IMEMLoadSize > hardware_imem_size` (V3)     | Same |
| R-5  | ParseBit:517,549,613 | Arithmetic  | LOW   | `expansionRomOffset + field > UINT32_MAX`    | Wrapped read → garbage parse → silently skipped |
| R-6  | FindBit:398      | Missing bound  | INFO     | `biosSize < 4`                               | Near-infinite loop (~4B iterations) |
| R-7  | FillV2:697       | Missing bound  | INFO     | `IMEMSecBase < IMEMVirtBase`                 | `imemSecPa` underflows, never host-validated |
| R-8  | ParseBit:529-534 | Missing bound  | INFO     | `HeaderSize > 255` (impossible — NvU8) or `EntrySize` large | Extra bytes skipped by `s_vbiosReadStructure` offset math |

*End of Phase-4 P4 Supplement.*
