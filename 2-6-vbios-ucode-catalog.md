# 2.6 — VBIOS Microcode Catalog

**Date:** 2026-05-17  
**ROMs:** CMP 170HX (`<GPU ROM archive>`), A100 (`<GPU ROM archive>`)  
**Analyst:** Phase-4 continuation from `7-3-phase4-booter-analysis.md`

---

## 1. Executive Summary

The VBIOS FALCON_DATA_V2 catalog embeds six Falcon ucodes in Image #2 of both the CMP 170HX and A100 ROMs. The ucodes are: PRE_OS/DEVINIT, FWSEC_DBG, FWSEC_PROD, HULK_DBG, HULK_PROD, and LS_UDE.

**Security-relevant findings:**
1. **FWSEC stored unencrypted in VBIOS** — `enc=0` in descriptor; VBIOS-level plaintext for both DBG and PROD variants. HS overlay is present but not VBIOS-encrypted (SEC2 self-decrypts internally).
2. **HULK has AES-encrypted HS overlay** — BL plaintext (entropy=5.50), HS tail encrypted (entropy=7.97). Standard Falcon HS image pattern. TargetID=5 (FBFalcon) is undocumented in `bit.h`.
3. **TargetID=7 (FWSEC/SEC2) is undocumented** — `bit.h` TARGET constants only define up to TargetID=3 (FECS). TargetID=5 and 7 are silent extensions.
4. **PRE_OS target reported as PMU (TargetID=1)** — DEVINIT runs on PMU for GA100; not a vulnerability but confirms PMU handles VBIOS init.

---

## 2. BIT Header Parsing

### CMP 170HX

```
Expansion ROM base:   file 0x5E00  (55 AA expansion ROM signature, 512B-aligned)
BIT header:           file 0x5EB0  (FF B8 magic)
BIT structure:        ver=1.0  hdr_sz=12  tok_sz=6  tok_cnt=16
```

BIT token 'p' (FALCON_DATA, id=0x70):
```
TokenID=0x70  DataVer=2  DataSize=4  DataPtr=0x02D9
BIT_DATA_FALCON_DATA_V2 @ file 0x5E00+0x02D9 = 0x60D9
  FalconUcodeTablePtr = 0x00006354
FALCON_UCODE_TABLE @ file 0x5E00+0x6354 = 0xC154
```

### A100

```
Expansion ROM base:   file 0x5000  (55 AA expansion ROM signature, 512B-aligned)
BIT header:           file 0x5EB0  (same relative offset as CMP — FF B8 magic)
BIT structure:        ver=1.0  hdr_sz=12  tok_sz=6  tok_cnt=16
```

BIT token 'p' (FALCON_DATA, id=0x70):
```
BIT_DATA_FALCON_DATA_V2 @ exp_off + DataPtr
  FalconUcodeTablePtr → FALCON_UCODE_TABLE @ file 0xAF44
```

### DataPtr Semantics

`BIT_TOKEN_V1_00.DataPtr` is **image-relative** (offset from expansion ROM base `55 AA`), not an absolute file offset. All descriptor pointers (`DescPtr` in table entries) are also expansion-ROM-relative.

Source confirmation: `kernel_gsp_fwsec.c:337`:
```c
s_vbiosReadStructure(pVbiosImg, &ucodeHeader,
    pVbiosImg->expansionRomOffset + falconData.FalconUcodeTablePtr, ...)
```

---

## 3. FALCON_UCODE_TABLE Header

```
FALCON_UCODE_TABLE_HDR_V1 @ file 0xC154 (CMP)
  Version:      1
  HeaderSize:   6
  EntrySize:    6
  EntryCount:   16
  DescVersion:  1  ← FALCON_UCODE_DESC_V1 (48 bytes)
  DescSize:     48
```

### Structure Definitions (from `bit.h`)

**FALCON_UCODE_TABLE_ENTRY_V1** (6 bytes):
```c
NvU8  ApplicationID;  // ucode function identifier
NvU8  TargetID;       // target Falcon engine
NvU32 DescPtr;        // exp-ROM-relative pointer to FALCON_UCODE_DESC_V1
```

**FALCON_UCODE_DESC_V1** (48 bytes):
```c
union { NvU32 HdrSzUn; NvU32 StoredSize; };  // bits[1:0]=flags (bit2=enc)
NvU32 UncompressedSize;
NvU32 VirtualEntry;
NvU32 InterfaceOffset;
NvU32 IMEMPhysBase;
NvU32 IMEMLoadSize;
NvU32 IMEMVirtBase;
NvU32 IMEMSecBase;
NvU32 IMEMSecSize;
NvU32 DMEMOffset;
NvU32 DMEMPhysBase;
NvU32 DMEMLoadSize;
```
Ucode payload immediately follows descriptor at `desc_abs + DescSize`.

---

## 4. Full Entry Table — CMP 170HX

```
FALCON_UCODE_TABLE @ 0xC154  (16 entries, 6 active)

 #  AppID  Name           TargetID  Target      DescPtr     File Start
 0  0x01   PRE_OS         1         PMU         0x00006954  0x0C784
 1  0x00   (null)         -         -           0x00000000  -
 2  0x00   (null)         -         -           0x00000000  -
 3  0x00   (null)         -         -           0x00000000  -
 4  0x00   (null)         -         -           0x00000000  -
 5  0x00   (null)         -         -           0x00000000  -
 6  0x08   LS_UDE         1         PMU         0x0002E01C  0x33E4C
 7  0x00   (null)         -         -           0x00000000  -
 8  0x45   FWSEC_DBG      7         SEC2        0x0000E70C  0x1453C
 9  0x85   FWSEC_PROD     7         SEC2        0x0001A3E8  0x20218
10  0x49   HULK_DBG       5         FBFalcon    0x000260C4  0x2BEF4
11  0x89   HULK_PROD      5         FBFalcon    0x0002A070  0x2FEA0
12  0x00   (null)         -         -           0x00000000  -
13  0x00   (null)         -         -           0x00000000  -
14  0x00   (null)         -         -           0x00000000  -
15  0x00   (null)         -         -           0x00000000  -
```

**AppID encoding:** bits[7:6] = variant (00=DBG, 01=PROD, 10=PROD_WITH_LIC), bits[5:0] = base function.  
**TargetID note:** `bit.h` defines PMU=1, DPU=2, FECS=3. TargetID=5 (FBFalcon/HULK) and TargetID=7 (SEC2/FWSEC) are **undocumented extensions** not listed in the header file.

---

## 5. Ucode Descriptors — CMP 170HX

### [0] PRE_OS / DEVINIT (AppID=0x01, TargetID=PMU)

```
Descriptor @ 0xC754  (exp-ROM-relative 0x6954)
  StoredSize:    0x7D88  (32,136 B)   enc=0
  IMEMPhysBase:  0x7670
  IMEMLoadSize:  0x0000
  IMEMVirtBase:  0x0000
  IMEMSecBase:   0x0000
  IMEMSecSize:   0x7670  (30,320 B)
  file range:    0x0C784 – 0x1450C
```

DEVINIT script runs on PMU to program hardware straps and HBM2e initialisation parameters before VBIOS POST. Plaintext (`enc=0`), HS overlay not present (no separate SecIMEM region beyond the contiguous load).

### [8] FWSEC_DBG (AppID=0x45, TargetID=SEC2)

```
CMP:  desc=0x1450C  payload=0x1453C–0x201DC  (48,288B)  enc=0
A100: desc=0x15F64  payload=0x15F94–0x20CF4  (44,384B)  enc=0

CMP  IMEMLoadSz=0xB700  IMEMSecBase=0x0400  IMEMSecSz=0xB300 (45,824B)
     DMEMOffset=0xB700  first16B: a0 05 00 00 00 b7 00 00 e8 8d 00 00 d0 00 00 01
     entropy: BL=5.64  HS=7.99  md5=cd64d12380b7b3dbec947937fff78e77

A100 IMEMLoadSz=0xA800  IMEMSecBase=0x0400  IMEMSecSz=0xA400 (41,984B)
     DMEMOffset=0xA800  first16B: 60 05 00 00 00 a8 00 00 14 8f 00 00 d0 00 00 01
     entropy: BL=5.63  HS=7.99  md5=c85fcc5f58db8a8849e79b4f263b8a05
```

### [9] FWSEC_PROD (AppID=0x85, TargetID=SEC2)

```
CMP:  desc=0x201E8  payload=0x20218–0x2BEB8  (48,288B)  enc=0
A100: desc=0x20D00  payload=0x20D30–0x2BA90  (44,384B)  enc=0

CMP  IMEMLoadSz=0xB700  IMEMSecBase=0x0400  IMEMSecSz=0xB300 (45,824B)
     DMEMOffset=0xB700  first16B: a0 05 00 00 00 b7 00 00 e8 8d 00 00 d0 00 00 01
     entropy: BL=5.64  HS=7.99  md5=048ac4b4027922aa2ec4aa3eabf6f324

A100 IMEMLoadSz=0xA800  IMEMSecBase=0x0400  IMEMSecSz=0xA400 (41,984B)
     DMEMOffset=0xA800  first16B: 60 05 00 00 00 a8 00 00 14 8f 00 00 d0 00 00 01
     entropy: BL=5.63  HS=7.99  md5=990b33ae382ba886c67c20804635a0a5
```

FWSEC_DBG and FWSEC_PROD have **identical first 16 bytes per ROM** (same BL code). CMP and A100 differ: CMP first16B starts `a0 05...` (BL entry 0x5A0), A100 starts `60 05...` (BL entry 0x560). The difference in total size (48,288 vs 44,384B = 3,904B) and IMEMLoadSz (0xB700 vs 0xA800) tracks with CMP having more complex VBIOS strap/init logic than A100.

This is the VBIOS-embedded SEC2 ucode that runs **before** the ACR-loaded AHESASC, handling early fuse checks and VBIOS signature verification.

### [10] HULK_DBG (AppID=0x49, TargetID=FBFalcon)

```
CMP:  desc=0x2BEC4  payload=0x2BEF4–0x2FE64  (16,240B)  enc=0
A100: desc=0x2BA9C  payload=0x2BACC–0x2F93C  (15,984B)  enc=0

CMP  IMEMLoadSz=0x3A00  IMEMSecBase=0x0400  IMEMSecSz=0x3600 (13,824B)
     DMEMOffset=0x3A00  DMEMPhysBase=0x0
     first16B: 20 47 00 00 00 3a 00 00 20 47 00 00 d0 00 00 01
     entropy: BL=5.50  HS=7.97  md5=cb9ceea9b8becd92358d5a749586159f

A100 IMEMLoadSz=0x3900  IMEMSecBase=0x0400  IMEMSecSz=0x3500 (13,568B)
     DMEMOffset=0x3900  DMEMPhysBase=0x0
     first16B: 20 47 00 00 00 39 00 00 20 47 00 00 d0 00 00 01
     entropy: BL=5.52  HS=7.97  md5=90f219bf14058b31b8b89507344c6848
```

### [11] HULK_PROD (AppID=0x89, TargetID=FBFalcon)

```
CMP:  desc=0x2FE70  payload=0x2FEA0–0x33E10  (16,240B)  enc=0
A100: desc=0x2F948  payload=0x2F978–0x337E8  (15,984B)  enc=0

CMP  IMEMLoadSz=0x3A00  IMEMSecBase=0x0400  IMEMSecSz=0x3600 (13,824B)
     DMEMOffset=0x3A00  DMEMPhysBase=0x0
     first16B: 20 47 00 00 00 3a 00 00 20 47 00 00 d0 00 00 01
     entropy: BL=5.50  HS=7.97  md5=0f55fa8e9e3441e149f9313a17ec8a31

A100 IMEMLoadSz=0x3900  IMEMSecBase=0x0400  IMEMSecSz=0x3500 (13,568B)
     DMEMOffset=0x3900  DMEMPhysBase=0x0
     first16B: 20 47 00 00 00 39 00 00 20 47 00 00 d0 00 00 01
     entropy: BL=5.52  HS=7.97  md5=5444fab571c19d454c2668885481c0ee
```

**HULK = HBM2e row-remap / memory training ucode.** Runs on TargetID=5 (FBFalcon — framebuffer memory controller Falcon). Handles HBM2e post-package repair and row remapping during VBIOS POST. HULK_DBG and HULK_PROD have **identical BL** (same first 16B per ROM); HS overlays differ (prod keys vs debug keys). CMP is 256B larger than A100 (IMEM 0x3A00 vs 0x3900) consistent with more complex CMP post-package-repair tables. BL is 0x400 bytes (IMEM[0x000–0x3FF]); HS overlay is IMEM[0x400–0x39FF] (CMP) / [0x400–0x38FF] (A100).

### [6] LS_UDE (AppID=0x08, TargetID=PMU)

```
CMP:  desc=0x33E1C  payload=0x33E4C–0x43CB0  (65,124B)  enc=1
A100: desc=0x337F4  payload=0x33824–0x41D78  (58,708B)  enc=1

CMP  IMEMSecSz=0xD384 (54,148B)  DMEMPhysBase=0x2AE0
A100 IMEMSecSz=0xBC34 (48,180B)  DMEMPhysBase=0x2920
     entropy (both): BL≈6.1  HS≈6.2  (enc=1: encrypted at VBIOS level)
```

LS_UDE is the largest ucode. `enc=1` (bit2 of vdesc_raw) — encrypted at the VBIOS container level, unlike all other entries. PMU post-boot debug extension.

---

## 6. Image #2 Layout Map — CMP 170HX

```
File offset     Size        Ucode           Engine    Enc   IMEM load   IMEM HS
─────────────────────────────────────────────────────────────────────────────────
0x0C784         32,136 B    PRE_OS/DEVINIT  PMU       No    0x7670      —
0x1453C         48,288 B    FWSEC_DBG       SEC2      No*   0xB700      0xB300
0x20218         48,288 B    FWSEC_PROD      SEC2      No*   0xB700      0xB300
0x2BEF4         16,240 B    HULK_DBG        FBFalcon  No*   0x3A00      0x3600
0x2FEA0         16,240 B    HULK_PROD       FBFalcon  No*   0x3A00      0x3600
0x33E4C         65,124 B    LS_UDE          PMU       Yes†  0xD384      0xD384
─────────────────────────────────────────────────────────────────────────────────
Image #2 total span: 0x0C720 – 0x43CB0  (~241 KB)

* enc=0 at VBIOS descriptor level; HS overlay internally AES-encrypted
  (entropy=7.97–7.99), self-decrypted by Falcon engine.
† enc=1 at VBIOS descriptor level — LS_UDE uniquely encrypted at container level.
```

---

## 7. Image #2 Layout Map — A100

```
File offset     Size        Ucode           Engine    Enc   IMEM load   IMEM HS
─────────────────────────────────────────────────────────────────────────────────
0x0EC1C         29,512 B    PRE_OS/DEVINIT  PMU       No    0x6D18      —
0x15F94         44,384 B    FWSEC_DBG       SEC2      No*   0xA800      0xA400
0x20D30         44,384 B    FWSEC_PROD      SEC2      No*   0xA800      0xA400
0x2BACC         15,984 B    HULK_DBG        FBFalcon  No*   0x3900      0x3500
0x2F978         15,984 B    HULK_PROD       FBFalcon  No*   0x3900      0x3500
0x33824         58,708 B    LS_UDE          PMU       Yes†  0xBC34      0xBC34
─────────────────────────────────────────────────────────────────────────────────
Image #2 total span: 0x0B520 – 0x41D78  (~217 KB)
```

**CMP vs A100 size deltas** (CMP larger throughout):

| Ucode   | CMP      | A100     | Delta    | Reason                                  |
|---------|----------|----------|----------|-----------------------------------------|
| PRE_OS  | 32,136 B | 29,512 B | +2,624 B | CMP HBM2e strap tables                  |
| FWSEC   | 48,288 B | 44,384 B | +3,904 B | CMP more complex early-boot strap logic |
| HULK    | 16,240 B | 15,984 B | +256 B   | CMP post-package-repair rows            |
| LS_UDE  | 65,124 B | 58,708 B | +6,416 B | CMP additional PMU debug extensions     |

---

## 8. FWSEC vs AHESASC Relationship

| Property         | VBIOS FWSEC                          | ACR AHESASC                          |
|------------------|--------------------------------------|--------------------------------------|
| Source           | VBIOS Image #2                       | `acr/bin/sec2/ga100/ahesasc_*/`      |
| Load time        | Very early (PMC_BOOT sequence)       | After Booter runs (GSP-RM boot)      |
| Loader           | VBIOS boot ROM / SEC2 itself         | ACR HS (authenticated by Booter)     |
| Purpose          | VBIOS signature verify, fuse read    | ACR LS Falcon authentication         |
| Encryption       | enc=0 in VBIOS; HS internally        | Encrypted C-array in driver binary   |
| PLM tighten?     | Unknown (Phase-4 P3 target)          | Phase-4 P1: inherits Booter PLMs     |

The AHESASC (ACR HESASC) is a **separate, later-stage** SEC2 ucode. FWSEC handles the VBIOS-level trust chain; AHESASC handles the GSP-RM / LS Falcon trust chain after handoff from Booter. Both run on SEC2 (TargetID=7 in VBIOS catalog = engine ID 0x7 = SEC2).

---

## 9. Security Analysis

### Finding P2-1: FWSEC HS Overlay Unprotected at VBIOS Level (Informational)

FWSEC_PROD is stored with `enc=0` in the VBIOS descriptor. The HS overlay within the binary is AES-encrypted (entropy=7.97), but the VBIOS image is not encrypted at the container level. An attacker with VBIOS flash access can replace FWSEC_PROD payload. Trust is enforced by the internal HS signature check, not by VBIOS-level encryption.

**Severity:** Informational — exploitability requires physical flash access or a separate VBIOS flash vulnerability. Standard NVIDIA threat model considers flash access out-of-scope.

### Finding P2-2: Undocumented TargetID Values (5, 7)

`bit.h` TARGET constants only enumerate: PMU=1, DPU=2, FECS=3. TargetID=5 (FBFalcon) and TargetID=7 (SEC2) are undocumented. This is a documentation gap, not a vulnerability, but it means tools parsing the catalog will misidentify these ucodes.

### Finding P2-3: HULK FBFalcon HS Binary — HBM2e Attack Surface (Informational)

HULK runs on FBFalcon (the FBHUB memory controller Falcon) with an AES-encrypted HS overlay (entropy=7.97). Corruption of HULK_PROD causes HBM2e training failure at POST — persistent DoS on physical flash access.

**FECS DMA arbiter intersection: NONE.** Two independent reasons:
1. HULK is VBIOS-loaded (not ACR LS-loaded) — the ACR `acrIssueDma_TU10X` path is never used for HULK.
2. Even if ACR loaded FBFalcon, `acrlibSetupFecsDmaThroughArbiter` is gated on `falconId == LSF_FALCON_ID_FECS` (source: `acr_dma_tu10x.c:412`) — FBFalcon takes a separate path via its own FBIF (`NV_PFBFALCON_FBIF_TRANSCFG`).

The Phase-2 FECS DMA arbiter (`instance<<21`, no bounds check) is exercised only during ACR loading of FECS. HULK's IMEM load (IMEMLoadSz=0x3A00 CMP / 0x3900 A100) uses VBIOS BAR0 DMA exclusively. **No new attacker-reachable path confirmed.**

### Finding P2-4: PRE_OS/DEVINIT Runs Unencrypted on PMU

The DEVINIT script (32,136 B) is entirely plaintext (`enc=0`, no HS overlay). It runs on PMU to set hardware straps. A crafted DEVINIT could configure HBM2e parameters maliciously. Again requires flash access.

---

## 10. Cross-References

- **Phase-4 P1** (`7-3-phase4-booter-analysis.md`): Booter sets GSP DMEM PLM=READ_L0_WRITE_L0; FWSEC runs before this on SEC2, so FWSEC executes before the PLM vulnerability window opens.
- **Phase-2** §3.1: ITCM gadget not in prod binary. FECS DMA arbiter: instance<<21, no bounds check.
- **Phase-4 P3** (next): AHESASC APM variant (`acr/bin/sec2/ga100/ahesasc_apm/`) — Confidential Computing path.
- **Phase-4 P4**: `_acrSetupLSFalcon_TU10X` pre-verify DMA scribble at ASB 0x1E81.

---

## 11. Open Items

~~All four open items resolved (2026-05-18):~~

1. ~~Full HULK descriptor IMEM/DMEM fields~~ — **RESOLVED.** See §5 HULK_DBG/PROD entries. CMP: IMEMLoadSz=0x3A00, IMEMSecBase=0x400, IMEMSecSz=0x3600, DMEMOffset=0x3A00. A100: 0x3900/0x400/0x3500/0x3900.
2. ~~A100 per-entry descriptor data~~ — **RESOLVED.** Full A100 descriptors in §5; layout map in §7.
3. ~~FWSEC_DBG first 16 bytes and entropy~~ — **RESOLVED.** CMP: `a0 05 00 00 00 b7 00 00 e8 8d 00 00 d0 00 00 01` BL=5.64 HS=7.99. A100: `60 05 00 00 00 a8 00 00 14 8f 00 00 d0 00 00 01` BL=5.63 HS=7.99.
4. ~~HULK IMEM vs FECS DMA arbiter~~ — **RESOLVED (no intersection).** See Finding P2-3. HULK is VBIOS-loaded; arbiter only triggers for `LSF_FALCON_ID_FECS`.

---

*Next: Phase-4 P3 — AHESASC APM variant (`acr/bin/sec2/ga100/ahesasc_apm/`)*
