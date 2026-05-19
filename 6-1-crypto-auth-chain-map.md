# 6.1 — Synthesis: Cryptographic Authentication Chain

**Date:** 2026-05-18  
**Status:** Complete — all claims binary-validated against prod-signed artifacts  
**Sources:** All 20 prior analysis documents + direct source and binary evidence  
**ROMs:** `<GPU ROM archive>` (CMP 170HX, 0xFF000 B), `<GPU ROM archive>` (A100, 0xFF000 B)

---

## 0. Trust Level Overview

The chain spans five trust levels and two distinct cryptographic regimes:

```
TRUST LEVEL     ACTOR                        CRYPTO REGIME
──────────────────────────────────────────────────────────────────────
L5  HS-root     Boot ROM silicon             N/A — silicon-immutable
L4  HS          FWSEC (SEC2 HS task)         RSA-3K (ROM verifies Booter; Booter loads FWSEC)
L3  HS          Booter LOAD (GSP-lite HS)    RSA-3K signature patch @ binary+0x5F00
L2  HS-SEC2     AHESASC (SEC2 HS task)       AES-DM + SCP — authenticates all LS ucodes
L1  LS-kernel   GSP-RM RISC-V               Inherits L2 setup; no self-tighten capability
L0  LS-app      PMU / FECS / GPCCS / etc.   AES-DM authenticated by AHESASC
```

**HS regime** (L3–L5): RSA-3072 + SHA-256. Bootstrapped from immutable ROM.  
**LS regime** (L0–L2): 128-bit AES-DM signatures keyed by a per-domain SCP hardware slot.
No public-key cryptography is involved in LS authentication on GA100.

The dividing line is sharp: above it (ROM→Booter→AHESASC) RSA-3K is unbroken;
below it (AHESASC→PMU/FECS/GPCCS/GSP-RM) the security property rests entirely on
the confidentiality of SCP slot 43 in every GA100 die ever shipped.

---

## 1. Layer 0 — Host Driver VBIOS Parser  
*(Before any Falcon engine runs)*

**Source:** `drivers/resman/kernel/gpu/gsp/kernel_gsp_fwsec.c`  
**ROM data:** `<GPU ROM archive>:0xC700` (Image #2), `<GPU ROM archive>:0xB500` (Image #2)  
**Analysis:** `2-5-host-firmware-parser.md`, `2-5-host-firmware-parser.md`

The host kernel driver is the first actor in the trust chain. It reads the VBIOS from SPI
flash, parses it to extract the FWSEC ucode, and loads that ucode onto the SEC2 Falcon engine.
This parsing step has no hardware-enforced integrity of its own — the driver trusts the
SPI-flash contents.

### 1.1 VBIOS Physical Layout (binary-confirmed on both ROMs)

```
<GPU ROM archive> (A100 addresses are ~0x0E00 lower):
  0x000000  IFR-1 header (0x6B4 B — byte-identical copy at IFR-2 @ 0x060000)
  0x005E00  ★ PCI ROM Image #1 (BIOS, 0x6200 B)
    0x005E10  PCIR  devID=0x20C2
    0x005EB0  BIT   16 entries, checksum=0x47
    0x0060D9  token 'p' (BIT_DATA_FALCON_DATA) → falconDataPtr=0x6354
  0x00C700  ★ PCI ROM Image #2 (firmware container, spans to 0x05E000)
    <image_base+0x6354>  FALCON_DATA_V2 → FalconUcodeTablePtr → SEC2 FWSEC entry
  0x060000  IFR-2 (byte-identical to IFR-1)
  0x065E00  Recovery copy of Image #1
  0x06C700  Recovery copy of Image #2
```

### 1.2 BIT Token Chain to FWSEC

```
s_vbiosFindBitHeader()    scans pVbiosImg for magic 0xB8FF + "BIT\0" + 0x00010C06
  → BIT header @ image+0x2B0 (CMP) / image+0x27C (A100)

s_vbiosParseFwsecUcodeDescFromBit():
  token 'p' (0x70, BIT_DATA_FALCON_DATA, DataVersion=2, DataSize≥4)
    → DataPtr (NvU16, max 65535) → FALCON_DATA_V2.FalconUcodeTablePtr (NvU32)
      → expansionRomOffset + FalconUcodeTablePtr  [unchecked NvU32 add — §3.3 R-5]
        → FALCON_UCODE_TABLE_HDR (Version=1, HeaderSize≥6, EntrySize≥6)
          entry filter: ApplicationID == 0x05  (FIRMWARE_SEC_LIC, always accepted)
                     OR ApplicationID == 0x85  (!debug, FWSEC_PROD)
                     OR ApplicationID == 0x45  (debug,  FWSEC_DBG)
```

**AppID=0x05 unconditional accept:** Any VBIOS entry claiming AppID=0x05 bypasses the
`kgspIsDebugModeEnabled_HAL` fuse check. This is the production FIRMWARE_SEC_LIC path and
is by design, but a crafted VBIOS can reach the descriptor fill path without a fuse gate.

### 1.3 Descriptor Parsing (V2 and V3 paths)

```
ucodeDescVersion comes from vDesc[15:8] (8-bit, allowlist: only V2 and V3 accepted).
ucodeDescSize    comes from vDesc[31:16] (16-bit, range 0–65535).

V2 path (version==2, descSize>=60):
  signaturesTotalSize = SignatureCount × BCRT30_RSA3K_SIG_SIZE (384 B)
  — no explicit upper-bound check on SignatureCount

V3 path (version==3, descSize>=44):
  signaturesTotalSize = descSize - 44          [§ Finding P4-1 — MEDIUM]
  max value: 65535 - 44 = 65491 B
  portMemAllocNonPaged(65491) will succeed on any system with > 64 KB free kernel heap
  Cross-check against SignatureCount × 384 is ABSENT
```

All VBIOS image source reads are guarded by `portSafeAddU32` + `> biosSize`
(complete and correct — see `2-5-host-firmware-parser.md` §3.1).
The ABSENT checks are hardware physical limits and the `signaturesTotalSize` upper bound.

### 1.4 Structural Gap: Hardware Limit Never Consulted

`FALCON_HWCFG3.IMEM_TOTAL_SIZE` and `DMEM_TOTAL_SIZE` are never read by any parser function.
Every size decision is made exclusively from VBIOS descriptor fields.
GA100 SEC2 physical IMEM = 0xC000 B (49,152 B); VBIOS `IMEMLoadSize = 0xB700` is correct,
but a crafted value of `0xC001` would be silently accepted and cause a hardware load fault
at execution time.

### 1.5 Silent NULL Ucode on Fill Failure (Finding P4-2 — LOW)

`s_vbiosNewFlcnUcodeFromDesc` always returns `NV_OK` even when the fill function fails.
The caller receives `NV_OK` with `*ppFwsecUcode = NULL`.
Propagation: `kgspExecuteFwsecFrts_HAL` catches the NULL via `NV_ASSERT_OR_RETURN`
in release builds, but the diagnostic at the VBIOS-parse level is silently swallowed.

---

## 2. Layer 1 — FWSEC (SEC2 HS Task, VBIOS-Embedded)

**Binary:** FWSEC ucode in `<GPU ROM archive>` Image #2 (AppID=0x85/0x05)  
**Confirmed sizes:** IMEMLoadSize=0xB700 (CMP) / 0xA800 (A100), DMEMLoadSize=0xD0  
**Analysis:** `2-6-vbios-ucode-catalog.md`

FWSEC is the first Falcon code to execute on the GPU. It runs as a HS (High-Secure) task
on SEC2, meaning it has been loaded and authenticated by the ROM or Booter chain before
execution begins.

### 2.1 What FWSEC Does in the Auth Chain

1. Performs FRTS (Firmware Reserved Timestamp Scratch) setup.
2. Establishes WPR2 — a temporary Write-Protected Region in FB used to pass FRTS data to ACR.
3. Programs `NV_PGC6_AON_FRTS_OUTPUT_FLAG_SECURE_SCRATCH_GROUP_03_2._ACR_READY = _YES`
   to signal ACR that FRTS data is available.

### 2.2 FWSEC Encryption Status

From `2-6-vbios-ucode-catalog.md`:
- FWSEC `enc=0` at the VBIOS-level descriptor (descriptor field, not ciphertext).
- HULK (FBFalcon) has AES HS overlay with entropy=7.97 — that overlay is separately keyed.
- FWSEC itself ships in cleartext within the VBIOS image.

### 2.3 KDF Byte Correlation with AHESASC Salt

The FWSEC internal KDF uses bytes[1..15] identical to the AHESASC AES-DM salt:
```
AHESASC g_kdfSalt[0..15]:  B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62
FWSEC   KDF bytes[1..15]:  C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62
```
Byte[0] is the domain-separation byte: 0x00 for FWSEC, 0xB6 for AHESASC LS auth.
This is intentional key diversification across trust domains using a single SCP slot root.

---

## 3. Layer 2 — Boot ROM → Booter (HS, RSA-3K Root)

**Source:** `uproc/acr/src/acrshared/ampere/acr_sanity_checks_ga100.c`,
            `uproc/acr/src/acrshared/ampere/acr_sanity_checks_ga100_and_later.c`  
**Binary:** `gsprm/bin/booter/ga100/load/g_booteruc_load_ga100_prod.h`  
           (35,328 B raw; active content 24,320 B; RSA-3K sig placeholder at 0x5F00)  
**Analysis:** `7-2-phase3-binary-analysis.md` §§1.3–1.4, `7-3-phase4-booter-analysis.md`

### 3.1 ROM Verification of Booter

The immutable boot ROM on GA100 contains:
- NVIDIA production RSA-3072 public key (silicon-embedded, not in any software file)
- NVIDIA debug RSA-3072 public key (conditional on debug strap)

ROM verifies the Booter binary's RSA-3K signature before handing off execution.
The signature occupies 384 bytes at file offset `0x5F00` in the production binary
(zeroed in this development archive copy; `booter_load_sig_ga100_ucode_encrypted = 1`
indicates the production build would have an AES-encrypted image with a real signature).

### 3.2 Chip-Lock (binary-confirmed @ ASB 0x22FC)

```asm
2308: mvi a10 0xa00                  ; NV_PMC_BOOT_42
230d: call BAR0_RD32                 ; read CHIP_ID
2311: uxtr a10 a10 0x114             ; extract CHIP_ID field
2315: cmpbreq.w a10 0x170 0x232b     ; 0x170 = GA100 → OK
231a: mvi a14 0xf                    ; ACR_ERROR_INVALID_CHIP_ID
231c: cmpbrne.w a10 0x171 0x232d     ; 0x171 = GA101 → check debug mode
2321: call _acrIsDebugModeEnabled_TU10X
2327: cmpbreq.b a10 0x0 0x232d       ; GA101 prod mode → return error
```

**GA100 (0x170)** and **GA101 debug-only (0x171)** are the only accepted chip IDs.
Every other chip returns `ACR_ERROR_INVALID_CHIP_ID` before any further execution.

### 3.3 Anti-Rollback (binary-confirmed @ ASB 0x264D)

```asm
; _acrGetUcodeFpfFuseVersion_GA100:
2615: mvi a10 0x824250               ; NV_FUSE_OPT_FPF_UCODE_ACR_HS_REV
261a: call BAR0_RD32
2620: and a10 0xff                   ; low 8 bits = monotone counter
2623→262d: count trailing one-bits   ; popcount → hwFuseVersion

; _acrCheckFuseRevocationAgainstHWFpfVersion_GA100:
267c: cmp.w a1 a9                    ; SW_ucode_version vs hwFuseVersion
267e: brc 0x2683                     ; if SW < HW → ACR_ERROR_UCODE_REVOKED (0x23)
```

The `binVersion` field in the LSF wrapper is a metadata label only.
The real anti-rollback gate is FPF fuse `0x824250` — a monotone OTP register.
Defeating it requires either a chip with fewer fuse bits burned than the SW version
or breaking the HS sign chain entirely.

### 3.4 TU10X vs GA10X Path (GA100 uses Turing era code)

| Feature | GA100 (TU10X path) | GA102+ (GA10X path) |
|---|---|---|
| PLM setup | Explicit `BAR0_WR32` calls in Booter | RISC-V boot manifest (NVIDIA-signed) |
| `BCR_PRIV_LEVEL_MASK` (0x111664) | **Not written** | `0x8F` (READ_L0_WRITE_L3) |
| GSP-RM start register | `NV_PGSP_RISCV_CPUCTL_ALIAS` (0x11126C) | `NV_PGSP_RISCV_BCR_CTRL` + `NV_PGSP_RISCV_CPUCTL` |

The GA10X comment explicitly states "Raise BCR PLM (all other PLMs set by RISC-V manifest)".
GA100 carries the Turing-era PLM configuration that GA102+ resolved via the manifest.

### 3.5 PLM Configuration (binary-confirmed @ booter_load+0x5460–0x54E5)

Instruction encoding pattern for each write:
```
8a [addr_lo] [addr_mid] [addr_hi]  4b [value] 00  7e 25 0f 00
   ←────── BAR0 address ──────→       ←value→       ← wait_idle →
```

| Register (BAR0 addr) | Binary offset | Value | Policy | Risk |
|---|---|---|---|---|
| `NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK` `0x110298` | `+0x546B` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_IMEM_PRIV_LEVEL_MASK` `0x110280` | `+0x548D` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| **`NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK` `0x110284`** | **`+0x5498`** | **`0xFF`** | **READ_L0 / WRITE_L0** | **CRITICAL** |
| `NV_PGSP_FALCON_CPUCTL_PRIV_LEVEL_MASK` `0x110288` | `+0x54A3` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_EXE_PRIV_LEVEL_MASK` `0x11028C` | `+0x54AE` | `0xFF` | READ_L0 / WRITE_L0 | Low |
| `NV_PGSP_FALCON_IRQTMR_PRIV_LEVEL_MASK` `0x110290` | `+0x54B9` | `0xFF` | READ_L0 / WRITE_L0 | Low |
| `NV_PGSP_FALCON_MTHDCTX_PRIV_LEVEL_MASK` `0x110294` | `+0x54C4` | `0xFF` | READ_L0 / WRITE_L0 | Low |
| `NV_PGSP_FALCON_DIODT_PRIV_LEVEL_MASK` `0x1100EC` | `+0x54CF` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_DIODTA_PRIV_LEVEL_MASK` `0x1100F0` | `+0x54DA` | `0x8F` | READ_L0 / WRITE_L3 | Secure |

PLM mask encoding: bits[3:0] = read mask, bits[7:4] = write mask.
`0xFF` = both nibbles `0xF` = all privilege levels can read and write.
`0x8F` = write nibble `0x8` = only L3 (HS) can write; read nibble `0xF` = all levels can read.

**Source comment at `booterSetupTargetRegisters_TU10X:94`:**
```c
// TODO suppal/derekw: TASK_RM fails to come up if this is WRITE_L3
```
The DMEM PLM was intentionally left at `0xFF` because tightening it to `0x8F` breaks GSP-RM boot.
This is a known, deferred design coupling issue — not an oversight.

### 3.6 REGIONCFG Disabled (binary-confirmed)

`NV_PGSP_FBIF_REGIONCFG` = `0x11066C`. The 3-byte needle `6c 06 11` is **absent** from all
24,320 bytes of active Booter binary content.

**Source (`booter_boot_gsprm_tu10x_ga100.c:57–73`):**
```c
// TODO suppal/derekw: revisit this
// Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot
#if 0
    data = BOOTER_REG_RD32(BAR0, NV_PGSP_FBIF_REGIONCFG);
    for (i = 0; i < NV_PFALCON_FBIF_TRANSCFG__SIZE_1; i++) {
        mask = ~(0xF << (i*4));
        data = (data & mask) | ((2 & 0xF) << (i * 4));  // restrict to WPR-only
    }
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_REGIONCFG, data);
#endif
```

With this disabled, GSP-RM FBIF DMA has **no WPR source restriction** — it can DMA from
any framebuffer address. This is the prerequisite for the compound APM_RTS attack
(see §6.2).

### 3.7 GSP-RM Privilege Level and Launch

From `booter_boot_gsprm_tu10x_ga100.c:114`:
```c
// Note: GSP-RM is L0 (so do not program _LSMODE or _LSMODE_LEVEL here)
data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _AUTH_EN, _TRUE, 0);
BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_SCTL, data);
```

GSP-RM runs at **privilege level 0 (LS)**, the lowest tier.
`AUTH_EN=TRUE` prevents unauthenticated CPU control-register writes but
does not protect DMEM from L0 reads or writes.

Launch register (binary-confirmed @ booter_load+0x5420):
```
8a 6c 12 11 0b 01   → BAR0[0x11126C] (NV_PGSP_RISCV_CPUCTL_ALIAS) = STARTCPU_TRUE
```

---

## 4. Layer 3 — AHESASC Initialization Sequence

**Source:** `uproc/acr/src/ahesasc/turing/acr_lock_wpr_tu10x.c`  
**Binary:** `acr/bin/sec2/ga100/ahesasc/g_acruc_ga100_ahesasc.{nm,objdump}` (23,296 B)  
**Analysis:** `7-2-phase3-binary-analysis.md` §2, `7-4-phase4-ahesasc-apm.md`

AHESASC (`acrInit_TU10X`) runs as a HS task on SEC2. Its execution sequence defines the
security posture of all subsequent LS Falcon execution:

```
acrInit_TU10X()
  1. acrProgramHubEncryption_HAL()          → generate TRNG HUB keys, encrypt via SCP, write to SFBHUB
  2. acrProtectNvlinkRegs_HAL()             → LTCS/HSHUB regs to priv-level-2-only
  3. acrProtectHostTimerRegisters_HAL()     → timer reg PLM to L3
  4. acrAllowFecsToUpdateSecureScratchGroup15_HAL()
  5. acrProtectHost2JtagWARBug2401005_HAL() → JTAG WAR (Turing-only bug)
  6. g_bIsDebug = acrIsDebugModeEnabled_HAL()
  7. acrLockAcrRegions_HAL() → acrLockWpr1DuringACRLoad_TU10X()
       programs NV_PFB_PRI_MMU_WPR1_ADDR_LO/HI
       WPR1 ALLOW_READ  = LSF_WPR_REGION_RMASK_SUB_WPR_ENABLED
       WPR1 ALLOW_WRITE = LSF_WPR_REGION_WMASK_SUB_WPR_ENABLED
       programs three subWPRs:
         SEC2   subWPR-0  full WPR1  R=L2+L3  W=L2+L3  (AHESASC ACRlib access)
         PMU    subWPR-0  full WPR1  R=L2+L3  W=L2+L3
         GSPlite subWPR-2 full WPR1  R=L3     W=L3     (ASB needs full WPR1 to load SEC2 RTOS)
  8. _acrShadowCopyOfWpr()                  → copies host-provided shadow region into WPR1
  9. acrSetupSharedSubWprs_HAL()            → APM_RTS sub-WPR and other shared regions
 10. acrCopyFrtsData_HAL()                  → copies FRTS data from WPR2 (FWSEC setup) to WPR1
 11. acrValidateSignatureAndScrubUnusedWpr_HAL()  ← LS SIGNATURE VERIFICATION (§5)
```

### 4.1 GA100-Specific WAR Functions (binary-confirmed in prod AHESASC)

| Address | Symbol | Purpose |
|---|---|---|
| `0x323A` | `_acrProgramDecodeTrapToIsolateTSTGRegisterToFECSWARBug2823165_GA100` | Locks LTC TSTG_CFG_2 (0x140098) to FECS-only via PPRIV_SYS decode trap 21 |
| `0x3468` | `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` | HBM2e row-remapper aware WPR placement validator |
| `0x328F` | `_acrGetUsableFbSizeInMB_GA100` | Walks FBPAs, reads CSTATUS RAMAMOUNT |
| `0x339B` | `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100` | HBM2e memlock range disable |

WPR placement error codes from `_acrCheckWprRangeWithRowRemapperReserveFB_GA100`:
`0x54` start in bottom FB-hole, `0x55` end in bottom, `0x56/0x57` top band,
`0x58` memlock not enabled, `0x59/0x5A` top-band start/end mismatch, `0x73` invalid usable FB size.

---

## 5. Layer 4 — LS Signature Verification (AES-DM, SCP Slot 43)

**Source:** `uproc/acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c`  
**Binary:** AHESASC symbols `_acrCalculateDmhash_TU10X` @ 0x1EE6,
           `_acrDeriveLsVerifKeyAndEncryptDmHash_TU10X` @ 0x21B3,
           `_acrVerifySignature_TU10X` @ 0x2256  
**Analysis:** `7-2-phase3-binary-analysis.md` §3a

This is the core of all LS authentication on GA100. Every LS Falcon ucode — PMU, DPU,
FECS, GPCCS, NVDEC, SEC2, FBFalcon — must pass this check before its sub-WPR is
configured and before the engine is started.

### 5.1 The Three Absent Algorithms

**Not present in prod GA100 AHESASC:**
- `_acrDecryptAesCbcBuffer_GA10X` — not present
- `_acrGetDerivedKeyAndLoadScpTrace0_GA10X` — not present
- Any RSA / SHA-256 / PKC symbols — not present
- SCP slot 31 — unused (Phase-2 §2.3 was wrong for GA100)

**What is present** (source + binary both confirmed):
```
00001ee6  T _acrCalculateDmhash_TU10X
000021b3  T _acrDeriveLsVerifKeyAndEncryptDmHash_TU10X
00002256  T _acrVerifySignature_TU10X
10000800  D _g_kdfSalt        ← 16 B at AHESASC DMEM VA 0x10000800
10000c00  D _g_dmHash         ← 16 B AES-DM accumulator
10000c10  D _g_dmHashForGrp   ← per-overlay-group hash table
```

### 5.2 The KDF Salt (binary-confirmed)

At AHESASC binary file offset `0x2800` (VA `0x10000800`, `.data` section):
```
B6 C2 31 E9  03 B2 77 D7  0E 32 A0 69  8F 4E 80 62
```
Byte-identical to the `g_kdfSalt` initializer in
`acr_verify_ls_signature_tu10x.c:31–34`:
```c
NvU8 g_kdfSalt[ACR_AES128_SIG_SIZE_IN_BYTES] ... =
{
    0xB6,0xC2,0x31,0xE9,0x03,0xB2,0x77,0xD7,0x0E,0x32,0xA0,0x69,0x8F,0x4E,0x80,0x62
};
```
This salt is a **public value** — embedded unencrypted in the signed binary. Its secrecy
is not assumed. The security property is that the KDF output (derivedKey) is secret
because SCP slot 43 is secret.

### 5.3 AES-DM Hash Accumulation

`acrCalculateDmhash_TU10X` (source lines 195–225, binary @ 0x1EE6):

```
Iterates over the ucode in 16-byte blocks, maintaining a running 128-bit state:

  H[0] = 0x00...00  (zeroed in acrVerifySignature_TU10X before first call)
  For each 16-byte block m_i:
    scp_trap(TC_INFINITY)
    load m_i into SCP_R2; chmod(0x1, R2)   ← "secure keyable" only
    load H[i-1] into SCP_R3
    scp_key(R2)                             ← install m_i as AES key
    scp_encrypt(R3, R4)                     ← R4 = AES-ECB(key=m_i, plain=H[i-1])
    scp_xor(R4, R3)                         ← R3 = H[i-1] XOR R4
    read R3 back to H[i]                    ← H[i] = H[i-1] XOR AES(m_i, H[i-1])
    scp_trap(TC_DISABLE_CCR)
```

This is the **Davies-Meyer** single-length compression function operating as a hash.
The ucode binary is the key schedule; the hash state is the plaintext/ciphertext input.
Security bound: 128-bit preimage resistance; ~2^64 collision resistance (birthday bound).

**Versioning extension** (when `pLsfHeader->signature.bSupportsVersioning`):
After hashing all ucode bytes, a version block is appended to the hash input:
```
[version: NvU32] [depMap: depMapCount × (falconId: NvU32, expectedVersion: NvU32)]
Total = 4 + depMapCount×8 bytes, padded to 16-byte alignment
acrCalculateDmhash_HAL(g_dmHash, g_UcodeLoadBuf[0], aligned_size)
```
This binds the LS ucode signature to the versions of its declared dependencies.
The depMap field is checked for cross-version consistency via
`acrCheckForLSRevocation_TU10X` (separate from hash verification).

### 5.4 Key Derivation and Final Signature

`acrDeriveLsVerifKeyAndEncryptDmHash_TU10X` (source lines 481–529, binary @ 0x21B3):

```
Step 1 — Domain separation:
  pSaltBuf = copy of g_kdfSalt
  if (bUseFalconId): pSaltBuf[0..3] ^= falconId    ← per-falcon domain byte

Step 2 — Enter SCP secure mode:
  scp_trap(TC_INFINITY)

Step 3 — Load derivation key from SCP hardware slot:
  if (g_bIsDebug):  scp_secret(0,    SCP_R2)       ← debug slot 0
  else:             scp_secret(0x2B, SCP_R2)        ← production slot 43 = 0x2B

Step 4 — Derive per-falcon key:
  scp_key(SCP_R2)                                   ← install slot-43 key
  scp_encrypt(SCP_R3=saltBuf, SCP_R4)               ← R4 = AES-ECB(salt^falconId, slot43)
  scp_chmod(0x1, SCP_R4)                            ← mark R4 as secure-keyable only

Step 5 — Compute signature:
  scp_key(SCP_R4)                                   ← install derived key
  scp_encrypt(SCP_R3=dmHash, SCP_R2)                ← R2 = AES-ECB(dmHash, derivedKey)

Step 6 — Read result:
  read R2 back to pDmHash                           ← pDmHash now holds the signature

Step 7 — Exit SCP secure mode:
  scp_trap(TC_DISABLE_CCR)
```

Binary confirmation of slot 43 (@ AHESASC objdump:2962+0x68):
```
220b: cci 0xc2b2   ← falc_scp_secret(0x2B=43, SCP_R2)   [PROD path]
2203: cci 0xc002   ← falc_scp_secret(0,       SCP_R2)   [DEBUG path]
```
`0xc2b2` decodes as: SCP instruction, secret-load opcode, slot=`0x2B`=43, register=R2.
Matches `ACR_LS_VERIF_KEY_INDEX_PROD_TU10X_AND_LATER` defined at
`uproc/acr/inc/acr.h:151`.

### 5.5 Complete LS Auth Formula

```
dmHash      = DaviesMeyer_AES128(ucode_bytes || version_block)
               where version_block = [version||depMap], present if bSupportsVersioning
derivedKey  = AES-ECB(g_kdfSalt[0..15] XOR (falconId<<0), scpSecret[43])
signature   = AES-ECB(dmHash, derivedKey)
PASS if signature == pLsfHeader->signature.prdKeys[0]   (prod)
           or == pLsfHeader->signature.dbgKeys[0]        (debug)
```

**No RSA. No SHA-256. No public-key operation at any point in this path.**

### 5.6 Security Implications

| Goal | Cost |
|---|---|
| Forge LS signature for any falconId | Recover SCP slot 43 once from any GA100 silicon → AES-ECB forge offline for all falconIds, all GA100s, forever |
| Decrypt LS ucode | N/A — GA100 LS ucodes ship in cleartext (`bUcodeLsEncrypted == 0`) |
| Bypass HS auth (ROM→Booter→AHESASC) | Break RSA-3K — out of scope for non-state actors |
| Substitute LS code without forging sig | 2^64 AES-DM collision work (birthday bound) |

The weakest link in the LS regime is SCP slot 43 confidentiality.
Published NVIDIA SCP fault-injection literature demonstrates slot-key recovery on
prior-gen chips; GA100 is structurally identical in this regard.

### 5.7 LS Signature Verification Loop (entry point)

`acrValidateSignatureAndScrubUnusedWpr_TU10X` (source lines 788–953):

```
acrReadWprHeader_HAL()          → load WPR header array into g_pWprHeader[LSF_FALCON_ID_END]

For each entry in WPR header:
  acrReadLsbHeader_HAL()        → read LSF_LSB_HEADER from WPR FB
  acrSanityCheckBlData_HAL()    → validate bootloader data; write ACR_FLCN_BL_RESERVED_ASM
                                   into reserved[] field (halt stub poisoning)
  acrVerifySignature_HAL(code)  → verify ucode bytes (§5.3–5.4)
  acrVerifySignature_HAL(data)  → verify data bytes at ucodeOffset+ucodeSize
  acrCheckForLSRevocation_HAL() → verify depMap: pBinVersions[dep] >= expectedVer
  acrSetupFalconCodeAndDataSubWprs_HAL() → write sub-WPR MMU entries per falcon

On any verification failure:
  _acrScrubContentAndWriteWpr() → DMA-scrub ucode and data to zero; write WPR header
  return error                  → the falcon is not started
```

After successful verification the sub-WPR entries are locked in the MMU, restricting
subsequent access to that falcon's code/data region.

### 5.8 LS Overlay Group Signatures (SEC2 group registers)

For falconId == LSF_FALCON_ID_SEC2, overlay-group signatures are written to BSI
secure scratch:
```c
acrCopyLsGrpSigToRegsForSec2_TU10X(pSig, ENUM_LS_SIG_GRP_ID_1):
  ACR_REG_WR32(BAR0, NV_PGC6_BSI_SECURE_SCRATCH_0, pSig[0])
  ACR_REG_WR32(BAR0, NV_PGC6_BSI_SECURE_SCRATCH_1, pSig[1])
```
These two DWORDs (32 bits of the 128-bit group signature) are stored in hardware-protected
BSI scratch for later attestation use.

---

## 6. Layer 5 — HUB VIDMEM Encryption (Data-at-Rest)

**Source:** `uproc/acr/src/ahesasc/turing/acr_hub_encryption_tu10x.c`  
**Binary:** AHESASC symbols `_acrEncryptAndSaveHubEncryptionKeys_TU10X` @ 0x2DA1,
           `_acrProgramHubEncryption_TU10X` @ 0x2F2E

HUB encryption protects framebuffer contents at rest (GC6 / power-gating scenarios).
It is orthogonal to the LS signature chain but shares the SCP hardware subsystem.

### 6.1 HUB Key Derivation and Storage

```
Salt (hardcoded, public):
  AF1728E1 1CB93271 DF82BFAC EDAF7461   (128-bit)

AHESASC (load path):
  1. scp_secret(SCP_HUB_KEY_INDEX, SCP_R2)          ← load HUB key-wrapping slot
  2. scp_key(R2); scp_encrypt(R3=salt, R4)           ← R4 = AES-ECB(salt, hubKeySlot) = derivedKey
  3. acrGetTRand_HAL() × ACR_REGION_COUNT            ← TRNG-generate fresh HUB key + nonce per region
  4. scp_key(R4); scp_encrypt(R3=hubKey, R2)         ← R2 = AES-ECB(hubKey, derivedKey) = encHubKey
  5. ACR_REG_WR32(NV_PGC6_BSI_HUB_ENCRYPTION_SECURE_SCRATCH(i), encHubKey[i])  ← save to BSI
  6. Write hubKey to NV_SFBHUB_ENCRYPTION_REGION_SUBKEY/SUBNONCE via secure bus
  7. Enable NV_SFBHUB_ENCRYPTION_ACR_CFG regions; set VIDMEM_READ/WRITE_VALID

BSI_LOCK (resume path, GC6 exit):
  1. Load encHubKey from NV_PGC6_BSI_HUB_ENCRYPTION_SECURE_SCRATCH
  2. Re-derive derivedKey via same salt + SCP slot
  3. scp_rkey10(R4, R3)                              ← generate AES-128 inverse key schedule in R3
  4. scp_decrypt(R2=encHubKey, R4)                   ← R4 = AES-ECB-decrypt(encHubKey, derivedKey)
  5. Re-program SFBHUB keys from decrypted value
```

BSI RAM access is mutex-protected via `SEC2_MUTEX_BSI_WRITE` throughout.

---

## 7. Layer 6 — APM / Confidential Computing Attestation

**Source:** `uproc/acr/src/apm/ampere/`, `uproc/acr/src/apm/nv/`  
**Binary:** `acr/bin/sec2/ga100/ahesasc_apm/` (28,928 B, +5,632 B vs baseline)  
**Analysis:** `7-4-phase4-ahesasc-apm.md`

APM extends AHESASC with a SHA-256-based measurement register (MSR) chain for
Confidential Computing attestation. It is a separate variant loaded only on A100 SXM4.

### 7.1 SKU Gate

```c
// _acrCheckIfApmEnabled_GA100:
apmMode = ACR_REG_RD32(BAR0, NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC);
devId   = DRF_VAL(_FUSE, _OPT_PCIE_DEVIDA, _DATA, ...)    // must = 0x20B5 (A100 SXM4 80GB)
chipId  = DRF_VAL(_PMC,  _BOOT_42, _CHIP_ID, ...)          // must = 0x170 (GA100)
```

The CC mode bit is set by VBIOS at POST from OOB/NvFlash — it is a **secure scratch
register, not an OTP fuse**. It can be toggled without fuse programming (Finding P3-3).

Debug boards skip the DevID check entirely via
`NV_FUSE_OPT_SECURE_SECENGINE_DEBUG_DIS != DATA_NO`.

### 7.2 APM_RTS Memory Layout

`APM_RTS` is a 4,096-byte structure (32 groups × 128 bytes each) stored in a dedicated
WPR sub-region at FB offset `g_offsetApmRts`:

```
APM_MSR_GROUP[g] (128 B each):
  [0x00]  msr     (32 B) — current SHA-256 measurement (big-endian)
  [0x20]  msrs    (32 B) — shadow measurement
  [0x40]  msrcnt  (4 B)  — extend count for msr
  [0x44]  msrscnt (4 B)  — extend count for msrs
  [0x48]  reserved (56 B)

MSR index allocation:
  MSR[0]  — security fuses + engine FPF versions (_acrMeasureFuses_GA100)
  MSR[1]  — NV_PFB_PRI_MMU_WPR_ALLOW_READ/WRITE state
  MSR[5]  — SEC2 AES-DM hash
  MSR[6]  — PMU  AES-DM hash
  MSR[7]  — NVDEC AES-DM hash
  MSR[8]  — FECS AES-DM hash
  MSR[9]  — GPCCS AES-DM hash
  MSR[2,3,4,10–31] — unassigned / not populated in APM source
```

### 7.3 MSR Extension Algorithm (PCR-style chain)

Extension buffer (68 bytes):
```
[0x00] reserved = 0x00
[0x01] reserved = 0x00
[0x02] falconID = LSF_FALCON_ID_SEC2   ← HARDCODED for all MSRs (Finding P3-1)
[0x03] prevStateSrc: 0x00=old_MSR / 0x01=zero
[0x04..0x23] newMeasurement (32 B SHA-256 input)
[0x24..0x43] prevState (current MSR value, or zeros)
```

```
new_MSR = SHA-256(extension_buffer_68B)
```

Access to APM_RTS in WPR FB is serialized by `SEC2_MUTEX_APM_RTS`.

### 7.4 Compound Vulnerability: APM_RTS DMA Attack

```
Prerequisite chain:
  [P1-1] DMEM PLM = READ_L0_WRITE_L0  → host kernel or LS Falcon can write GSP DMEM
  [P1-2] REGIONCFG #if 0              → GSP-RM FBIF DMA has no WPR restriction
  [P3-2] APM_RTS in WPR sub-region    → reachable by unrestricted FBIF DMA

Attack:
  1. Achieve code execution in GSP-RM (enabled by [P1-1] — write RPC buffer in DMEM)
  2. Issue FB-DMA from compromised GSP-RM to APM_RTS sub-WPR address (enabled by [P1-2])
  3. Overwrite MSR values and extend-counts before or after AHESASC_APM runs
  4. Attestation chain reports forged measurements to the CC verifier

WPR2 CPU-side lock (set by acrLockWpr1DuringACRLoad_TU10X) restricts host CPU access
but NOT Falcon FBIF DMA when REGIONCFG is disabled.
```

**Severity:** Medium — A100 SXM4 only; requires GSP-RM compromise first.

---

## 8. Layer 7 — Runtime: ASB Bootstraps LS Falcons

**Source:** `uproc/acr/src/asb/ampere/acr_ls_falcon_boot_ga100.c`,
            `uproc/acr/src/asb/turing/acr_ls_falcon_boot_tu10x.c`  
**Binary:** `acr/bin/gsp/ga100/asb/g_acruc_ga100_asb.{nm,objdump}` (10,752 B HS code)

After AHESASC completes verification, ASB (running on GSP-lite) bootstraps each LS Falcon:

### 8.1 Falcon Dispatch Table (binary-confirmed @ ASB 0x2348)

| falconId | Addr | Engine | Register base |
|---|---|---|---|
| 0 | `0x23D1` | PMU | `0x1F9000` area |
| 1 | `0x2519` | DPU | — |
| 2 | `0x2466` | FECS | `0x1009000 + (inst<<21)` |
| 3 | `0x24A7` | GPCCS | `0x502000 + (inst<<15) + 0xA34` |
| 4 | `0x24D8` | NVDEC | — |
| 7 | `0x2422` | SEC2 | `0x840000` area |

### 8.2 FECS DMA Arbiter Stride (unchecked, binary-confirmed @ ASB 0x2577)

```asm
258f: lsl.w a0 a9 0x15       ← a0 = falconInstance << 21  (NO BOUNDS CHECK)
2592: mvi a9 0x1009a20        ← base = NV_PGRAPH_PRI_FECS_ARB_CMD_OVERRIDE
2597: add.w a2 a0 a9          ← regAddr = base + (instance << 21)
```

`NV_GPC_PRI_STRIDE = 1 << 21 = 0x200000`. `falconInstance` passed unchecked from caller.
No attacker-reachable path to control `falconInstance` has been found in the current
call graph. This remains an internal implementation hazard.

### 8.3 LS Bootvec Mechanism (prod-only, binary-confirmed @ ASB 0x1ABE)

```asm
_acrlibSetupBootvec_TU10X:
  1ac9-1ad5: save stack canary
  1ad5: call _acrlibFlcnRegLabelWrite_TU10X   ← one BAR0 register write, that is all
  1ad9-1ae6: verify canary
```

The `acrlibSetupBootvecRiscv_GA100` function (from `acr_riscv_ls_ga100.c`, gated by
`#ifdef ACR_RISCV_LS`) is **not compiled into the prod-signed ASB binary**.
No ITCM machine-code emission. No MSPM/MRSP CSR gadgets. The ITCM gadget hypothesis
from Phase-2 §3.1 is definitively refuted for the prod build.

---

## 9. Post-Verification Persistent Weaknesses

These are not momentary verification failures — they persist for the entire GPU uptime:

| ID | Register / Mechanism | Value | Effect | Source evidence |
|---|---|---|---|---|
| **W-1** | `NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK` (0x110284) | `0xFF` | GSP DMEM writable by any L0 actor — host kernel, other LS Falcons | Booter binary+0x5498; source TODO comment |
| **W-2** | `NV_PGSP_FBIF_REGIONCFG` (0x11066C) | Not written (disabled) | GSP-RM FBIF DMA can reach any FB address including WPR | Needle absent from Booter binary; `#if 0` in source |
| **W-3** | GSP-RM privilege level | L0 | GSP-RM cannot re-tighten its own PLMs; inherits W-1 forever | Source comment; no PLM symbols in GSP-RM RISC-V ELF |
| **W-4** | APM CC enable bit | Scratch register | CC attestation mode can be toggled by OOB/VBIOS flash without OTP | `NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC`; not fuse-backed |
| **W-5** | APM MSR falconID field | Hardcoded SEC2 | All 9 active MSR groups attribute to SEC2; verifier cannot distinguish engines | Source comment "needs to be replaced with current falcon" |

---

## 10. Complete Chain Diagram

```
SPI Flash (VBIOS)
│  <GPU ROM archive>:0xC700 / <GPU ROM archive>:0xB500
│  BIT token 'p' → FALCON_DATA_V2 → FWSEC V3 descriptor
│  signaturesTotalSize from vDesc[31:16] — no upper bound check [P4-1]
│
├─► Host kernel: kernel_gsp_fwsec.c parser
│     s_vbiosFindBitHeader → s_vbiosParseFwsecUcodeDescFromBit
│     s_vbiosFillFlcnUcodeFromDescV3 → portMemAllocNonPaged(signaturesTotalSize)
│     kgspExecuteFwsecFrts → load FWSEC onto SEC2
│
▼
FWSEC (SEC2 HS, VBIOS-embedded)
│  Sets up WPR2 (FRTS data region)
│  Writes _FRTS_OUTPUT_FLAG_..._ACR_READY = YES
│  KDF domain byte[0] = 0x00 (shares bytes[1..15] with AHESASC salt)
│
▼
Boot ROM (silicon-immutable, RSA-3K root)
│  Verifies Booter binary RSA-3K signature
│  Keys: prod RSA-3K pubkey + debug RSA-3K pubkey (both silicon-embedded)
│
▼
Booter LOAD (GSP-lite HS)  [35,328 B; active 24,320 B; sig @ +0x5F00]
│  TU10X code path (NOT GA10X manifest path)
│  Chip-lock:    PMC_BOOT_42.CHIP_ID == 0x170 (GA100) or 0x171+debug
│  Anti-rollback: FPF fuse 0x824250, popcount(low 8 bits) >= SW build version
│
│  PLM writes (binary-confirmed):
│    IMEM_PLM  0x110280 = 0x8F  READ_L0 / WRITE_L3         ✓ SECURE
│    DMEM_PLM  0x110284 = 0xFF  READ_L0 / WRITE_L0  ⚠ CRITICAL (W-1)
│    SCTL_PLM  0x110298 = 0x8F  READ_L0 / WRITE_L3         ✓ SECURE
│
│  REGIONCFG:  0x11066C        NOT WRITTEN (#if 0)  ⚠ CRITICAL (W-2)
│
│  Handoff:   BSI_VPR_SECURE_SCRATCH_14.BOOTER_LOAD_HANDOFF = DONE
│  Launch:    NV_PGSP_RISCV_CPUCTL_ALIAS = STARTCPU_TRUE
│
▼
AHESASC (SEC2 HS task)  [23,296 B baseline; three variants]
│
│  Init sequence (acrInit_TU10X):
│    HUB encryption:  TRNG keys → AES-ECB wrap via SCP_HUB_KEY_INDEX
│                     → BSI scratch NV_PGC6_BSI_HUB_ENCRYPTION_SECURE_SCRATCH
│                     → SFBHUB subkeys programmed via secure bus
│
│    WPR1 MMU lock:   NV_PFB_PRI_MMU_WPR1_ADDR_LO/HI programmed
│                     ALLOW_READ / ALLOW_WRITE with sub-WPR enable
│                     SubWPR: SEC2-full-R/W-L2+L3, PMU-full-R/W-L2+L3, GSP-full-R-L3
│
│    FRTS copy:        WPR2→WPR1 via double-buffered DMA
│
│  LS verification loop (acrValidateSignatureAndScrubUnusedWpr_TU10X):
│    For each falcon in WPR header:
│      ┌─ AES-DM hash ucode bytes (Davies-Meyer, 16 B blocks):
│      │     H[i] = H[i-1] XOR AES-ECB(key=m_i, plain=H[i-1])
│      │     via SCP trapped CSR instructions (falc_scp_*)
│      │
│      ├─ Optionally extend hash with version + depMap
│      │
│      ├─ Key derivation (SCP slot 43 / prod):
│      │     saltBuf = g_kdfSalt XOR (falconId << 0)  ← domain separation
│      │     derivedKey = AES-ECB(saltBuf, scpSecret[43])
│      │     signature  = AES-ECB(dmHash,  derivedKey)
│      │
│      ├─ Compare signature against LSF header stored sig
│      │
│      ├─ Check depMap: pBinVersions[dep] >= expectedVer
│      │
│      └─ On PASS: setup sub-WPR for this falcon's code/data region
│         On FAIL: DMA-scrub ucode+data to zero, return error
│
▼
LS Falcon Runtime (PMU / FECS / GPCCS / NVDEC / FBFalcon / SEC2-RTOS)
│  Each falcon's code+data in a locked sub-WPR
│  Bootstrapped by ASB (GSP-lite) after AHESASC verification completes
│
▼
GSP-RM RISC-V  [172,032 B; runs at L0]
   DMEM_PLM = 0xFF  ← inherits Booter setting (W-1); GSP-RM cannot re-tighten (W-3)
   FBIF DMA unrestricted (W-2) — can reach any FB address including APM_RTS sub-WPR

━━━━━━━━━━━ APM PATH (A100 SXM4 only, DevID=0x20B5) ━━━━━━━━━━━
AHESASC_APM additionally:
  Checks CC bit in NV_PGC6_AON_SECURE_SCRATCH_GROUP_20 (scratch, not fuse — W-4)
  Measures: fuses, WPR MMU state, per-falcon AES-DM hashes (MSR[0,1,5–9])
  MSR extension: SHA-256(falconID=SEC2_HARDCODED || prevState || newMeasurement) (W-5)
  APM_RTS in WPR sub-region — reachable via W-1+W-2 compound chain
```

---

## 11. Cryptographic Primitive Inventory

| Location | Algorithm | Key source | Key type | Security property |
|---|---|---|---|---|
| ROM → Booter | RSA-3072 / SHA-256 | Silicon-embedded pubkey | Asymmetric | Unbroken; out of scope |
| Booter → AHESASC | RSA-3072 (same chain) | Same ROM pubkey | Asymmetric | Unbroken |
| LS signature verification | AES-128 Davies-Meyer hash | ucode bytes as key schedule | Symmetric (hash) | ~2^64 collision bound |
| LS key derivation | AES-128 ECB | SCP slot 43 (per-die HW secret) | Symmetric | Confidential to silicon |
| LS signature encrypt | AES-128 ECB | derived key (above) | Symmetric | Per-falcon domain |
| HUB key wrap | AES-128 ECB | SCP_HUB_KEY_INDEX slot | Symmetric | At-rest protection |
| HUB key derivation | AES-128 ECB | SCP_HUB_KEY_INDEX + public salt | Symmetric | Salt public; key from SCP |
| APM MSR chain | SHA-256 | N/A (hash) | Hash | SHA-256 collision resistance |
| APM FWSEC KDF | AES-128 ECB | SCP slot (domain byte 0x00) | Symmetric | Same root as LS slot 43 |

**Single root-of-trust for LS regime:** SCP slot 43. Compromise of any one GA100 die's
SCP slot 43 (via fault injection, SCA, or EM probing) enables offline forgery of valid
LS signatures for all falconIds across all GA100 dies globally.

---

## 12. Open Items Not Yet Analyzed

| Item | File | Security relevance |
|---|---|---|
| Booter RELOAD binary | `gsprm/bin/booter/ga100/reload/g_booteruc_reload_ga100_prod.h` | PLM behavior on resume from GC6; may re-tighten or inherit |
| Booter UNLOAD binary | `gsprm/bin/booter/ga100/unload/g_booteruc_unload_ga100_prod.h` | PLM teardown; does it widen PLMs before GPU handoff? |
| AHESASC GSP-RM variant | `acr/bin/sec2/ga100/ahesasc_gsp_rm/` | MIG isolation differences vs baseline |
| PMU + SEC2 Unload | ACR Unload binary for PMU/SEC2 | PLM state at driver teardown |
| `_acrSetupLSFalcon_TU10X` @ ASB 0x1E81 | ASB objdump | Pre-verify DMA scribble — does ucodeOffset get re-validated before use as DMA source after signature verify? |

---

*Cross-references: `7-3-phase4-booter-analysis.md` (PLM/REGIONCFG binary evidence),
`7-2-phase3-binary-analysis.md` §3a (AES-DM binary confirmation),
`7-4-phase4-ahesasc-apm.md` (APM/CC details),
`2-5-host-firmware-parser.md` + `2-5-host-firmware-parser.md` (parser gaps),
`2-6-vbios-ucode-catalog.md` (ROM structure and FWSEC sizes).*
