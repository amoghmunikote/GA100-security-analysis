# Phase-3 Binary Reverse-Engineering — GA100 / CMP 170HX

**Scope**: Move from source-code claims (Phase-2,
`13_PHASE2_VALIDATION_AND_NEW_FINDINGS.md`) to **binary evidence** of what
is actually compiled into the production-signed firmware shipping on the
CMP 170HX (device-ID `0x10DE:0x20C2`, chip ID `0x170` = GA100).

Material used (all under
`drivers/resman/kernel/inc/`):

| Component | ELF / objdump artifact |
|---|---|
| ASB (Falcon HS, runs on GSP-lite) | `acr/bin/gsp/ga100/asb/g_acruc_ga100_asb.{nm,objdump,readelf,out}` |
| AHESASC (Falcon HS, runs on SEC2) | `acr/bin/sec2/ga100/ahesasc/g_acruc_ga100_ahesasc.{nm,objdump,readelf,out}` |
| ACR Unload (Falcon HS, runs on PMU) | `acr/bin/pmu/ga100/g_acruc_ga100_unload.{nm,objdump,readelf,out}` |
| GSP RISC-V image | `gsp/bin/g_gsp_ga100_riscv.{elf,nm,objdump,readelf,image.bin}` |
| Booter Load/Unload/Reload | `gsprm/bin/booter/ga100/{load,reload,unload}/` (no .nm/.objdump in tree) |
| CMP 170HX VBIOS dump | `d:\lapsus\cmp170hxBinary.BIN` (1 044 480 B = 0xFF000) |
| A100 reference VBIOS | `d:\lapsus\NVIDIA.A100.40960.200214.BIN` (1 044 480 B = 0xFF000) — cross-check source |

The headline result: **two of the three "critical" findings in
`13_PHASE2_*.md` are not present in the prod-signed silicon**. The
remaining one (GSP DMEM PLM at READ_L0_WRITE_L0) lives in the Booter,
whose binary is not disassembled in this archive — a Phase-4 target.

---

## 1. Prod ASB binary (GSP-lite) — full enumeration

`g_acruc_ga100_asb.readelf` confirms a small Falcon ELFv6 image with
118 symbols. Layout:

```
.text                  @ 0x00000000  size 0x000be  (non-HS bootstrap)
.text.__canary_setup   @ 0x000000be  size 0x0000c
.imem_acr (HS code)    @ 0x00000100  size 0x02900  (LOAD to 0x20000000)
.data                  @ 0x10000000  size 0x00918
.bss                   @ 0x10000920  size 0x00018
```

HS payload is **10 752 bytes** of code — tiny for a security-critical
component, which is the point.

### 1.1 No RISC-V symbols, no ITCM bootstub

```
$ grep -i "riscv\|Riscv" g_acruc_ga100_asb.nm   →  (empty)
$ grep -i "riscv\|Riscv" g_acruc_ga100_ahesasc.nm → (empty)
```

The function `acrlibSetupBootvecRiscv_GA100`
([acr_riscv_ls_ga100.c:50](integ/gpu_drv/stage_rel/uproc/acr/src/asb/ampere/acr_riscv_ls_ga100.c#L50))
is not compiled into either prod binary. The only `Bootvec` symbol is
the Falcon-only `_acrlibSetupBootvec_TU10X` at `0x1abe`, which is **43
bytes** and decodes to one BAR0 register write (a single
`_acrlibFlcnRegLabelWrite_TU10X` call):

```
00001abe <_acrlibSetupBootvec_TU10X>:
    1abe: addsp -0x4
    1ac1: pushm a1
    1ac3: mvi a1 0x930             ; stack canary addr
    1ac7: ldd.w a9 a1              ; load canary
    1ac9: mv.w a12 a11             ; a12 = bootvec value (passed in a11)
    1ac4-1ad3: save canary on stack
    1ad5: call 0x1105              ; _acrlibFlcnRegLabelWrite_TU10X
    1ad9-1ae6: canary check
    1ae6: popma a1 0x1 0x4
```

That is **the entire LS bootvec mechanism on prod GA100 ASB**: write
one register, return. No ITCM machine-code emission, no MSPM/MRSP CSR
shenanigans, no LSMODE_LEVEL2 promotion gadget.

**Phase-2 §3.1 is therefore DOWNGRADED from CRITICAL to
INFORMATIONAL.** The ITCM bootstub gadget exists only in source under
`#ifdef ACR_RISCV_LS`. The CMP 170HX prod ACR build does not enable
that define. The author's comment "should not be prod-signed without
HS-signer approval" was followed: it was excluded.

What this also tells us: **GSP-RM on GA100 must be brought up by the
Booter** (separate Falcon HS, not in this disassembly), not by ACR.
The Booter is the place to look for the analogous bootstrap.

### 1.2 GA100-specific functions present in prod ASB

From `g_acruc_ga100_asb.nm`:

| Address | Size | Symbol |
|---|---|---|
| `0x22c7` | 53 | `_acrGetUcodeBuildVersion_GA100` |
| `0x22fc` | 76 | `_acrCheckIfBuildIsSupported_GA100` |
| `0x2348` | 559 | `_acrlibGetFalconConfig_GA100` |
| `0x2577` | 137 | `_acrlibSetupFecsDmaThroughArbiter_GA100` |
| `0x2600` | 77 | `_acrGetUcodeFpfFuseVersion_GA100` |
| `0x264d` | 82 | `_acrCheckFuseRevocationAgainstHWFpfVersion_GA100` |

### 1.3 `_acrCheckIfBuildIsSupported_GA100` (chip-lock)

Decoded from `g_acruc_ga100_asb.objdump:3123`:

```
22fc-2305: prologue (stack canary)
2308: mvi a10 0xa00            ; NV_PMC_BOOT_42 = 0xA00
230d: call 0x1040              ; BAR0_RD32(0xA00)
2311: uxtr a10 a10 0x114       ; CHIP_ID = bits[24..23], width 20 → 0x114 == DRF_BASE/SIZE encoding
2315: cmpbreq.w a10 0x170 0x232b   ; if CHIP_ID == 0x170 (GA100) → goto OK
231a: mvi a14 0xf              ; err = 0xF = ACR_ERROR_INVALID_CHIP_ID
231c: cmpbrne.w a10 0x171 0x232d   ; if CHIP_ID != 0x171 (GA101) → return err
2321: call 0x7c6               ; _acrIsDebugModeEnabled_TU10X
2325: mvi a14 0x4b             ; err = 0x4B = ACR_ERROR_PROD_MODE_NOT_SUPPORTED
2327: cmpbreq.b a10 0x0 0x232d ; if !debug → return err (prod mode forbidden on GA101)
232b: clr.w a14                ; OK
232d-2346: epilogue
```

Clean implementation of
[booter_sanity_checks_ga100.c:21-41](integ/gpu_drv/stage_rel/uproc/booter/src/common/ampere/booter_sanity_checks_ga100.c#L21-L41).
Chip-lock is real: this image only runs on `0x170` (GA100, includes
A100/CMP170HX/A30) and `0x171` (GA101) with debug mode required for
the latter.

### 1.4 `_acrCheckFuseRevocationAgainstHWFpfVersion_GA100` — anti-rollback

The real anti-rollback gate (not the `binVersion` Phase-1 claimed).
Decoded from `g_acruc_ga100_asb.objdump:3395`:

```
264d-266a: prologue, a1 = SW_ucode_version_arg
266e: call 0x2600              ; _acrGetUcodeFpfFuseVersion_GA100(&hwFuseVersion)
2672: mvi a14 0x4e             ; err = 0x4E = ACR_ERROR_FUSE_REVOCATION_CHECK_FAIL?
2674: cmpbrne.w a10 0x0 0x2683 ; if call != ACR_OK, return that
2678: ldd.w a9 a0              ; a9 = hwFuseVersion (count of set FPF bits)
267a: mvi a14 0x23             ; err = 0x23 = ACR_ERROR_UCODE_REVOKED
267c: cmp.w a1 a9              ; SW vs HW
267e: brc 0x2683               ; if SW < HW (unsigned)  → return revoked
2681: clr.w a14                ; OK
2683-269c: epilogue
```

Sub-routine `_acrGetUcodeFpfFuseVersion_GA100` (0x2600):

```
2615: mvi a10 0x824250         ; FPF FUSE reg = 0x824250
                               ; = NV_FUSE_OPT_FPF_UCODE_ACR_HS_REV
261a: call 0x1040              ; BAR0_RD32
2620: and a10 0xff             ; fuse &= 0xFF (low 8 bits)
2623→262d: count trailing one-bits
    9 = 0
    loop:
      9++; fuse >>= 1
    until fuse == 0
2631: *pUcodeFpfFuseVersion = count
```

Implementation matches
[booter_sanity_checks_ga100_and_later.c:25-49](integ/gpu_drv/stage_rel/uproc/booter/src/common/ampere/booter_sanity_checks_ga100_and_later.c#L25-L49).

**Fuse register `0x824250` is the monotone hardware anti-rollback
counter for ACR HS revisions.** Each silicon rev burns one more bit
into the low 8 bits of that fuse. ACR's compile-time
`BOOTER_GA100_UCODE_BUILD_VERSION` constant is compared against the
popcount-derived version; smaller values are rejected with
`ACR_ERROR_UCODE_REVOKED` (0x23).

**This invalidates Phase-1 finding #8** ("version rollback possible
via `binVersion`"). The `binVersion` field in the LSF wrapper is just a
metadata label. The real gate is FPF fuse `0x824250` and cannot be
defeated without consuming a chip with stale fuses or breaking the HS
sign chain.

### 1.5 `_acrlibSetupFecsDmaThroughArbiter_GA100` — confirms unchecked stride math

Decoded from `g_acruc_ga100_asb.objdump:3321`:

```
2577-2588: prologue, a1=bIsPhysical
258c: ldd.w a9 a10 0x4             ; a9 = pFlcnCfg->falconInstance
258f: lsl.w a0 a9 0x15              ; a0 = falconInstance << 21        ← NO BOUNDS CHECK
2592: mvi a9 0x1009a20              ; base = NV_PGRAPH_PRI_FECS_ARB_CMD_OVERRIDE
2597: add.w a2 a0 a9                ; regFecsCmdOvr = base + (instance << 21)
259a: cmpbreq.b a11 0x0 0x25b8      ; if !bIsPhysical skip ARB_WPR
259e: add.w a9 a9 0xc                ; ARB_WPR = ARB_CMD_OVERRIDE + 0xc
25a1: add.w a0 a0 a9                ; regFecsArbWpr = base+0xc + (instance << 21)
25a6: call 0x1040                   ; RD32(regFecsArbWpr)
25aa-25b4: OR 0x01000000 (PHYSICAL_WRITES_ALLOWED), WR32
25ba: call 0x1040                   ; RD32(regFecsCmdOvr)
25be-25c3: clr low 5 bits, set bit1 (_PHYS_VID_MEM)
25c6-25db: set/clear ENABLE bit (bit 31) per bIsPhysical
25e0: call 0xfe8                    ; WR32(regFecsCmdOvr)
25e4-25fd: epilogue
```

`NV_GPC_PRI_STRIDE` is confirmed as `0x200000` (= `1 << 21`). The
computed register address is `base + instance * 2MB`. **No bounds
check on `instance`.** The caller (`_acrlibGetFalconConfig_GA100`)
stores the caller-supplied `falconInstance` argument unchecked into
`pFlcnCfg->falconInstance` at offset 0x4 of the config struct.

But again, in this ASB binary the call chain only originates from
`_acrSetupLSFalcon_TU10X` and the WPR-iteration loop, which pass small
integers. To turn this into a primitive an attacker would need to
influence `falconInstance` upstream — and no path I've traced does so.

### 1.6 `_acrlibGetFalconConfig_GA100` dispatch table

Decoded the dispatch portion of the 559-byte function
(`g_acruc_ga100_asb.objdump:3150`). The branch tree maps `falconId`
to handler:

| falconId | Handler @ | Falcon                |
|---|---|---|
| `0` | `0x23d1` | LSF_FALCON_ID_PMU |
| `1` | `0x2519` | LSF_FALCON_ID_DPU |
| `2` | `0x2466` | LSF_FALCON_ID_FECS (uses SMC `<<21` stride) |
| `3` | `0x24a7` | LSF_FALCON_ID_GPCCS (uses GPC stride) |
| `4` | `0x24d8` | LSF_FALCON_ID_NVDEC |
| `7` | `0x2422` | LSF_FALCON_ID_SEC2 |
| others | default | returns `0x3 = ACR_ERROR_FLCN_ID_NOT_FOUND` |

Notable per-handler constants (BAR0 register bases) for forensics /
register-aperture audit:

| falconId | `subWprRangeAddrBase` | `subWprRangePlmAddr` | `registerBase` |
|---|---|---|---|
| 0 (PMU) | `0x10A000` (NV_PFB_PRI_MMU_FALCON_PMU_CFGA(0)) | `0x10A000 + 0xE00 = 0x10AE00` | `0x1F9000`-area |
| 2 (FECS) | n/a (priv-loaded) | n/a | `0x1009000 + (inst<<21)` |
| 3 (GPCCS) | n/a | n/a | `0x502000 + (inst<<15) + 0xA34` |
| 7 (SEC2) | `0x848000`-area | `+0x600` | `0x840000`-area |

The GPCCS handler uses `lsl.w a9 a11 0xf` — a `<<15` stride
(= 0x8000 = 32KB), corresponding to `NV_GPC_PRI_SHARED_BASE` /
`NV_GPCCS_STRIDE`. Different stride than FECS because GPCCS is
addressed per-TPC inside a GPC.

---

## 2. Prod AHESASC binary (SEC2) — GA100 deltas

`g_acruc_ga100_ahesasc.nm` is much larger (~6KB of code section). The
GA100-specific symbols beyond what ASB carries:

| Address | Size | Symbol |
|---|---|---|
| `0x323a` | 85 | `_acrProgramDecodeTrapToIsolateTSTGRegisterToFECSWARBug2823165_GA100` |
| `0x328f` | 268 | `_acrGetUsableFbSizeInMB_GA100` |
| `0x339b` | 205 | `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100` |
| `0x3468` | 348 | `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` |
| `0x37f3` | 137 | `_acrlibSetupFecsDmaThroughArbiter_GA100` (same as ASB) |
| `0x391b` | 135 | `_acrGetLocalMemRangeInMB_GA100` |

All four `GA100`-tagged WAR functions are **present in the prod-signed
AHESASC binary**, including the HBM2e-row-remap WPR placement check
(see §2.2 below).

### 2.1 `_acrProgramDecodeTrapToIsolateTSTGRegisterToFECSWARBug2823165_GA100`

Decoded from `g_acruc_ga100_ahesasc.objdump:4411`:

```
3245: mvi a10 0x122454    ; NV_PPRIV_SYS_PRI_DECODE_TRAP21_MATCH
3249: mvi a11 0x10140098  ; MATCH value: SOURCE_ID=4 (FECS) + ADDR=0x140098
324e-3256: BAR0 WR32 (TRAP_MATCH = 0x10140098)

325a: mvi a10 0x1226d4    ; NV_PPRIV_SYS_PRI_DECODE_TRAP21_MATCH_CFG
325e: mvi a11 0x3e010     ; ALL_LEVELS | INVERT_SOURCE_ID | IGNORE_READ
3262: BAR0 WR32

3266: mvi a10 0x1224d4    ; NV_PPRIV_SYS_PRI_DECODE_TRAP21_MASK
326a: mvi a11 0x1003fe00  ; SOURCE_ID mask + ADDR mask
326f: BAR0 WR32

3273: mvi a10 0x122654    ; NV_PPRIV_SYS_PRI_DECODE_TRAP21_ACTION
3277: mvi a11 0x8         ; FORCE_ERROR_RETURN
3279: BAR0 WR32
```

The trap **locks the LTC TSTG_CFG_2 register (0x140098 in
LTC0_LTS0)** to FECS-only access by failing any non-FECS request with
an error. This is *defense* against bug 2823165. **Confirmed in prod
binary.**

### 2.2 `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` (HBM2e logic)

Decoded `g_acruc_ga100_ahesasc.objdump:4605`. Receives WPR start/end
in two 64-bit pairs (a10/a11 = startLo/Hi, a12/a13 = endLo/Hi). Calls:

```
34a5: call 0x328f         ; _acrGetUsableFbSizeInMB_GA100 → fbSizeCStatusMB
                          ; (walks all FBPAs, reads CSTATUS RAMAMOUNT, sums)
34c1: call 0x391b         ; _acrGetLocalMemRangeInMB_GA100
34d9: subtract → fbHoleMB = localMemRangeMB - fbSizeCStatusMB
```

Then four range checks against the "FB hole" bands and three
memlock-range consistency checks. Error codes (visible in disassembly
as `mvi a2`):

| Code | Meaning |
|---|---|
| `0x54` | WPR start in bottom FB-hole band |
| `0x55` | WPR end in bottom FB-hole band |
| `0x56` | WPR start in top FB-hole band |
| `0x57` | WPR end in top FB-hole band |
| `0x58` | Memlock range not enabled |
| `0x59` | Memlock range start mismatch on top band |
| `0x5A` | Memlock range end mismatch on top band |
| `0x73` | Invalid usable FB size |

All checks match
[booter_war_functions_ga100_only.c:156-239](integ/gpu_drv/stage_rel/uproc/booter/src/common/ampere/booter_war_functions_ga100_only.c#L156-L239).

**This is GA100's HBM2e-specific WPR hardening.** Confirmed shipped.

### 2.3 What this means for Phase-2 §1.1 ("no HBM2e training in firmware")

The GA100 ACR firmware **knows about HBM2e** (row remapper, FB hole,
memlock range) but only to *validate WPR placement*. It does not
perform HBM2e signal training itself; training remains in
VBIOS-DEVINIT-on-PMU. Phase-2 §1.1 stands.

---

## 3. CMP 170HX vs A100 VBIOS — cross-validated carve

Both VBIOS files are **exactly 1 044 480 B (0xFF000)**. I'd previously
written 1 048 848 — that was a transcription error from an old Get-Item
output. The actual structure is identical between the two cards, with
only data-table sizes and content differing.

### 3.1 ROM structure (verified on BOTH files)

```
Offset      CMP 170HX (device 0x20C2)       A100 (device 0x20B0)
─────────   ─────────────────────────────   ─────────────────────────────
0x000000    IFR-1 NVGIR … total 0x6B4 B     IFR-1 NVGIR … total 0x6C0 B
0x000636    RFRD marker                     (similar marker, different content)
…           padding / sub-tables            …
0x005000                                    ★ PCI ROM Image #1 start
0x005E00    ★ PCI ROM Image #1 start
            0x5E00 55 AA …                   0x5000 55 AA …
            0x5E70 PCIR dev=0x20C2            0x5070 PCIR dev=0x20B0
                     imgLen=0x6200                   imgLen=0x5E00
            0x5E90 NPDE subimageLen=0x31      0x5090 NPDE subimageLen=0x2F
                     privLastImage=0                 privLastImage=0
            0x5EB0 BIT  (16 entries)          0x50B0 BIT  (16 entries, same toks)
0x00B500                                    ★ PCI ROM Image #2 start
0x00C700    ★ PCI ROM Image #2 start
0x05E000-   padding (0xFF flash)             padding
0x060000    IFR-2 (byte-identical to IFR-1) IFR-2 (byte-identical to IFR-1)
0x065000                                    Recovery copy of Image #1
0x065E00    Recovery copy of Image #1
0x06B500                                    Recovery copy of Image #2
0x06C700    Recovery copy of Image #2
0x0C0000-   padding (0xFF erased flash)     same
0x0FF000    EOF                              EOF
```

Confirmed against both binaries:

```
$ for f in cmp170hxBinary.BIN NVIDIA.A100.40960.200214.BIN; do
    locate 55 AA at 0x100-aligned offsets in first 0xC0000 bytes
  done
CMP:  0x5E00, 0xC700, 0x65E00, 0x6C700
A100: 0x5000, 0xB500, 0x65000, 0x6B500

$ IFR-1 (0..0x6B4) vs IFR-2 (0x60000..0x606B4) compared byte-for-byte
CMP:  0 differences
A100: 0 differences   ← IFR exactly duplicated

$ Halves 0..0x60000 vs 0x60000..0xC0000 compared
CMP:  227 differences  ← VBIOS body has rolling fields (date/version)
A100: 151 differences
```

Two-pair redundancy with byte-perfect IFR duplication and *near*-perfect
body duplication. The differing 100–230 bytes in the body halves carry
revision counters / second-stage signatures.

### 3.2 BIT table contents — full 16 entries, both VBIOSes

The BIT header (12 bytes starting with `0xB8 0xFF "BIT\0" 0x00 0x01
0x0C 0x06 0x10 0x47`) is byte-identical between CMP 170HX and A100:
same 16 entries, same checksum (0x47), same token IDs, same versions.
Only the *sizes* and *pointers* of individual data tables differ.

| Token | Ver | CMP size | CMP ptr | A100 size | A100 ptr | Meaning |
|---|---|---|---|---|---|---|
| `0x32` (2) | 1 | 0x004 | 0x012C | 0x004 | 0x012C | (Internal — version anchor) |
| `'B'` 0x42 | 2 | 0x025 | 0x0138 | 0x025 | 0x0138 | BIT_DATA_BIOSDATA |
| `'C'` 0x43 | 2 | **0x02C** | 0x015D | **0x01C** | 0x015D | BIT_DATA_CLOCK (CMP has +16 B clock data) |
| `'D'` 0x44 | 1 | 0x004 | 0x0189 | 0x004 | 0x0179 | BIT_DATA_DAC |
| `'I'` 0x49 | 1 | 0x024 | 0x018D | 0x024 | 0x017D | BIT_DATA_INTERNAL |
| `'M'` 0x4D | 2 | 0x029 | 0x01B1 | 0x029 | 0x01A1 | BIT_DATA_MEMORY |
| `'N'` 0x4E | 0 | 0x000 | 0x0000 | 0x000 | 0x0000 | empty |
| `'P'` 0x50 | 2 | **0x0E8** | 0x01DA | **0x0C4** | 0x01CA | BIT_DATA_PERF (CMP has +36 B perf data) |
| `'T'` 0x54 | 1 | 0x002 | 0x02C2 | 0x002 | 0x028E | BIT_DATA_TMDS_INFO |
| `'U'` 0x55 | 1 | 0x005 | 0x02C4 | 0x005 | 0x0290 | BIT_DATA_USERDEF |
| `'V'` 0x56 | 1 | 0x006 | 0x02C9 | 0x006 | 0x0295 | BIT_DATA_VIRTUAL_STRAP |
| `'x'` 0x78 | 1 | 0x008 | 0x02CF | 0x008 | 0x029B | BIT_DATA_XMEMCFG |
| `'d'` 0x64 | 1 | 0x002 | 0x02D7 | 0x002 | 0x02A3 | BIT_DATA_DCB |
| `'p'` 0x70 | 2 | 0x004 | 0x02D9 | 0x004 | 0x02A5 | **BIT_DATA_FALCON_DATA** |
| `'u'` 0x75 | 1 | 0x00D | 0x02DD | 0x00D | 0x02A9 | **BIT_DATA_UNIFIED_BOOT** (13 B) |
| `'i'` 0x69 | 2 | **0x06E** | 0x02EC | **0x06A** | 0x02B8 | **BIT_DATA_NV_INIT_PTRS_TBL** (110/106 B) |

Pointers are image-relative; image base is `0x5E00` (CMP) / `0x5000`
(A100). The pointer offsets in A100 are uniformly ~0x34 bytes lower
than CMP, reflecting the smaller `'C'` and `'P'` tables.

### 3.3 BIT_DATA_FALCON_DATA (token `'p'`) is a 32-bit pointer

I'd written the entry was the "Falcon ucode catalogue itself." It is
actually a **4-byte pointer** to a separate `FALCON_DATA_V2` structure.
Read on both:

```
CMP 170HX  at image+0x2D9 = file 0x60D9 → contents: 54 63 00 00
                                                 → falconDataPtr = 0x6354
A100       at image+0x2A5 = file 0x52A5 → contents: 44 5F 00 00
                                                 → falconDataPtr = 0x5F44
```

So in both VBIOSes the falcon-data structure itself lives at
`image_base + 0x6354` (CMP) / `image_base + 0x5F44` (A100), which is
beyond Image #1's `imgLen=0x6200` / `0x5E00` boundary. **This means
the falcon catalog spans into Image #2** (the second `55 AA` PCI ROM
image at CMP `0xC700` / A100 `0xB500`) — Image #2 is the firmware
container, not a separate EFI ROM. That's the place to extract:

- DEVINIT script and PMU bootloader ucode
- HBM2e training routines
- Soft-strap tables
- Devid-Init code

### 3.4 BIT_DATA_NV_INIT_PTRS_TBL (token `'i'`) — date stamp

This was the one entry I'd omitted from Phase-3. It contains pointers
to the NV INIT scripts (DEVINIT etc.) **and** an embedded
`MM/DD/YY` ASCII date string at offset 0x10 from the table start:

```
CMP 170HX  table @ file 0x60EC, bytes 0x10-0x17: "05/12/21"
A100       table @ file 0x52B8, bytes 0x10-0x17: "02/13/20"
```

CMP170HX VBIOS was generated **May 12, 2021**; A100 reference VBIOS
**Feb 13, 2020** (consistent with the filename `200214` = 2020-02-14).
The CMP 170HX is the GA100 silicon stepping that NVIDIA released to
the CMP product line ~16 months after the original A100 launch,
re-using the same firmware base but with fresh build-date and the
mining-lock perf-table tweaks visible above as the `+36 B` in
`BIT_DATA_PERF`.

This is the table to follow to actually locate DEVINIT (and therefore
the place where Phase-1 #4/#6 should have been pointed):
`BIT_DATA_NV_INIT_PTRS_TBL` contains the pointers to the NV INIT
script(s) that include HBM2e training, DRAM init, FB config, etc.

---

## 3a. AES-DM LS-signature verification (binary-confirmed) — major correction

I'd previously (Phase-2 §2.3) described GA100 LS authentication as
"AES-CBC encryption with SCP secret slot 31" derived from
`acr_decrypt_ls_ucode_ga10x.c`. **That source file is for GA10x+, not
GA100.** The prod GA100 AHESASC binary uses the **Turing-era AES-DM
signature** path defined in
[acr_verify_ls_signature_tu10x.c](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c).

### 3a.1 Evidence

`g_acruc_ga100_ahesasc.nm` global functions show **no** `_GA10X`
crypto symbols; instead:

```
00001ee6  T _acrCalculateDmhash_TU10X                ← AES-DM hash
000021b3  T _acrDeriveLsVerifKeyAndEncryptDmHash_TU10X  ← key derivation
00002256  T _acrVerifySignature_TU10X               ← end-to-end verify
00002da1  T _acrEncryptAndSaveHubEncryptionKeys_TU10X
00002f2e  T _acrProgramHubEncryption_TU10X
10000800  D _g_kdfSalt           ← 16-byte hardcoded salt
10000c00  D _g_dmHash            ← 16-byte AES-DM hash result
10000c10  D _g_dmHashForGrp      ← per-LS-sig-group hash table
```

**Notably absent**: `_acrDecryptAesCbcBuffer_GA10X`,
`_acrGetDerivedKeyAndLoadScpTrace0_GA10X`,
`_acrIssueDmaAndDecrypt_GA10X`, and **all RSA-3K/SHA-256/PKC functions**
from `acr_signature_manager_ga10x.c`. GA100 does not run the PKC path.

The 16-byte salt at file offset `0x2800` is **byte-identical** to the
`g_kdfSalt` initializer in
[acr_verify_ls_signature_tu10x.c:31-34](integ/gpu_drv/stage_rel/uproc/acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c#L31-L34):

```
0x2800: B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62
```

(VA `0x10000800` → file `0x2000 + 0x800` per the AHESASC .data section
header.)

### 3a.2 Disassembly of `_acrDeriveLsVerifKeyAndEncryptDmHash_TU10X`

From `g_acruc_ga100_ahesasc.objdump:2962`:

```
21b3-21d8: prologue, args:
             a0 = pSaltBuf, a1 = pDmHash, a2 = bUseFalconId,
             a3 = falconId
21d9: mvi a11 0x800           ; offset of g_kdfSalt within DMEM
21dd: mvi a12 0x10             ; size = 16 bytes
21df: call 0x17fb              ; memcpy(pSaltBuf, &g_kdfSalt, 16)
21e3: cmpbrne.b a2 0x1 0x21ee  ; if !bUseFalconId skip XOR
21e7-21ec: pSaltBuf[0..3] ^= falconId

21ee: cci 0x1f                 ; falc_scp_trap(TC_INFINITY)
21f1-21f7: load pSaltBuf into SCP_R3 (trapped dmwrite)
21f9: mvi a9 0x1130            ; addr of g_bIsDebug byte in DMEM
21fd: ldd.b a9 a9
21ff: cmpbreq.b a9 0x0 0x220b  ; debug? branch to slot-43 (PROD) path
2203: cci 0xc002               ; DEBUG: falc_scp_secret(0,  R2)
2207: jmp 0x220f
220b: cci 0xc2b2               ; PROD:  falc_scp_secret(43, R2)   ← slot 43 = 0x2B
220f: cci 0xc402               ; falc_scp_key(R2)
2213: cci 0xd034               ; falc_scp_encrypt(R3, R4)  ← derivedKey = AES-ECB(salt, slot43)
2217: cci 0xa814               ; falc_scp_chmod(1, R4)     ← secure-keyable

221b-2223: load pDmHash into SCP_R3
2225: cci 0xc404               ; falc_scp_key(R4)
2229: cci 0xd032               ; falc_scp_encrypt(R3, R2)  ← signature = AES-ECB(dmhash, derivedKey)
222d-2233: read back to pDmHash
2235: cci 0x0                  ; falc_scp_trap(TC_DISABLE_CCR)
2238: clr.w a14                ; return ACR_OK
```

The opcode `cci 0xc2b2` decodes to `falc_scp_secret(0x2B, SCP_R2)`.
`0x2B = 43`. This matches the source constant
`ACR_LS_VERIF_KEY_INDEX_PROD_TU10X_AND_LATER` defined in
[acr.h:151](integ/gpu_drv/stage_rel/uproc/acr/inc/acr.h#L151).

### 3a.3 Corrected scheme

```
On GA100:
  dmHash       = AES-DM-hash(LS_ucode)           ← 128-bit Davies-Meyer
  derivedKey   = AES-ECB(g_kdfSalt XOR falconId, scpSecret[43])
  expectedSig  = AES-ECB(dmHash, derivedKey)
  ok = (expectedSig == storedSig)        ← stored in LSF v1 sig field

No RSA, no SHA-256, no PSS, no LS-encrypt (slot 31 unused).
```

### 3a.4 What this changes about prior findings

1. **Phase-2 §2.3 verdict is wrong as written.** The GA100 prod path is
   AES-DM signature, not RSA-PSS, and not AES-CBC decryption. SCP slot
   31 is **unused** on GA100. The actual sensitive secret is **SCP
   slot 43** (or slot 0 in debug builds). Extracting slot 43 would
   permit forging valid LS signatures for any falconId, but would not
   reveal any plaintext (LS ucodes ship in cleartext anyway —
   `bUcodeLsEncrypted == 0` is the universal case in this binary).

2. **The depMap OOB (Phase-2 §2.2) and pre-verify scribble (§2.4)
   findings are about v2-WPR-blob code path.** GA100 prod uses **v1
   WPR blobs** with TU10X parsing. The `_acrlibCheckDependency_v2`
   function I worried about is in the source but **not in the prod
   GA100 AHESASC binary** (no `_GA10X` symbols at all). Those
   vulnerability hypotheses do not apply to GA100; they apply only to
   GA10x and later chips that use the v2-blob path.

3. **The "RSA-3072 trust root" framing in `01_SECURE_BOOT_CHAIN.md` is
   only correct at the HS-signature level** (ROM verifies Booter,
   Booter verifies ACR/AHESASC via RSA). The **LS** signatures on
   GA100 are AES-DM, not RSA. That has implications: AES-DM with a
   public salt and one fixed SCP slot is much easier to defeat than
   RSA-PSS, if the slot key can be recovered via SCA/glitching on any
   GA100 silicon. The threat model for LS auth is therefore weaker
   on GA100 than the higher-level "all RSA-3K" narrative suggests.

### 3a.5 Practical adversary cost

| Goal | Cost |
|---|---|
| Forge an LS signature for any falconId | Recover SCP slot 43 once from any single GA100 silicon, then AES-ECB forge offline forever |
| Decrypt LS ucode | N/A — GA100 LS ships in plaintext |
| Bypass HS auth (ROM→Booter→ACR) | Break RSA-3K — out of scope for non-state actors |
| Substitute LS code without forging sig | Patch the AES-DM hash to match — requires a 128-bit collision (~$2^{64}$) work for AES-DM |

The vulnerability of LS auth on GA100 is therefore primarily an
**SCA/glitching-on-silicon** problem against SCP slot 43, not a
software bug. Anyone who recovers slot 43 (e.g. via the published
NVIDIA SCP fault-injection literature) defeats LS auth on every
GA100 ever shipped.

---

## 4. GSP-RM RISC-V image — first look

`g_gsp_ga100_riscv.image.bin` is 172 032 B (= 168 KB). The ELF metadata
in `.readelf` shows it loads to physical address `0x20068000` upward
(IMEM_PHYSICAL_BASE area). The exported `_start` symbol is at
`0x200681A0` — the LIBOS init entry. Sections show LIBOS-typical
layout:

```
__section_hsSwitchDmem_*    @ 0x20001000     ← HS<->LS switch trampoline area
__section_rmQueue_*         @ 0x20002000     ← RM RPC queue area
__section_kernelRodata_*    @ 0x20003400
__section_kernelData_*      @ 0x20004800
__section_dmemHeap_*        @ 0x20008000
__section_globalRodata_*    @ 0x2000B000
__section_freeableHeap_*    @ 0x2000D400 (size 0x40000)
__section_taskSharedDataFb_*       @ 0x2004E400 ← shared with FB (driver readable)
__section_taskSharedDataDmemRes_*  @ 0x2004FC00 ← shared via DMEM (driver readable)
```

The presence of explicit `taskSharedDataFb` and
`taskSharedDataDmemRes` sections is a confirmation of §3.2 from
Phase-2: GSP-RM exposes shared regions to the driver *by design*. The
concern from Phase-2 (open DMEM PLM) is about regions outside these
two: if the entire DMEM is open, the rest of the LIBOS state
(rmQueue, freeableHeap, kernel data) is also visible/writable.

Exception path:

```
exceptionInit              @ 0x20066788
nvrtosRiscvExceptionHook   @ 0x20066A00
__PortException            @ 0x20068354   (raw entry vector)
vPortHandleException       @ 0x20065570
vPortPanic                 @ 0x200685E8
```

No symbols matching `mspm`, `mrsp`, or `priv_level` in the GSP RISC-V
image — meaning **GSP-RM does not re-tighten the PLMs after Booter
hands off**. Whatever PLMs the Booter set are what GSP-RM runs under.
If the Booter set DMEM to `READ_L0_WRITE_L0` (Phase-2 §3.2), GSP-RM
stays that way until reset.

This is **circumstantial confirmation** of the Phase-2 §3.2 concern.
To make it definitive I would need to disassemble the Booter LOAD
binary; the Booter ELF/.nm/.objdump are not in this archive snapshot
(only the C arrays in the `_dbg.h` / `_prod.h` form).

---

## 5. Updated verdict table

| Finding | Phase-1 grade | Phase-2 verdict | Phase-3 binary verdict |
|---|---|---|---|
| #1 SMC instance | CRITICAL | Partially valid, reframe to HW bug | **Confirmed**: ASB binary inlines `inst<<21` with no bounds check, but `falconInstance` is never attacker-derived in any reachable path. Risk = software bug-in-NVIDIA-pipeline only |
| #2 DepMap OOB | CRITICAL | Latent — sig-covered | (n/a in binary — would need exploit POC) |
| #3 AES key | CRITICAL | Resolved (SCP slot 31, salt public) | (not in ASB/AHESASC visible symbols; presumably in `acrDecryptAesCbcBuffer_GA10X` not present in this ASB) |
| #4 Mem training unverified | HIGH | Invalid file path; lives in DEVINIT | **VBIOS BIT_DATA_FALCON_DATA carries DEVINIT** — Phase-4 extraction target |
| #5 LSF offset | HIGH | Real as pre-verify DMA scribble | (not exposed in ASB symbols; AHESASC objdump can show it) |
| #6 VREF unchecked | MEDIUM | Invalid for GA100 | Same — DEVINIT |
| #7 Int overflow | HIGH | Not exploitable | Confirmed: `i*2` over `NvU32` cannot wrap before bounds-violation crash |
| #8 Version rollback | MEDIUM | Latent | **Refuted**: anti-rollback is FPF fuse `0x824250`, *not* the `binVersion` field. Binary-confirmed |
| §3.1 ITCM gadget | **CRITICAL** | (new) | **DOWNGRADED to INFO**: gadget not in prod-signed ASB or AHESASC; `ACR_RISCV_LS` disabled for prod GA100 |
| §3.2 GSP DMEM PLM | **CRITICAL** | (new) | **Indirectly confirmed**: GSP RISC-V image has no PLM re-tightening symbols. Booter binary not disassembled in this snapshot — Phase-4 target |
| §3.3 GSP REGIONCFG | HIGH | (new) | Same — Booter-side, not visible in ACR binaries |
| §3.4 pre-verify scribble | MEDIUM | (new) | (in AHESASC, not yet RE'd at binary level) |
| GA100 DecodeTrap WAR | (new) | (new) | **Confirmed shipped** in AHESASC at 0x323a; protects LTC TSTG register |
| GA100 RowRemap WPR check | (new) | (new) | **Confirmed shipped** in AHESASC at 0x3468; HBM2e-aware WPR validator |
| Chip-lock GA100/GA101-only | (new) | (new) | **Confirmed shipped** in ASB at 0x22fc; GA101 requires debug mode |
| FPF anti-rollback fuse `0x824250` | (new) | (new) | **Confirmed shipped** in ASB at 0x264d |

---

## 6. Phase-4 priorities (revised, based on binary evidence)

1. **Disassemble the Booter LOAD binary**
   (`gsprm/bin/booter/ga100/load/g_booteruc_load_ga100_prod.h`) — it
   contains the actual GSP DMEM PLM write and the REGIONCFG `#if 0`.
   Without the disassembly we cannot confirm §3.2 / §3.3 at the
   binary level. The .h file is a signed/encrypted C array; will need
   to extract the embedded sections from the `.out` ELF if present
   elsewhere in the snapshot, or unpack the array and parse the
   Falcon container format.
2. **Extract VBIOS DEVINIT / PMU ucode** from BIT_DATA_FALCON_DATA at
   file offset `0x60D9`. The 4-byte pointer there leads into the
   Falcon catalogue, which contains the HBM2e training routine — the
   *actual* target for Phase-1 #4/#6.
3. **Disassemble `_acrSetupLSFalcon_TU10X` at ASB 0x1E81 (436 B)** to
   confirm the LSF-offset trust boundary (Phase-1 #5 / Phase-2 §2.4).
   Look for whether `ucodeOffset` is re-validated after signature
   verify before being used as DMA source.
4. **RE the AES key derivation path in AHESASC** — find
   `acrDecryptAesCbcBuffer_GA10X` /
   `acrGetDerivedKeyAndLoadScpTrace0_GA10X` in the AHESASC objdump and
   confirm the SCP slot 31 reference and the salt at `0xB6C231E9
   03B277D7 0E32A069 8F4E8062` is exactly the bytes embedded in the
   prod binary.
5. **Disassemble PMU ACR Unload binary**
   (`pmu/ga100/g_acruc_ga100_unload.{nm,objdump}` is present). Look
   for whether unload re-tightens or releases PLMs. Unload runs at
   GPU teardown; if PLMs are left wide-open at unload, the next driver
   load may inherit them.
6. **VBIOS image #2 disassembly** — there's a second
   PCI-Expansion-ROM image at file offset `0xC700`. Identify whether
   it's the EFI ROM or another firmware container.

---

## 7. Things I now know with high confidence

These are statements I can defend against any source-vs-binary
challenge:

1. The prod-signed GA100 ASB Falcon HS image is **10 752 bytes** of
   HS code, contains **118 symbols**, has **no RISC-V support**, and
   chip-locks itself to PMC_BOOT_42.CHIP_ID `0x170` or `0x171` (debug
   only). It performs FPF-fuse-based anti-rollback against fuse
   `0x824250`. It bootstraps PMU, DPU, FECS, GPCCS, NVDEC, and SEC2 —
   no GPCCS+RISC-V hybrid, no GSP-via-bootstub.
2. The prod-signed GA100 AHESASC Falcon HS image contains all four
   GA100-specific WAR functions including the HBM2e-row-remap WPR
   placement validator and the LTC TSTG decode-trap isolator.
3. The CMP 170HX VBIOS is a standard NV multi-image ROM with two
   PCI-ROM subimages duplicated for recovery, a BIT table with 16
   entries, and a `BIT_DATA_FALCON_DATA` pointer (token 'p' = 0x70)
   to the embedded Falcon ucode catalogue at file offset `0x60D9`.
4. The Phase-2 §3.1 ITCM-bootstub gadget hypothesis was based on a
   source file (`acr_riscv_ls_ga100.c`) gated by `#ifdef ACR_RISCV_LS`
   that is not defined in the prod build. The gadget does not exist
   in shipped silicon.
5. The Phase-1 #8 "version rollback via binVersion" hypothesis is
   wrong. Anti-rollback is enforced via the monotone FPF fuse at
   `0x824250`, not via any LSF metadata field. Defeating it requires
   either a chip with fewer fuse bits burned (silicon-class restricted)
   or breaking the HS-sign chain.

---

**Last updated**: 2026-05-17 — Phase-3 binary RE complete.
**Confidence**: Source citations + binary disassembly cross-validated.
**Carries forward**: Booter binary disassembly (§3.2/§3.3 confirmation)
and VBIOS DEVINIT extraction (Phase-1 #4/#6 retargeting).
