# 1.1 — Asset Inventory and Audit Status

**Scope**: NVIDIA Ampere GA100 (chip ID `0x170`); products A100, A30, CMP 170HX (DevID `0x20C2`).
**Archive root**: `workspace/`
**Source tree root**: `integ/gpu_drv/stage_rel/` (abbreviated `<src>` below)
**Binary artifact root**: `<src>/drivers/resman/kernel/inc/`
**Last updated**: 2026-05-17 — reflects Phase-3 binary RE completion.

---

## 1. Trust Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│  BROM (ROM — not in archive)                                │
│  RISC-V, fuse-locked keys, verifies Booter via RSA-3K       │
└──────────────────┬──────────────────────────────────────────┘
                   │ RSA-3072 verify
    ┌──────────────▼──────────────────────────────────────┐
    │  Booter LOAD  (Falcon HS, runs in Falcon HS mode)   │
    │  • Establishes WPR1/WPR2 in FB                      │
    │  • Sets DMEM PLMs for GSP-RM ← CRITICAL GAP        │
    │  • Loads + launches GSP-RM RISC-V image             │
    │  Binary: g_booteruc_load_ga100_prod.h               │
    │  (8 832 32-bit words = 35 328 B raw; active 24 320 B)│
    └──────┬──────────────────────┬───────────────────────┘
           │ RSA-3K verifies      │ RSA-3K verifies
    ┌──────▼────────┐    ┌────────▼──────────────────────┐
    │  ASB (HS)     │    │  AHESASC (HS)                 │
    │  on GSP-lite  │    │  on SEC2 Falcon               │
    │  10 752 B code│    │  ~26 KB code                  │
    │  118 symbols  │    │  129 symbols                  │
    │               │    │  • AES-DM LS sig verify       │
    │ Launches:     │    │  • WPR placement validator    │
    │  PMU, DPU,    │    │  • HBM2e row-remap checks     │
    │  FECS, GPCCS, │    │  • LTC TSTG decode-trap setup │
    │  NVDEC, SEC2  │    │                               │
    └──────┬────────┘    └───────────────────────────────┘
           │ AES-DM verify (SCP slot 43)
    ┌──────▼──────────────────────────────────────────────┐
    │  LS Falcons (Low Secure, plaintext ucodes)          │
    │  PMU · DPU · FECS · GPCCS · NVDEC · SEC2           │
    └─────────────────────────────────────────────────────┘
           │  (alongside, not in Falcon chain)
    ┌──────▼──────────────────────────────────────────────┐
    │  GSP-RM  (RISC-V, 172 032 B = 168 KB)              │
    │  Runs in WPR2 at 0x20068000+                        │
    │  Authenticated by Booter (RSA-3K on image container)│
    │  PLM set by Booter — GSP-RM does not retighten      │
    └─────────────────────────────────────────────────────┘
```

Authentication summary:
- **HS chain**: ROM → RSA-3K → Booter → RSA-3K → ASB + AHESASC
- **LS chain**: AHESASC → AES-DM (SCP slot 43, 128-bit Davies-Meyer hash)
- **GSP-RM**: Booter RSA-3K on the RISC-V container; PLMs fixed at Booter runtime

---

## 2. Binary Artifacts — Prod-Signed (Disassembly Available)

All paths relative to `<src>/drivers/resman/kernel/inc/`.

### 2.1 ACR — ASB (Falcon HS, runs on GSP-lite)

| Variant | Directory | `.h` bytes | Symbols | RE status |
|---|---|---|---|---|
| **prod** | `acr/bin/gsp/ga100/asb/` | 43 299 B | 118 (readelf) / 104 (nm) | **Phase-3 complete** |
| fmodel | same | 40 086 B | — | not analyzed |

Key artifacts in prod ASB dir:

| File | Purpose |
|---|---|
| `g_acruc_ga100_asb.nm` | Symbol table — 104 entries (exported/global); 118 total per readelf |
| `g_acruc_ga100_asb.objdump` | Full disassembly (169 KB) |
| `g_acruc_ga100_asb.readelf` | Section layout / ELF headers |
| `g_acruc_ga100_asb_prod.out` | Prod signed container (268 KB with HS wrapper) |
| `g_acruc_ga100_asb_ga100_rsa3k_0_sig.h` | RSA-3K signature slot 0 |
| `g_acruc_ga100_asb_ga100_rsa3k_1_sig.h` | RSA-3K signature slot 1 |
| `g_acruc_ga100_asb_gp104_sig.h` | Legacy AES sig (GP104-era, not used on GA100) |
| `g_acruc_ga100_asb_tu116_aes_sig.h` | TU116-era AES sig |

Section layout (from Phase-3):
```
.text                  @ 0x00000000  0x0BE B  (non-HS bootstrap)
.text.__canary_setup   @ 0x000000BE  0x00C B
.imem_acr (HS code)    @ 0x00000100  0x2900 B  = 10 752 B  (LOAD → 0x20000000)
.data                  @ 0x10000000  0x918 B
.bss                   @ 0x10000920  0x018 B
```

### 2.2 ACR — AHESASC (Falcon HS, runs on SEC2) — Standard

| Variant | Directory | `.h` bytes | Symbols | RE status |
|---|---|---|---|---|
| **prod** | `acr/bin/sec2/ga100/ahesasc/` | 64 319 B | 129 (nm) | **Phase-3 partial** |
| fmodel | same | 57 068 B | — | not analyzed |

Key GA100-specific symbols confirmed present (Phase-3 §2):
- `0x323a` `_acrProgramDecodeTrapToIsolateTSTGRegisterToFECSWARBug2823165_GA100` — **confirmed shipped**
- `0x328f` `_acrGetUsableFbSizeInMB_GA100` — **confirmed shipped**
- `0x339b` `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100` — **confirmed shipped**
- `0x3468` `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` — **confirmed shipped**

Crypto path: AES-DM (SCP slot 43, Turing-era TU10X code path — **not** GA10x RSA-3K/AES-CBC path).

### 2.3 ACR — AHESASC APM Variant (SEC2, Ampere Protected Memory)

| Variant | Directory | `.h` bytes | Symbols | RE status |
|---|---|---|---|---|
| prod | `acr/bin/sec2/ga100/ahesasc_apm/` | 92 611 B | ~160 (nm) | **Phase-4 complete** — see `7-4-phase4-ahesasc-apm.md` |

APM variant (+5,632 B vs baseline): adds SHA-256 MSR chain, CC attestation, 26 additional symbols. SKU-gated to DevID 0x20B5 (A100 SXM4 80GB only). CC enable bit is a scratch register (W-4), not OTP fuse. MSR falconID hardcoded to SEC2 for all groups (W-5/Finding P3-1). Compound APM_RTS overwrite path via W-1+W-2 (Finding P3-2).

### 2.4 ACR — AHESASC GSP-RM Variant (SEC2)

| Variant | Directory | `.h` bytes | Symbols | RE status |
|---|---|---|---|---|
| prod | `acr/bin/sec2/ga100/ahesasc_gsp_rm/` | 74 844 B | ~140 (nm) | not analyzed (open gap from `6-1-crypto-auth-chain-map.md §12`) |

Parallel AHESASC build used in GSP-RM (MIG) context. Distinct from standard AHESASC. Open gap: check for MIG isolation differences in WPR placement and LS sig verification.

### 2.5 ACR — Unload (Falcon HS, runs on PMU)

| Variant | Directory | `.h` bytes | Symbols | RE status |
|---|---|---|---|---|
| prod | `acr/bin/pmu/ga100/` | 34 418 B | 89 (nm) | **Phase-5a complete** — see `5-5-vuln-plm-unload.md` |

PLM behavior confirmed: PMU DMEM PLM resets to 0xFF (hardware default) at unload (`SCTL_RESET_LVLM_EN=TRUE`). No vulnerability — PMU is halted and WPR still locked during the teardown window. SEC2 PLM remains 0x88 throughout (SEC2 cannot self-reset). No new W-level finding from teardown analysis.

### 2.6 ACR — Unload Variants (SEC2)

Two SEC2-side unload binaries:

| Binary | Directory | `.h` bytes | RE status |
|---|---|---|---|
| `g_acruc_ga100_unload` | `acr/bin/sec2/ga100/unload/` | 43 308 B | **Phase-5a complete** — see `5-5-vuln-plm-unload.md` |
| `g_acruc_ga100_unload_gsp_rm` | same | 43 329 B | not analyzed (open gap) |

SEC2 Unload runs as bootstrap owner; skips SEC2 self-reset (correct). WPR unlock sequence confirmed: all sub-WPRs disabled, WPR1 ALLOW_READ/WRITE → 0x0. SEC2 DMEM PLM stays at 0x88. No new W-level finding. SEC2 Unload GSP-RM variant not analyzed.

### 2.7 GSP-RM — RISC-V Image

| File | Size | RE status |
|---|---|---|
| `gsp/bin/g_gsp_ga100_riscv_image.bin` | 172 032 B (168 KB) | **Phase-3 symbol survey only** |
| `gsp/bin/g_gsp_ga100_riscv.elf` | — | available |
| `gsp/bin/g_gsp_ga100_riscv.nm` | — | available |
| `gsp/bin/g_gsp_ga100_riscv_sign.bin` | — | RSA-3K container sig |
| `gsp/bin/g_gsp_ga100_riscv_desc.bin` | — | RISC-V descriptor |

Entry: `_start` @ `0x200681A0` (LIBOS init).
Security-relevant sections:
```
__section_hsSwitchDmem_*    @ 0x20001000   ← HS↔LS trampoline
__section_rmQueue_*         @ 0x20002000   ← RM RPC queue (driver-readable by design)
__section_taskSharedDataFb_*       @ 0x2004E400  ← FB-shared region
__section_taskSharedDataDmemRes_*  @ 0x2004FC00  ← DMEM-shared region
__section_freeableHeap_*    @ 0x2000D400   0x40000 B  ← concern: PLM covers this?
```
No PLM re-tightening symbols found → GSP-RM inherits whatever PLM Booter sets.

---

## 3. Binary Artifacts — Booter (C-Array Only, No Disassembly)

All paths: `<src>/drivers/resman/kernel/inc/gsprm/bin/booter/ga100/`

| Role | File | Encoded bytes | RE status |
|---|---|---|---|
| **LOAD** | `load/g_booteruc_load_ga100_prod.h` | **8 832 32-bit words = 35 328 B raw** (active 24 320 B) | **Phase-4 complete** — see `7-3-phase4-booter-analysis.md` |
| RELOAD | `reload/g_booteruc_reload_ga100_prod.h` | 2 368 B | not analyzed |
| UNLOAD | `unload/g_booteruc_unload_ga100_prod.h` | 2 176 B | not analyzed |

Signature files present for each (RSA-3K slot 1: `_ga100_rsa3k_1_sig.h`).  
Debug variants present (`_dbg.h`).

**Extraction approach**: The `.h` files are C byte-array initialisers. Parse the hex literals, write raw binary, parse the Falcon container header to locate `.text`/`.data` sections, then disassemble via Falcon ISA decoder. The LOAD binary is the most critical: it contains the DMEM PLM writes for WPR2/GSP-RM and the `#if 0`-guarded REGIONCFG table referenced in Phase-2 §3.3.

---

## 4. VBIOS Dumps

| File | Size | DevID | BIOS Date | RE status |
|---|---|---|---|---|
| `<GPU ROM archive>` | 1 044 480 B (0xFF000) | `0x20C2` CMP 170HX | 2021-05-12 | **Phase-3 BIT table mapped** |
| `<GPU ROM archive>` | 1 044 480 B (0xFF000) | `0x20B0` A100 | 2020-02-13 | cross-reference complete |

### ROM Structure (both files)

```
0x000000     IFR-1 (NVGIR + sub-tables)
0x005E00 *   PCI ROM Image #1 (CMP) / 0x5000 (A100)
  +0x70      PCIR: DevID, imgLen
  +0x90      NPDE header
  +0xB0      BIT table (16 entries)
0x00C700 *   PCI ROM Image #2 (CMP) / 0xB500 (A100) — firmware container
0x05E000     padding (0xFF erased flash)
0x060000     IFR-2 (byte-identical copy of IFR-1)
0x065E00 *   Recovery copy of Image #1
0x06C700 *   Recovery copy of Image #2
0x0C0000     padding
0x0FF000     EOF
```

### BIT Table — 16 Entries (token layout identical between CMP and A100)

| Token | Meaning | CMP size | Status |
|---|---|---|---|
| `0x32` | Version anchor | 4 B | — |
| `'B'` | BIT_DATA_BIOSDATA | 37 B | — |
| `'C'` | BIT_DATA_CLOCK | 44 B (CMP +16 vs A100) | — |
| `'D'` | BIT_DATA_DAC | 4 B | — |
| `'I'` | BIT_DATA_INTERNAL | 36 B | — |
| `'M'` | BIT_DATA_MEMORY | 41 B | — |
| `'N'` | (empty) | 0 B | — |
| `'P'` | BIT_DATA_PERF | 232 B (CMP +36 vs A100) | mining-lock tweaks |
| `'T'` | BIT_DATA_TMDS_INFO | 2 B | — |
| `'U'` | BIT_DATA_USERDEF | 5 B | — |
| `'V'` | BIT_DATA_VIRTUAL_STRAP | 6 B | — |
| `'x'` | BIT_DATA_XMEMCFG | 8 B | — |
| `'d'` | BIT_DATA_DCB | 2 B | — |
| **`'p'`** | **BIT_DATA_FALCON_DATA** | 4 B ptr | **Phase-4 extraction target** |
| **`'u'`** | **BIT_DATA_UNIFIED_BOOT** | 13 B | — |
| **`'i'`** | **BIT_DATA_NV_INIT_PTRS_TBL** | 110 B (CMP) | DEVINIT ptr + date stamp |

Falcon catalogue pointer (token `'p'`):
- CMP: `image_base + 0x6354` = file `0x60D9` → ptr value `0x6354`
- A100: `image_base + 0x5F44` = file `0x52A5` → ptr value `0x5F44`
- Both point **into Image #2** — Image #2 is the firmware container (DEVINIT, PMU ucode, HBM2e training).

---

## 5. Source Code — Security-Critical Components

All paths relative to `<src>/uproc/`.

### 5.1 ACR — Falcon (HS)

| File | Scope | Security relevance |
|---|---|---|
| `acr/src/asb/ampere/acr_ls_falcon_boot_ga100.c` | GA100-only | LS falcon boot, chip-specific register bases |
| `acr/src/asb/ampere/acr_ls_falcon_boot_ga10x.c` | GA10x | LS falcon boot, generic ampere |
| `acr/src/asb/ampere/acr_riscv_ls_ga100.c` | GA100 | **Gated `#ifdef ACR_RISCV_LS`; NOT in prod** — ITCM gadget source |
| `acr/src/asb/turing/acr_ls_falcon_boot_tu10xga100.c` | TU10X+GA100 | Shared LS boot path actually used in prod |
| `acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga10x.c` | GA10x+ **only** | AES-CBC path — **NOT in GA100 prod** |
| `acr/src/ahesasc/ampere/acr_signature_manager_ga10x.c` | GA10x+ **only** | RSA-3K LS path — **NOT in GA100 prod** |
| `acr/src/ahesasc/ampere/acr_sub_wpr_ga10x.c` | GA10x | sub-WPR layout |
| `acr/src/ahesasc/ampere/acr_verify_ls_signature_ga10x.c` | GA10x | v2-blob OOB source — **NOT in GA100 prod** |
| `acr/src/ahesasc/turing/acr_verify_ls_signature_tu10x.c` | TU10X | **GA100 prod crypto path** — AES-DM SCP slot 43 |
| `acr/src/acrshared/ampere/acr_sanity_checks_ga100.c` | GA100 | Chip-lock + FPF anti-rollback (confirmed Phase-3) |
| `acr/src/acrshared/ampere/acr_sanity_checks_ga100_and_later.c` | GA100+ | FPF fuse check for fuse `0x824250` |
| `acr/src/acrshared/ampere/acr_war_functions_ga100_only.c` | GA100 | HBM2e WARs + decode-trap WAR |
| `acr/src/acrshared/ampere/acr_war_functions_ga100_and_later.c` | GA100+ | Shared Ampere WARs |
| `acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c` | GA10x | WPR lock/unlock control |
| `acr/src/acrsec2shared/ampere/acr_dma_ga100.c` | GA100 | DMA helper functions |
| `acr/src/acrsec2shared/ampere/acr_register_access_ga100.c` | GA100 | BAR0 register access primitives |
| `acr/src/apm/ampere/acr_apm_checks_ga100.c` | GA100 | APM measurement path |
| `acr/src/apm/ampere/acr_measurements_ga100.c` | GA100 | APM measurement collection |
| `acr/src/unload/ampere/acr_unload_ga10x.c` | GA10x | ACR teardown path |
| `acr/inc/ampere/acr_lsverif_keys_rsa3k_prod_ga10x.h` | GA10x | RSA-3K public key (GA10x+ only) |

### 5.2 Booter (Falcon HS)

| File | Scope | Security relevance |
|---|---|---|
| `booter/src/load/turing/booter_boot_gsprm_tu10x_ga100.c` | TU10X+GA100 | **Primary GA100 GSP-RM boot** — PLM writes here |
| `booter/src/load/ampere/booter_boot_gsprm_ga10x.c` | GA10x | GSP-RM boot (GA10x variant) |
| `booter/src/load/ampere/booter_bootvec_ga10x.c` | GA10x | Boot vector setup |
| `booter/src/load/ampere/booter_sig_verif_ga10x.c` | GA10x | HS signature verification |
| `booter/src/load/turing/booter_wpr1_tu10x.c` | TU10X | WPR1 (VBIOS blob) management |
| `booter/src/load/turing/booter_wpr2_tu10x.c` | TU10X | **WPR2 (GSP-RM) management** — range + PLM |
| `booter/src/load/turing/booter_sub_wpr_tu10x.c` | TU10X | Sub-WPR (per-engine) ranges |
| `booter/src/load/turing/booter_wpr_ctrl_tu10x.c` | TU10X | WPR lock/unlock controller |
| `booter/src/load/turing/booter_sig_verif_tu10x.c` | TU10X | HS image RSA verify |
| `booter/src/common/ampere/booter_sanity_checks_ga100.c` | GA100 | Chip-lock + product-family checks |
| `booter/src/common/ampere/booter_sanity_checks_ga100_and_later.c` | GA100+ | FPF fuse anti-rollback |
| `booter/src/common/ampere/booter_war_functions_ga100_only.c` | GA100 | HBM2e row-remap WPR placement |
| `booter/src/unload/ampere/booter_unload_ga10x.c` | GA10x | Booter teardown |
| `booter/src/reload/turing/booter_reload_tu10x.c` | TU10X | Booter reload path |

### 5.3 SEC2 (Falcon LS, host for AHESASC)

| File | Scope | Security relevance |
|---|---|---|
| `sec2/src/sec2/ampere/sec2ga100.c` | GA100 | SEC2 init, command dispatch |
| `sec2/src/sec2/ampere/sec2ga100only.c` | GA100 only | GA100-specific SEC2 hooks |
| `sec2/src/acr/ampere/sec2_acrga100.c` | GA100 | SEC2 ACR interface |
| `sec2/src/apm/ampere/sec2_apmga100.c` | GA100 | APM RTM path |
| `sec2/src/apm/ampere/sec2_apmrtmga100.c` | GA100 | APM run-time measurement |
| `sec2/src/lsr/ampere/lsrga100.c` | GA100 | Liquid Cooled SKU register path |
| `sec2/src/spdm/ampere/sec2_spdmga100.c` | GA100 | SPDM attestation path |
| `sec2/src/vpr/ampere/sec2_vprga100.c` | GA100 | VPR (Video Protected Region) |
| `sec2/src/pr/ampere/sec2_prga10x.c` | GA10x | Protected Region management |
| `sec2/src/pr/ampere/sec2_prmpkandcertga10x.c` | GA10x | MPK/cert provisioning |
| `sec2/src/ic/ampere/sec2_icga100.c` | GA100 | IC (Integrity Check) engine |

### 5.4 FBFalcon (Memory Controller Falcon)

| File | Security relevance |
|---|---|
| `fbflcn/src/fbflcn_gddr_boot_time_training_ga10x.c` | Boot-time DRAM training (GDDR — not HBM2e) |
| `fbflcn/src/fbflcn_gddr_mclk_switch_ga10x.c` | Memory clock switching |
| `fbflcn/src/memory/ampere/memory_ga100.c` | HBM2e-specific memory controller |
| `fbflcn/src/fbfalcon/ampere/fbfalcon_ga10x.c` | FBFalcon init |
| `fbflcn/src/fbfalcon/ampere/interrupts_ga100.c` | Interrupt handler registration |

### 5.5 GSP Manifests (RISC-V)

| File | Relevance |
|---|---|
| `gsp/fmc/manifests/manifest_gsp_ga10x.c` | GSP-RM RISC-V manifest (partition layout, privilege decl) |
| `nvriscv/sepkern_spark/manifests/manifest_gsp_ga10x.c` | SepKern variant manifest |
| `nvriscv/sepkern_spark/manifests/manifest_gsp_ga10x_gsprm_unsigned.c` | Unsigned GSP-RM manifest (dev only) |
| `nvriscv/sepkern_spark/manifests/manifest_pmu_ga10x.c` | PMU RISC-V manifest |

### 5.6 DPU (Display Falcon)

| File | Relevance |
|---|---|
| `disp/dpu/src/dpu/ampere/dispflcnga10x.c` | DPU init |
| `disp/dpu/src/lsf/ampere/dpu_lsfga10x.c` | LSF ucode descriptor for DPU |

### 5.7 SecureScrub

| File | Relevance |
|---|---|
| `securescrub/src/securescrub/ampere/securescrubga10x.c` | GPU memory scrubbing at init/teardown — privilege boundary |

---

## 6. Analysis Document Index

| Document | Phase | Status | Key result |
|---|---|---|---|
| `2-1-secure-boot-chain.md` | 1 | Superseded by Phase-3 | HS chain is RSA-3K; LS chain is AES-DM not RSA |
| `2-2-firmware-wpr-lsf.md` | 1 | Partially valid | LSF offset trust issue stands; WPR blob is v1 on GA100 |
| `2-3-firmware-parsing-vulns.md` | 1 | Partially valid | depMap OOB is GA10x+, not GA100 prod |
| `4-1-isolation-smc-mig.md` | 1 | Valid | Instance stride math confirmed (no bounds check) |
| `4-2-isolation-fecs-dma.md` | 1 | Valid | FECS DMA arbiter unchecked stride confirmed in binary |
| `3-1-falcon-privilege-boundaries.md` | 1 | Valid (corrected ISA description) | PLM/DMEM concerns confirmed by Phase-4 Booter binary analysis |
| `4-3-runtime-ipc-interfaces.md` | 1 | Valid | RPC queue shared region confirmed in GSP ELF |
| `5-1-vuln-memory-training.md` | 1 | Superseded / retargeted | GA100 uses HBM2e (DEVINIT/HULK), NOT GDDR6; doc reframed with correction block |
| `4-4-runtime-post-verification.md` | 1 | Valid | pre-verify DMA scribble confirmed as W-6; see `5-4-vuln-dma-scribble.md` |
| `4-5-runtime-errata-workarounds.md` | 1 | Valid | All four GA100 WARs confirmed shipped in AHESASC |
| `5-3-vuln-exploit-chains.md` | 1 | Partially valid | Downgrade ITCM gadget; SCP slot 43 is new pivot; W-6 adds pre-verify scribble primitive |
| `1-2-reverse-engineering-methodology.md` | 1 | Superseded (path/filename corrections applied) | Replaced by Phase-3 binary evidence; training target corrected to HBM2e/DEVINIT |
| `7-1-phase2-validation-findings.md` | 2 | Partially superseded (slot/path corrections applied) | Phase-3 corrects AES scheme (slot 43, not 31) and downgrades ITCM; Windows paths fixed |
| `7-2-phase3-binary-analysis.md` | 3 | Valid (path corrections applied) | Binary-confirmed findings; Phase-4 priorities; Windows paths fixed |
| `2-4-rom-structural-analysis.md` | 3 | Valid | ROM layout binary-confirmed; BIT table, FALCON_DATA_V2, both ROMs |
| `7-3-phase4-booter-analysis.md` | 4 | **Current** | DMEM PLM=0xFF (W-1), REGIONCFG disabled (W-2), TU10X path confirmed |
| `2-6-vbios-ucode-catalog.md` | 4 | **Current** | Full FALCON_DATA_V2 catalog; HULK/FWSEC/LS_UDE offsets; TargetID 5/7 undocumented |
| `7-4-phase4-ahesasc-apm.md` | 4 | **Current** | APM variant analyzed; W-4 (CC scratch not fuse), W-5 (MSR falconID hardcoded), P3-2 (APM_RTS compound) |
| `2-5-host-firmware-parser.md` | 4 | **Current** | P4-1 (MEDIUM: heap alloc no upper bound), P4-2 (LOW: silent NULL) |
| `2-5-host-firmware-parser.md` | 4 | **Current** | Exhaustive bounds audit; 12 safe bounds, 3 absent hardware-limit checks; proposed fixes |
| `6-1-crypto-auth-chain-map.md` | 4 | **Current** | End-to-end trust map; all 7 layers; W-1 through W-5 consolidated |
| `6-2-verification-state-machine.md` | 4 | **Current** | Complete source trace of every check in boot chain; RSA-3K PSS disassembly |
| `6-3-wpr-hardware-lockdown.md` | 4 | **Current** | Register-level WPR lock sequence; PLM table; PPRIV_SYS decode trap; REGIONCFG dead code |
| `5-4-vuln-dma-scribble.md` | 5 | **Current** | W-6 confirmed: cross-falcon WPR scribble via driver-controlled blDataOffset |
| `5-5-vuln-plm-unload.md` | 5 | **Current** | P5a resolved: no new W-level finding; PMU resets to 0xFF (intentional); SEC2 stays 0x88 |
| `DISCLOSURE_SUMMARY_AND_NEXT_STEPS.md` | meta | Active | PSIRT disclosure plan |
| `NVIDIA_PSIRT_DISCLOSURE_DRAFT.md` | meta | Active | Draft disclosure |
| `TESTING_VALIDATION_FRAMEWORK.md` | meta | Active | Validation methodology |

---

## 7. Key Hardware Constants and Register Map

### Anti-rollback and Chip Identity

| Register | Address | Function |
|---|---|---|
| `NV_PMC_BOOT_42` | `0x00000A00` | Chip ID field (bits [24:5] = CHIP_ID) |
| `NV_FUSE_OPT_FPF_UCODE_ACR_HS_REV` | `0x00824250` | Monotone anti-rollback fuse (low 8 bits, popcount = revision) |

### FECS / GPCCS DMA Arbiter

| Register | Address | Function |
|---|---|---|
| `NV_PGRAPH_PRI_FECS_ARB_CMD_OVERRIDE` | `0x01009A20` | FECS DMA arbiter command — base for instance stride |
| `NV_GPC_PRI_STRIDE` | `0x200000` (= 1<<21) | FECS instance stride (<<21 per instance, no bounds check) |
| `NV_GPCCS_STRIDE` | `0x008000` (= 1<<15) | GPCCS instance stride per TPC |

### LTC Decode Trap (Bug 2823165 WAR)

| Register | Address | Function |
|---|---|---|
| `NV_PPRIV_SYS_PRI_DECODE_TRAP21_MATCH` | `0x00122454` | Trap match value (FECS SOURCE_ID=4, addr=0x140098) |
| `NV_PPRIV_SYS_PRI_DECODE_TRAP21_MATCH_CFG` | `0x001226D4` | ALL_LEVELS \| INVERT_SOURCE_ID \| IGNORE_READ |
| `NV_PPRIV_SYS_PRI_DECODE_TRAP21_MASK` | `0x001224D4` | Source+addr mask |
| `NV_PPRIV_SYS_PRI_DECODE_TRAP21_ACTION` | `0x00122654` | FORCE_ERROR_RETURN (0x8) |

### Sub-WPR / Falcon Register Bases (from AHESASC dispatch table)

| Falcon | subWprRangeAddrBase | subWprRangePlmAddr | registerBase |
|---|---|---|---|
| PMU (id=0) | `0x010A000` | `0x010AE00` | `0x1F9000`-area |
| DPU (id=1) | — | — | — |
| FECS (id=2) | priv-loaded | priv-loaded | `0x1009000 + (inst<<21)` |
| GPCCS (id=3) | priv-loaded | priv-loaded | `0x502000 + (inst<<15) + 0xA34` |
| NVDEC (id=4) | — | — | — |
| SEC2 (id=7) | `0x848000`-area | `+0x600` | `0x840000`-area |

### AES-DM Key Derivation (SCP slot 43, confirmed Phase-3)

```
g_kdfSalt @ DMEM 0x800:  B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62
SCP secret slot (prod):  0x2B = 43  (ACR_LS_VERIF_KEY_INDEX_PROD_TU10X_AND_LATER)
SCP secret slot (debug): 0x00 = 0

Scheme:
  dmHash     = AES-DM-hash(LS_ucode_payload)
  derivedKey = AES-ECB(g_kdfSalt XOR falconId, scpSecret[43])
  storedSig  = AES-ECB(dmHash, derivedKey)
  verify: compute == stored
```

---

## 8. Audit Status Matrix

| Component | Source analyzed | Binary disassembled | Finding grade | Status |
|---|---|---|---|---|
| ASB (GSP-lite) | Yes | **Yes (Phase-3)** | chip-lock + anti-rollback confirmed | **Complete** |
| AHESASC standard | Yes | **Yes (Phase-3/4)** | W-1 through W-6 confirmed; pre-verify scribble W-6 confirmed | **Complete** |
| AHESASC APM | Yes | **Yes (Phase-4)** | W-4 (CC scratch), W-5 (MSR hardcoded), P3-2 (APM_RTS) | **Complete** |
| AHESASC GSP-RM | No | **No** | Unknown | Open gap |
| ACR Unload (PMU) | Yes | **Yes (Phase-5a)** | PMU PLM resets to 0xFF on teardown; no new W-finding | **Complete** |
| ACR Unload (SEC2) | Yes | **Yes (Phase-5a)** | SEC2 PLM stays 0x88; no new W-finding | **Complete** |
| Booter LOAD | Yes | **Yes (Phase-4)** | W-1 (DMEM PLM=0xFF) + W-2 (REGIONCFG #if 0) binary-confirmed | **Complete** |
| Booter RELOAD | No | **No** | PLM behavior on GC6 resume unknown | Open gap |
| Booter UNLOAD | No | **No** | PLM release at GPU teardown unknown | Open gap |
| GSP-RM RISC-V | Partial | **Symbol survey only** | No PLM retighten confirmed (inherits W-1/W-2) | Open gap |
| VBIOS Image #1 | BIT table mapped | Struct mapped | DEVINIT ptr located | **Complete** |
| VBIOS Image #2 | **Yes (Phase-4)** | Struct mapped | FALCON_DATA_V2 catalog complete; HULK/FWSEC/LS_UDE offsets | **Complete** |
| SEC2 firmware | Source only | **No** | SPDM, APM, VPR paths | Open gap |
| FBFalcon | No | **No** | HBM2e training = VBIOS DEVINIT + HULK (not standalone FBFalcon ucode) | Open gap |
| Host parser (kernel_gsp_fwsec.c) | **Yes (Phase-4)** | N/A | P4-1 (MEDIUM heap alloc), P4-2 (LOW silent NULL), 3 absent hardware-limit checks | **Complete** |

## 9. Confirmed Weaknesses (W-level findings)

| ID | Name | Severity | Source | Document |
|---|---|---|---|---|
| **W-1** | GSP DMEM PLM = READ_L0_WRITE_L0 | **CRITICAL** | Booter binary+0x5498 = 0xFF; TODO comment confirms intentional | `7-3-phase4-booter-analysis.md` |
| **W-2** | REGIONCFG disabled (`#if 0`) | **CRITICAL** | Needle absent from Booter binary; `#if 0` + SACC comment in source | `7-3-phase4-booter-analysis.md` |
| **W-3** | SCP slot 43 shared across all GA100 dies | HIGH | Single root-of-trust; `cci 0xc2b2` binary-confirmed | `7-2-phase3-binary-analysis.md §3a` |
| **W-4** | CC attestation mode in scratch register (not OTP) | MEDIUM | `NV_PGC6_AON_SECURE_SCRATCH_GROUP_20_CC`; A100 SXM4 only | `7-4-phase4-ahesasc-apm.md` |
| **W-5** | APM MSR falconID hardcoded to SEC2 | LOW | Source comment "needs to be replaced with current falcon" | `7-4-phase4-ahesasc-apm.md` |
| **W-6** | Pre-verify DMA scribble (blDataOffset unvalidated) | MEDIUM | `acr_verify_ls_signature_tu10x.c:859`; ring-0 pre-condition | `5-4-vuln-dma-scribble.md` |

---

*Confidence*: All W-level findings binary-validated against prod-signed artifacts. Phases 1–5 complete. Remaining open gaps listed above.*
