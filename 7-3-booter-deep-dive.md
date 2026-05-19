# 7.3 — Booter Load Deep Dive

**Date:** 2026-05-17  
**Status:** COMPLETE  
**Priority:** P1 (highest) — resolves critical open gap on GSP DMEM PLM configuration

---

## 1. Binary Extraction and Structure

### Source

`drivers/resman/kernel/inc/gsprm/bin/booter/ga100/load/g_booteruc_load_ga100_prod.h`

Array: `NvU32 booter_ucode_data_ga100[]` — 8,832 32-bit words = **35,328 bytes** raw.

### Extraction

Words extracted as little-endian `uint32_t` → raw binary at `/tmp/booter_load_ga100_prod.bin`.

```
Total image:   35,328 bytes  (0x8A00)
Active content:  24,320 bytes  (0x5F00) — entropy 6.33–6.88
Sig slot:           384 bytes  @0x5F00  — entropy 0.00 (all zeros)
Trailing pad:    10,624 bytes  @0x6080  — entropy 0.00 (all zeros)
```

### Encryption Status

**NOT encrypted in this archive copy.**  
Entropy 6.33–6.88 vs. expected ~8.00 for AES ciphertext. The companion sig file (`g_booteruc_load_ga100_ga100_rsa3k_1_sig.h`) carries:

```c
// WARNING - this is not a prod mode build!!
NvU32 booter_load_sig_prod_ga100[] = {
    0x00000000, ... (96 zero words = 384 bytes)
};
NvU32 booter_load_sig_ga100_ucode_encrypted = 1;
```

The `ucode_encrypted = 1` field tells the driver infrastructure this binary _should_ have an encrypted payload in a real production build. In the development archive copy, the RSA-3K sig is zeroed and the AES encryption is absent.

**Implication:** The binary's control flow and register-write constants are directly readable without decryption. This enables full source↔binary validation.

---

## 2. Archive BINDATA Structure

The driver loads Booter via `BINDATA_ARCHIVE` (function `s_allocateUcodeFromBinArchive`):

| Named segment   | File                                  | Contents                  |
|-----------------|---------------------------------------|---------------------------|
| `image_prod`    | `g_booteruc_load_ga100_prod.h`        | Raw Falcon binary (35,328 B) |
| `sig_prod`      | `g_booteruc_load_ga100_ga100_rsa3k_1_sig.h` | RSA-3K sig (384 B, zeroed) |
| `patch_loc`     | same sig file, `patch_location[]`     | `24320` = `0x5F00`        |
| `patch_meta`    | same sig file, `patch_meta_data[]`    | fuse_ver=0, eng_id=1, ucode_id=3 |
| `num_sigs`      | same sig file, `num_sigs_per_ucode[]` | `1`                       |

Sig patch location 0x5F00 coincides exactly with where the all-zero block begins, confirming the zeroed bytes are the placeholder RSA-3K signature.

---

## 3. Execution Architecture: TU10X vs GA10X Path

GA100 Booter uses the **TU10X (Turing)** code path, NOT the GA10X (Ampere) path.

| Feature                                     | TU10X (GA100)                        | GA10X (GA102+)              |
|---------------------------------------------|--------------------------------------|------------------------------|
| PLM setup mechanism                         | Explicit Falcon `BAR0_WR32` calls    | RISC-V boot manifest         |
| DMEM_PRIV_LEVEL_MASK                        | `0xFF` (READ_L0_WRITE_L0) — **INSECURE** | Set by manifest (presumably tighter) |
| BCR_PRIV_LEVEL_MASK (`0x111664`)            | **Not written** (GA10X+ only)        | `0x8F` (READ_L0_WRITE_L3)   |
| GSP-RM start register                       | `NV_PGSP_RISCV_CPUCTL_ALIAS`         | `NV_PGSP_RISCV_BCR_CTRL` + `NV_PGSP_RISCV_CPUCTL` |
| BAR0 register access mechanism              | CSB bridge via SEC2 Falcon I/O space | Same                         |

The GA10X `booterSetupTargetRegisters_GA10X` comment explicitly states:
```c
// Raise BCR PLM (all other PLMs are set by RISC-V manifest)
```

GA100 therefore carries the Turing-era PLM vulnerability that GA102+ resolved by delegating to the RISC-V manifest.

---

## 4. PLM Configuration — Complete Binary-Verified Table

PLM writes occur in `booterSetupTargetRegisters_TU10X`. All nine register writes are binary-confirmed by searching for the 3-byte little-endian BAR0 address in the active code section.

The instruction encoding observed in the PLM write cluster (binary 0x5460–0x54F0) is:
```
8a [addr_lo] [addr_mid] [addr_hi]  4b [value] 00 7e 25 0f 00 8a ...
     ^^^^^^^^ BAR0 address ^^^^^^^^       ^^^ PLM mask ^^^  ^^^ wait_idle call ^^^
```

### Binary Hex Dump — PLM Write Cluster

```
05460  2c 00 bf 99 f4 30 fc fe 4f 01  8a 98 02 11  a0 f9  |,....0..O.  SCTL PLM  ..|
05470  4b 8f  00 7e 25 0f 00            8a 40 02 11  4b 00 40 7e 25  |K.8f ~%...  CTL  ...~%|
05480  0f 00  8a 00 01 11  bd b4 7e 25 0f 00  8a 80 02 11  |..  0x110100  ..~%..  IMEM  |
05490  4b 8f  00 7e 25 0f 00  8a 84 02 11  4b ff  00 7e 25  |K.8f ..  DMEM  K.ff ..~%|
054a0  0f 00  8a 88 02 11  4b 8f  00 7e 25 0f 00  8a 8c 02  |..  CPUCTL  K.8f ..  EXE  |
054b0  11  4b ff  00 7e 25 0f 00  8a 90 02 11  4b ff  00 7e  |K.ff ..  IRQTMR  K.ff ..|
054c0  25 0f 00  8a 94 02 11  4b ff  00 7e 25 0f 00  8a ec  |..  MTHDCTX  K.ff ..  |
054d0  00 11  4b 8f  00 7e 25 0f 00  8a f0 00 11  4b 8f  00  |DIODT K.8f ..  DIODTA K.8f|
054e0  7e 25 0f 00 ...                                         |~%...|
```

### PLM Table (source → binary verified)

| Register (BAR0 addr)             | Step | Binary offset | Value | Effective policy          | Risk |
|----------------------------------|------|---------------|-------|---------------------------|------|
| `NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK` `0x110298` | 1 | `0x546B+6` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_IMEM_PRIV_LEVEL_MASK` `0x110280` | 4a | `0x548D` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| **`NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK` `0x110284`** | **4b** | **`0x5498`** | **`0xFF`** | **READ_L0 / WRITE_L0** | **CRITICAL — GSP DMEM WRITE OPEN** |
| `NV_PGSP_FALCON_CPUCTL_PRIV_LEVEL_MASK` `0x110288` | 4c | `0x54A3` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_EXE_PRIV_LEVEL_MASK` `0x11028C` | 4d | `0x54AE` | `0xFF` | READ_L0 / WRITE_L0 | Low risk (EXE control) |
| `NV_PGSP_FALCON_IRQTMR_PRIV_LEVEL_MASK` `0x110290` | 4e | `0x54B9` | `0xFF` | READ_L0 / WRITE_L0 | Low risk |
| `NV_PGSP_FALCON_MTHDCTX_PRIV_LEVEL_MASK` `0x110294` | 4f | `0x54C4` | `0xFF` | READ_L0 / WRITE_L0 | Low risk |
| `NV_PGSP_FALCON_DIODT_PRIV_LEVEL_MASK` `0x1100EC` | 5a | `0x54CF` | `0x8F` | READ_L0 / WRITE_L3 | Secure |
| `NV_PGSP_FALCON_DIODTA_PRIV_LEVEL_MASK` `0x1100F0` | 5b | `0x54DA` | `0x8F` | READ_L0 / WRITE_L3 | Secure |

**PLM mask field encoding (bits 7:0):**
- Bits 3:0 = READ protection: `0xF` = all levels enabled (L0 readable)
- Bits 7:4 = WRITE protection: `0xF` = all levels (L0 writable), `0x8` = only L3 (HS writable)
- `0xFF` = `0b_1111_1111` → READ_L0, WRITE_L0 (no hardware protection)
- `0x8F` = `0b_1000_1111` → READ_L0, WRITE_L3 (HS-only writes)

---

## 5. REGIONCFG `#if 0` Block — Binary Confirmation

### Source (booter_boot_gsprm_tu10x_ga100.c:57–73)

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
    BOOTER_REG_WR32(BAR0, NV_PGSP_FBIF_REGIONCFG, data);
#endif
```

### Binary Verification

`NV_PGSP_FBIF_REGIONCFG` = `0x11066C`. The 3-byte LE needle `6c 06 11` is **NOT PRESENT** anywhere in the 24,320-byte active binary content.

**Confirmed: the REGIONCFG block is dead code (`#if 0`), absent from the compiled binary.**

### Security Implication

`REGIONCFG` controls which FB regions each Falcon DMA channel is allowed to access. Field value `2` in each slot would restrict transactions to "WPR region only". With this block disabled:

- GSP-RM FBIF DMA has **no WPR source restriction** — it can DMA from any framebuffer address
- An attacker who can control GSP-RM execution (e.g., via RPC overflow) or who can write to GSP DMEM (see §4) could direct GSP-RM DMA reads against arbitrary framebuffer addresses, including regions containing other guest or host secrets in a multi-tenant environment

The comment "Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot" suggests the GSP-RM RISC-V firmware itself accesses non-WPR FB regions during startup, so enabling this restriction would break boot. This is a design coupling issue, not a simple hardening oversight.

---

## 6. GSP-RM Privilege Level

From source (booter_boot_gsprm_tu10x_ga100.c:114):
```c
// Note: GSP-RM is L0 (so do not program _LSMODE or _LSMODE_LEVEL here)
data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _RESET_LVLM_EN, _TRUE, 0);
data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _STALLREQ_CLR_EN, _TRUE, data);
data = FLD_SET_DRF(_PFALCON, _FALCON_SCTL, _AUTH_EN, _TRUE, data);
BOOTER_REG_WR32(BAR0, NV_PGSP_FALCON_SCTL, data);
```

**GSP-RM runs at privilege level 0 (LS)**, the lowest Falcon privilege tier. This means:

1. GSP-RM cannot re-tighten its own PLMs (confirmed by Phase-3 finding: no PLM re-tighten symbols in GSP-RM binary)
2. GSP-RM DMEM remains writable by any L0 accessor for the entire GSP-RM lifetime
3. `AUTH_EN = TRUE` prevents unauthenticated CPU control register writes, but does not protect DMEM from L0 reads/writes

---

## 7. SCTL Final Configuration (Step 6)

Binary confirms `AUTH_EN = TRUE` is set. At binary 0x546B:

```
8a 98 02 11   → write to NV_PGSP_FALCON_SCTL_PRIV_LEVEL_MASK (0x110298) = 0x8F
...
[sctl value setup: RESET_LVLM_EN=TRUE, STALLREQ_CLR_EN=TRUE, AUTH_EN=TRUE]
```

The SCTL itself is PLM-protected (WRITE_L3), so an LS attacker cannot modify SCTL after Booter completes. However, DMEM remains writable to L0 regardless.

---

## 8. booterStartGspRm_TU10X — GSP-RM Launch Sequence

Binary region approximately 0x5420–0x5460:

```
8a 24 06 11 4b 90 00    → BAR0[0x110624] (NV_PGSP_FBIF_CTL) = 0x90 (ENABLE | ALLOW_PHYS_NO_CTX)
8a 84 06 11 0b 01       → BAR0[0x110684] (NV_PGSP_FBIF_CTL2) = NACK_MODE_NACK_AS_ACK
8a 6c 12 11 0b 01       → BAR0[0x11126c] (NV_PGSP_RISCV_CPUCTL_ALIAS) = STARTCPU_TRUE
```

`NV_PGSP_RISCV_CPUCTL_ALIAS` is a pre-GA10X mechanism. GA100 starts the GSP-RM RISC-V core via this alias register rather than the BCR-based mechanism used on GA102+.

---

## 9. Consolidated Vulnerability Assessment

### Finding 1 (CONFIRMED, CRITICAL): GSP DMEM PLM = READ_L0_WRITE_L0

**Source:** `booterSetupTargetRegisters_TU10X:94`  
**Binary evidence:** `NV_PGSP_FALCON_DMEM_PRIV_LEVEL_MASK` (0x110284) at binary+0x5498, value byte = `0xFF`  
**Comment in source:** "TODO suppal/derekw: TASK_RM fails to come up if this is WRITE_L3"

**Impact:**  
After Booter completes and GSP-RM starts, the GSP Falcon's DMEM has no hardware write protection. Any actor with L0 privilege access to the GSP Falcon's MMIO space can write arbitrary values into GSP DMEM:
- **Host driver (kernel):** Can directly write GSP DMEM via BAR0 priv-register access
- **Any other LS Falcon** with CSB-bridge access to GSP could potentially overwrite GSP DMEM
- The specific threat model depends on whether the host driver validates its own BAR0 writes

**Comparison with GA10X:** GA102+ delegates PLM setup to the RISC-V boot manifest, and the BCR PLM is set to READ_L0_WRITE_L3. The manifest is controlled by NVIDIA signing, not Booter source code. GA100 does not have this mechanism.

**Workaround note:** The TODO comment implies NVIDIA engineers identified this, attempted to fix it (WRITE_L3), found it breaks GSP-RM boot, and deferred the fix. No evidence of a subsequent resolution exists in this codebase.

### Finding 2 (CONFIRMED): FBIF REGIONCFG Disabled — Unrestricted GSP-RM FB DMA

**Binary evidence:** `NV_PGSP_FBIF_REGIONCFG` (0x11066c) absent from binary.  
**Reason:** `#if 0` wrapper in source, comment: "Setting REGIONCFG causes SACC in GSP-RM / LIBOS during boot"

**Impact:**  
GSP-RM can DMA from any framebuffer address, not just WPR-protected regions. In a system where multiple guests share the A100 (MIG mode), this means a compromised GSP-RM has no FB-region hardware restriction preventing it from reading framebuffer memory belonging to other guests.

**Mitigating factor:** GSP-RM is authenticated by Booter (RSA-3K + AES-DM, via AHESASC) before execution. The threat requires first achieving code execution within GSP-RM, not a direct driver primitive.

### Finding 3 (CONFIRMED): GSP-RM Is L0 and Cannot Self-Tighten PLMs

**Source:** "Note: GSP-RM is L0 (so do not program _LSMODE or _LSMODE_LEVEL here)"  
**Phase-3 corroboration:** No PLM re-tighten symbols found in GSP-RM RISC-V binary  
**Impact:** DMEM PLM weakness persists for the full GPU uptime; GSP-RM has no mechanism to harden its own memory protection after Booter exits.

---

## 10. Phase-4 P1 Open Items

The Booter LOAD analysis is **complete** at the source+binary level. The following remain deferred:

| Item | Target | Status |
|------|--------|--------|
| Booter RELOAD binary | `g_booteruc_reload_ga100_prod.h` | Not analyzed; likely similar PLM behavior |
| Booter UNLOAD binary | `g_booteruc_unload_ga100_prod.h` | P5 — PLM teardown path |
| Real prod binary with non-zero sig | Not in archive | Would need production SPI flash dump |

---

## 11. Cross-References

- Phase-2 §3.2/3.3: PLM gap first identified at source level (REGIONCFG `#if 0`, DMEM PLM TODO)
- Phase-3 §4: GSP-RM no PLM re-tighten symbols — confirmed
- Phase-4 P2: VBIOS FALCON_DATA_V2 catalog — next priority (DEVINIT + HBM2e ucode locations)
- PSIRT draft: `NVIDIA_PSIRT_DISCLOSURE_DRAFT.md` — Findings 1 and 2 from this document should be added
