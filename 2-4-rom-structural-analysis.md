# 2.4 — ROM Structural Analysis
## Exact Offset and Byte-Layout Map of Both VBIOS Images

**Files analysed:**
- `<GPU ROM archive>` — CMP 170HX, PCI DevID `0x20C2`, VBIOS date 2021-05-12
- `<GPU ROM archive>`  — A100,      PCI DevID `0x20B0`, VBIOS date 2020-02-13
- Both: exactly **1 044 480 B = 0xFF000** bytes

**Methodology:** `xxd`, Python `struct.unpack`, byte-diff map over 4 KB windows.
All offsets are **absolute file offsets** (little-endian unless noted).

---

## 1. Source File Catalog — GA100_SECURITY_ANALYSIS/

| File | Size (lines) | Role |
|---|---|---|
| `1-1-asset-inventory.md` | — | Master asset inventory, trust hierarchy, Phase-4 queue |
| `2-1-secure-boot-chain.md` | — | Phase-1: full secure boot chain analysis (partially superseded) |
| `2-2-firmware-wpr-lsf.md` | — | Phase-1: WPR blob layout, LSF format, offset-trust boundary |
| `2-3-firmware-parsing-vulns.md` | — | Phase-1: parser vulnerability tree (depMap OOB = GA10x+, not GA100 prod) |
| `4-1-isolation-smc-mig.md` | — | Phase-1: SMC/MIG instance-stride analysis; confirmed in Phase-3 binary |
| `4-2-isolation-fecs-dma.md` | — | Phase-1: FECS DMA arbiter; unchecked instance<<21 confirmed in binary |
| `3-1-falcon-privilege-boundaries.md` | — | Phase-1: PLM / DMEM privilege model; Booter binary needed to confirm |
| `4-3-runtime-ipc-interfaces.md` | — | Phase-1: RPC queue; GSP RISC-V shared-region layout confirmed |
| `5-1-vuln-memory-training.md` | — | Phase-1: memory training; DEVINIT target retargeted to VBIOS Image #2 |
| `4-4-runtime-post-verification.md` | — | Phase-1: pre-verify DMA scribble; binary confirmation pending |
| `4-5-runtime-errata-workarounds.md` | — | Phase-1: GA100 WAR functions; all 4 confirmed in Phase-3 binary |
| `5-3-vuln-exploit-chains.md` | — | Phase-1: exploit chains; ITCM gadget downgraded; SCP slot 43 is new pivot |
| `1-2-reverse-engineering-methodology.md` | — | Phase-1: RE target list; superseded by Phase-3 |
| `7-1-phase2-validation-findings.md` | — | Phase-2: source-validated findings; AES scheme corrected in Phase-3 |
| `7-2-phase3-binary-analysis.md` | — | Phase-3: binary-level RE, CMP 170HX prod-signed ACR + VBIOS |
| `15_ROM_STRUCTURAL_ANALYSIS.md` | — | **This document.** Exact hex offset map of both ROMs |

---

## 2. Physical Flash Layout Overview

Both ROMs use an identical two-copy redundancy scheme. The 0xFF000-byte flash is split at 0x60000 into a primary half and a recovery half.

```
File offset   CMP 170HX content         A100 content             Size
──────────    ──────────────────────    ──────────────────────    ─────
0x000000      IFR-1 header              IFR-1 header              ~0x700
0x002000      RFRD descriptor           RFRD descriptor           0x28
0x002028      DEVINIT scripts begin     DEVINIT scripts begin
              (HBM2e training, clocks)  (HBM2e training, clocks)
0x005000      [still DEVINIT data]      ┌ Image #1 (PCI ROM) ┐   0x5E00
0x005E00      ┌ Image #1 (PCI ROM) ┐   │                     │   0x6200
0x00B500      │                     │   └ Image #1 end        │
0x00C000      └ Image #1 end        │   (padding 0xFF)        │
0x00C700      ┌ Image #2 (Falcon)   │   ┌ Image #2 (Falcon) ┐
0x00B500      │                     └──►└ start              │
0x047700      └ Image #2 end            │                     │
0x041F00      (padding 0x00)            └ Image #2 end        │
0x048000      ── both ROMs 0x00 ──────────── 0x00 padding ─────────────
0x05FFFF      end of primary half        end of primary half
──────────────────────────────────────────────────────────────────────
0x060000      IFR-2 (byte-identical copy of IFR-1)
0x065000                                 Recovery Image #1 copy
0x065E00      Recovery Image #1 copy
0x06B500                                 Recovery Image #2 copy
0x06C700      Recovery Image #2 copy
0x0BFFFF      end of recovery half
──────────────────────────────────────────────────────────────────────
0x0C0000      0xFF erased flash (both identical)
0x0FEFFF      end of file
```

Diff density (0 = identical, 4096 = fully random / encrypted / differs entirely per 4 KB window):

```
0x000000-0x001FFF  ~43–165 diffs   IFR header — mostly shared BROM code, 6 key fields differ
0x002000-0x047FFF  2000–4086 diffs DEVINIT + ucodes — completely independent per SKU
0x048000-0x05FFFF  0 diffs         Both ROMs 0x00 (post-firmware padding)
0x060000-0x0BFFFF  (mirrors above with same pattern)
0x0C0000-0x0FEFFF  0 diffs         Both 0xFF erased flash
```

---

## 3. IFR-1 Header — Offset 0x000000

The Internal Flash Record (IFR) begins both ROMs. It embeds a small Falcon/PMU bootrom stub that scans the flash for RFRD/RFFS segment markers.

### 3.1 NVGI Header Block (bytes 0x000–0x023)

| Offset | Bytes (CMP)             | Bytes (A100)            | Field                        |
|--------|-------------------------|-------------------------|------------------------------|
| 0x0000 | `4E 56 47 49`           | `4E 56 47 49`           | Magic = "NVGI"               |
| 0x0004 | `52`                    | `8A`                    | Sub-type **(differs)**       |
| 0x0005 | `03`                    | `03`                    | Revision = 3                 |
| 0x0006 | `24 00`                 | `24 00`                 | Header size = 0x0024 = 36 B  |
| 0x0008 | `B4 06 00 80`           | `C0 06 00 80`           | IFR total end pointer **(differs)** `0x800006B4` / `0x800006C0` |
| 0x000C | `DE 10 85 15`           | `DE 10 50 14`           | Build stamp **(differs)**    |
| 0x0010 | `02 02 00 00`           | `02 02 00 00`           | Version word = 0x0202        |
| 0x0014 | `24 00 00 00`           | `24 00 00 00`           | (repeated header size)       |
| 0x0018 | `00 00 04 91`           | `00 00 04 83`           | Checksum/flags **(differs)** |
| 0x001C | `31 20 00 01`           | `31 20 00 01`           | Shared constant              |
| 0x0020 | `00 00 04 00`           | `00 00 04 00`           | Shared constant              |

**Key CMP-only bytes:** 0x0004=`52`, 0x0008=`B4`, 0x000E=`85`, 0x000F=`15`, 0x001B=`91`.
Total IFR differences (0x000–0x6FF): **43 bytes** in two clusters: header fields (5 bytes) and the tail region 0x6A0–0x6DB (38 bytes, RFFS record placement).

### 3.2 IFR BROM Code (bytes 0x025–0x68F)

Both ROMs share byte-identical BROM code in this range. The code contains the flash-scan loop that searches for `RFRD` and `RFFS` segment markers. These 4-byte strings appear embedded in the code as search literals — they are **not standalone segment headers**:

| Offset | Marker embedded in code | Role in code |
|--------|-------------------------|--------------|
| `0x0519` | `52 46 46 53` = "RFFS" | String constant used by scan loop |
| `0x0636` | `52 46 52 44` = "RFRD" | String constant used by scan loop |

### 3.3 IFR Tail and RFFS Standalone Record

At the end of the IFR code region, the BROM writes a pointer to the RFFS end-cap record and then the record itself:

| Offset (CMP) | Offset (A100) | Bytes (both) | Field |
|---|---|---|---|
| `0x6B8` | `0x6C8` | `C0 06 00 00` (CMP) / `00 00 00 00` (A100) | Pointer to RFFS record |
| `0x6C0` | `0x6D0` | `52 46 46 53` | RFFS magic = "RFFS" |
| `0x6C4` | `0x6D4` | `02 00` | RFFS version = 2 |
| `0x6C6` | `0x6D6` | `0C 00` | RFFS struct size = 12 B |
| `0x6C8` | `0x6D8` | `20 00 00 10` | RFFS next-segment address |
| `0x6CC` | `0x6DC` | `00 00 00 00` | (padding) |

The RFFS record marks the end of IFR-1. After it, both ROMs pad with `0x00` bytes up to 0x2000.

---

## 4. RFRD Flash Descriptor — Offset 0x002000 (Both ROMs)

The RFRD (Read Flash Record Descriptor) at 0x2000 describes the flash layout to the BROM scan loop. It is the **only true structural RFRD record**; all other RFRD occurrences (0x636, 0x139E4/0x15528) are Falcon code literals.

| Offset | CMP bytes             | A100 bytes            | LE uint32 (CMP)  | Field            |
|--------|-----------------------|-----------------------|------------------|------------------|
| +0x00  | `52 46 52 44`         | same                  | —                | Magic = "RFRD"   |
| +0x04  | `03 00 28 00`         | same                  | ver=3, sz=0x28   | Version / size   |
| +0x08  | `00 5E 00 00`         | `00 50 00 00`         | `0x00005E00`     | **Image #1 base offset** |
| +0x0C  | `00 18 04 00`         | `00 CE 03 00`         | `0x00041800`     | Payload end ptr (Image #1+#2 combined size anchor) |
| +0x10  | `00 10 0C 00`         | `00 10 0C 00`         | `0x000C1000`     | (shared constant) |
| +0x14  | `00 10 03 00`         | `00 10 03 00`         | `0x00031000`     | (shared constant) |
| +0x18  | `00 00 06 00`         | `00 00 06 00`         | **`0x00060000`** | IFR-2 / recovery offset |
| +0x1C  | `00 22 00 00`         | `00 22 00 00`         | `0x00002200`     | (shared constant) |
| +0x20  | `0C E7 00 00`         | `64 0F 01 00`         | `0x0000E70C`     | DEVINIT script total size (bytes) |
| +0x24  | `E8 A3 01 00`         | `00 BD 01 00`         | `0x0001A3E8`     | (secondary size field) |

Key confirmed fields:
- **+0x08**: Image #1 file offset = `0x5E00` (CMP) / `0x5000` (A100)
- **+0x18**: `0x00060000` — offset of IFR-2 (recovery section start), identical in both ROMs

Between 0x2028 and the Image #1 base, both ROMs contain DEVINIT scripts, clock tables, soft-strap data, and memory-training routines.

---

## 5. PCI ROM Image #1

### 5.1 Image Header

| Field | CMP offset | CMP value | A100 offset | A100 value |
|---|---|---|---|---|
| PCI ROM signature `55 AA` | `0x005E00` | `55 AA` | `0x005000` | `55 AA` |
| Image size (512B blocks) | `0x005E02` | `0x31` = 49 blks = **0x6200 B** | `0x005002` | `0x2F` = 47 blks = **0x5E00 B** |
| Image boundary end | computed | `0x005E00 + 0x6200 = 0x00C000` | computed | `0x005000 + 0x5E00 = 0x00AE00` |
| PCIR pointer (at +0x18) | `0x005E18` | `0x0070` → PCIR @ `0x005E70` | `0x005018` | `0x0070` → PCIR @ `0x005070` |
| x86 near-jump opcode | `0x005E08` | `E9` (JMP +0x194C → 0x7756) | `0x005008` | `E9` (JMP +0x1940 → 0x694A) |
| BIOS build date string | `0x005E37` | `"05/14/21"` (x86 ROM date) | `0x005037` | `"02/14/20"` |

Note: The x86 VGA ROM "date" at Image header +0x37 (build date of the x86 option ROM) slightly differs from the VBIOS operational date in BIT token `'i'` (see §7.3 below).

### 5.2 PCIR Header (PCI Data Structure)

Both images share the same PCIR structure at `Image_base + 0x70`:

| Field | CMP @ `0x005E70` | A100 @ `0x005070` |
|---|---|---|
| Magic | `50 43 49 52` = "PCIR" | same |
| Vendor ID | `DE 10` = **0x10DE (NVIDIA)** | same |
| Device ID | `C2 20` = **0x20C2** | `B0 20` = **0x20B0** |
| Device List Ptr | `00 00` | same |
| PCIR struct length | `18 00` = 24 B | same |
| Revision | `00` | same |
| Class code | `00 02 03` = Display/VGA/8514-compat | same |
| Image length (512B blks) | `31 00` = 0x31 blks = **0x6200 B** | `2F 00` = 0x2F = **0x5E00 B** |
| Revision level | `01 00` = 1 | same |
| Code type | `00` = **x86** | same |
| Last image flag | `80` = **LAST** (intentional; NVIDIA parser uses NPDE to find Image #2) | same |

**Security note**: The `LastImage = 0x80` flag in PCIR tells standard PCI ROM scanners to stop here, hiding Image #2 (the Falcon firmware container) from OS-level ROM enumeration. NVIDIA's own parser reads beyond this via the `BIT_DATA_FALCON_DATA` pointer chain.

### 5.3 NPDE Header (NVIDIA PCI Data Extension) — Image #1

At `Image_base + 0x90`:

| Field | CMP @ `0x005E90` | A100 @ `0x005090` |
|---|---|---|
| Magic | `4E 50 44 45` = "NPDE" | same |
| Version | `01 01` (v1.1) | same |
| Struct size | `14 00` = 20 B | same |
| Subimage length | `31 00` = 49 blks | `2F 00` = 47 blks |
| Last image flag | `00` = **MORE** (NPDE says continue; PCIR said LAST) | same |
| Subsystem Vendor | `DE 10` = 0x10DE | same |
| Subsystem Device | `85 15` = 0x1585 (CMP 170HX subsys) | `50 14` = 0x1450 (A100 subsys) |

### 5.4 BIT Table Header — Image #1

At `Image_base + 0xB0`:

| Field | CMP @ `0x005EB0` | A100 @ `0x0050B0` | Value |
|---|---|---|---|
| Pre-header bytes | `FF B8` | `FF B8` | BIT block anchor (part of checksum domain) |
| Magic | `42 49 54 00` = "BIT\0" | same | |
| Header ID | `00` | `00` | |
| Version | `01` | `01` | 1 |
| Header size | `0C` = 12 B | `0C` | Counts from `FF B8` |
| Entry size | `06` = 6 B | `06` | token(1)+ver(1)+size(2)+ptr(2) |
| Entry count | `10` = **16** | `10` | |
| Checksum | `47` | `47` | Sum of all BIT bytes = 0 |
| Entries start | `0x005EBC` | `0x0050BC` | `= (FF_B8_offset) + hdr_sz` |

---

## 6. BIT Table — All 16 Entries

Pointers are **image-base-relative** (add `0x5E00` for CMP, `0x5000` for A100 to get file offset).

| # | Token | Name | Ver | CMP size | CMP ptr→file | A100 size | A100 ptr→file |
|---|---|---|---|---|---|---|---|
| 00 | `0x32` '2' | version-anchor | 1 | 4 B | `0x012C`→`0x5F2C` | 4 B | `0x012C`→`0x512C` |
| 01 | `0x42` 'B' | BIOSDATA | 2 | 37 B | `0x0138`→`0x5F38` | 37 B | `0x0138`→`0x5138` |
| 02 | `0x43` 'C' | **CLOCK** | 2 | **44 B** | `0x015D`→`0x5F5D` | **28 B** | `0x015D`→`0x515D` |
| 03 | `0x44` 'D' | DAC | 1 | 4 B | `0x0189`→`0x5F89` | 4 B | `0x0179`→`0x5179` |
| 04 | `0x49` 'I' | INTERNAL | 1 | 36 B | `0x018D`→`0x5F8D` | 36 B | `0x017D`→`0x517D` |
| 05 | `0x4D` 'M' | MEMORY | 2 | 41 B | `0x01B1`→`0x5FB1` | 41 B | `0x01A1`→`0x51A1` |
| 06 | `0x4E` 'N' | (empty) | 0 | 0 B | — | 0 B | — |
| 07 | `0x50` 'P' | **PERF** | 2 | **232 B** | `0x01DA`→`0x5FDA` | **196 B** | `0x01CA`→`0x51CA` |
| 08 | `0x54` 'T' | TMDS_INFO | 1 | 2 B | `0x02C2`→`0x60C2` | 2 B | `0x028E`→`0x528E` |
| 09 | `0x55` 'U' | USERDEF | 1 | 5 B | `0x02C4`→`0x60C4` | 5 B | `0x0290`→`0x5290` |
| 10 | `0x56` 'V' | VIRTUAL_STRAP | 1 | 6 B | `0x02C9`→`0x60C9` | 6 B | `0x0295`→`0x5295` |
| 11 | `0x78` 'x' | XMEMCFG | 1 | 8 B | `0x02CF`→`0x60CF` | 8 B | `0x029B`→`0x529B` |
| 12 | `0x64` 'd' | DCB | 1 | 2 B | `0x02D7`→`0x60D7` | 2 B | `0x02A3`→`0x52A3` |
| **13** | **`0x70` 'p'** | **FALCON_DATA** | 2 | **4 B** | **`0x02D9`→`0x60D9`** | **4 B** | **`0x02A5`→`0x52A5`** |
| **14** | **`0x75` 'u'** | **UNIFIED_BOOT** | 1 | **13 B** | `0x02DD`→`0x60DD` | **13 B** | `0x02A9`→`0x52A9` |
| **15** | **`0x69` 'i'** | **NV_INIT_PTRS_TBL** | 2 | **110 B** | `0x02EC`→`0x60EC` | **106 B** | `0x02B8`→`0x52B8` |

**Key size differences (mining-lock customisation for CMP):**
- Token 'C' (CLOCK): CMP +16 B vs A100 — extra clock entries (mining perf table)
- Token 'P' (PERF): CMP +36 B vs A100 — extra perf entries (mining-lock power/freq table)

---

## 7. BIT Data Regions of Security Interest

### 7.1 FALCON_DATA Pointer (Token 'p') — File offset 0x60D9 / 0x52A5

The 4-byte data at these offsets is a **pointer to the FALCON_DATA_V2 catalog**, image-base-relative:

| ROM | Ptr bytes | LE value | → file offset |
|---|---|---|---|
| CMP | `54 63 00 00` | `0x00006354` | `0x5E00 + 0x6354` = **`0x00C154`** |
| A100 | `44 5F 00 00` | `0x00005F44` | `0x5000 + 0x5F44` = **`0x00AF44`** |

### 7.2 FALCON_DATA_V2 Catalog Structure — File 0xC154 / 0xAF44

| Field | Offset | CMP | A100 |
|---|---|---|---|
| Header byte | +0x00 | `0x01` | `0x01` |
| Ver major | +0x01 | `0x06` | `0x06` |
| Entry count | +0x02 | `0x06` (6 ucodes) | `0x06` (6 ucodes) |
| Entry size | +0x03 | `0x10` = 16 B each | `0x10` |
| Flags | +0x04 | `0x01` | `0x01` |
| Payload ptr | +0x08 | `0x00006954` (abs file) | `0x00009BEC` (abs file) |
| ucode ptr 1 | +0x2C | `0x0002E01C` (rel → file `0x03A19C`) | `0x0002E7F4` (rel → file `0x039764`) |

The six entries catalogue PMU/DEVINIT, HBM2e training, clock management, and auxiliary ucodes. Each entry is 16 bytes (ptr + size + type). **This is the Phase-4 DEVINIT extraction target.**

### 7.3 NV_INIT_PTRS_TBL (Token 'i') — File 0x60EC / 0x52B8

Key fields decoded (110 B CMP / 106 B A100):

| Byte offset | CMP value | A100 value | Apparent field |
|---|---|---|---|
| +0x00 | `00` | `00` | (flags / null) |
| +0x01-02 | `67 00` = 0x0067 | `0D 00` = 0x000D | DEVINIT script 1 ptr (image-relative) |
| +0x03-04 | `92 01` = 0x0192 | `92 03` = 0x0392 | DEVINIT script 2 ptr |
| +0x07-08 | `73 0C` = 0x0C73 | `16 1C` = 0x1C16 | Init clock table ptr |
| +0x09-0A | `C9 01` = 0x01C9 | `AB 01` = 0x01AB | (secondary ptr) |
| **+0x0F-0x16** | **`"05/12/21\0"`** | **`"02/13/20\0"`** | **VBIOS build date (ASCII null-terminated)** |
| +0x23-26 | `23 DE FE B5` | `9D 05 69 D3` | Firmware HMAC/signature prefix |
| +0x27-2A | `43 23 41 BD` | `59 C9 4A A3` | (sig continuation) |
| +0x2B-30 | `8E FE 06 C3 A1 59` | `BF 07 8F 2D 88 8F` | (sig continuation) |

**VBIOS build dates (authoritative):**
- CMP 170HX: `0x60FB` — `"05/12/21"` = **2021 May 12**
- A100:       `0x52C7` — `"02/13/20"` = **2020 Feb 13**

---

## 8. PCI ROM Image #2 — Firmware Container

Image #2 is NVIDIA's proprietary Falcon firmware container. It is **not** a standard PCI expansion ROM despite beginning with `55 AA`. Standard PCI ROM scanners stop at Image #1 (PCIR LastImage=0x80).

### 8.1 Image #2 Header (0x55AA + NPDS at +0x20)

| Offset | Field | CMP `0xC700` | A100 `0xB500` |
|---|---|---|---|
| +0x00 | Signature | `55 AA` | `55 AA` |
| +0x02 | Image size byte | `00` | `00` (non-standard — size conveyed by NPDS) |
| +0x03–0x1F | Reserved | all `0x00` | all `0x00` |
| +0x18 | NPDS pointer | `20 00 00 00` = 0x20 | same |
| +0x20 | NPDS magic | `4E 50 44 53` = "NPDS" | same |

### 8.2 NPDS (NVIDIA PCI Data Structure) — 24 Bytes

| Field | Offset | CMP | A100 |
|---|---|---|---|
| Magic | +0x00 | `NPDS` | `NPDS` |
| Vendor ID | +0x04 | `DE 10` = 0x10DE | same |
| Field_06 | +0x06 | `80 20` = 0x2080 | same |
| Struct size | +0x0A | `18 00` = 24 B | same |
| Revision | +0x0C | `00 00 00 00` | same |
| **Image size** | **+0x10** | **`D8 01 00 00` = 0x1D8 blks = 0x3B000 B** | **`B5 01 00 00` = 0x1B5 blks = 0x36A00 B** |
| Max runtime | +0x14 | `E0 80 00 00` = 0x80E0 | same |

**Image #2 boundaries (absolute file offsets):**
- CMP: `0x00C700` to `0x00C700 + 0x3B000` = **`0x00C700`–`0x047700`** (241 KB)
- A100: `0x00B500` to `0x00B500 + 0x36A00` = **`0x00B500`–`0x041F00`** (219 KB)

### 8.3 NPDE (NVIDIA PCI Data Extension) — Image #2 — 20 Bytes

At Image#2_base + 0x40:

| Field | CMP `0xC740` | A100 `0xB540` |
|---|---|---|
| Magic | `NPDE` | `NPDE` |
| Version | `01 01` (v1.1) | same |
| Struct size | `14 00` = 20 B | same |
| Sub-image len | `D8 01` = 0x1D8 blks | `B5 01` = 0x1B5 blks |
| **Last image** | **`80` = LAST** | **`80` = LAST** |

After the 20-byte NPDE, Image #2 carries extension fields (firmware loading parameters, scatter-gather pointers) from offset +0x54 to +0x80, then Falcon ucode payloads begin at approximately `Image#2_base + 0x84` = **`0xC784` (CMP)**.

---

## 9. ACR / Falcon Signature Block Locations

The ACR Falcon images are **not embedded directly in the VBIOS ROM**. They are loaded by GSP-RM from a separate kernel driver blob (`.h` C arrays under `drivers/resman/kernel/inc/`). The VBIOS ROM contains only:

1. **PMU ucode** (boot-time DEVINIT, memory training) in Image #2 starting near `0xC784` / `0xB584`
2. **DEVINIT scripts** (register programming sequences) from ~0x2028 to Image #1

The ACR/AHESASC/Booter RSA-3K signature headers live in the driver blob, not in the VBIOS. Their file locations in the archive:

| Component | File | Sig block |
|---|---|---|
| ASB (GSP-lite) | `acr/bin/gsp/ga100/asb/g_acruc_ga100_asb_ga100_rsa3k_1_sig.h` | RSA-3K sig #1 (5 301 B) |
| ASB (GSP-lite) | `acr/bin/gsp/ga100/asb/g_acruc_ga100_asb_ga100_rsa3k_0_sig.h` | RSA-3K sig #0 (3 134 B) |
| AHESASC | `acr/bin/sec2/ga100/ahesasc/g_acruc_ga100_ahesasc_ga100_rsa3k_1_sig.h` | RSA-3K sig |
| AHESASC APM | `acr/bin/sec2/ga100/ahesasc_apm/g_acruc_ga100_ahesasc_apm_ga100_rsa3k_1_sig.h` | RSA-3K sig |
| Booter LOAD | `gsprm/bin/booter/ga100/load/g_booteruc_load_ga100_ga100_rsa3k_1_sig.h` | RSA-3K sig |

The VBIOS ROM itself carries no RSA headers. The BIT table data at token `'i'` (+0x23) contains a 16-byte firmware HMAC (not an RSA signature) that differs per-SKU.

---

## 10. Recovery Half Layout — Offset 0x060000

IFR-2 at 0x60000 is **byte-identical** to IFR-1 at 0x000000 (confirmed by 0-diff comparison of both halves). Recovery ROM images are positioned at the same relative offsets within the second half as their primaries within the first half:

| Region | CMP primary | CMP recovery | A100 primary | A100 recovery |
|---|---|---|---|---|
| IFR | `0x000000` | `0x060000` | `0x000000` | `0x060000` |
| Image #1 start | `0x005E00` | `0x065E00` | `0x005000` | `0x065000` |
| Image #1 end | `0x00C000` | `0x06C000` | `0x00AE00` | `0x06AE00` |
| Image #2 start | `0x00C700` | `0x06C700` | `0x00B500` | `0x06B500` |
| Image #2 end | `0x047700` | `0x0A7700` | `0x041F00` | `0x0A1F00` |

Within a half, primary vs recovery differ in 100–230 bytes: rolling revision counters, VBIOS build-sequence markers, and second-stage signature fields. IFR primary vs IFR recovery is byte-perfect (0 differences).

---

## 11. Key Hex Constant Summary (Both ROMs)

| Constant | CMP file offset | A100 file offset | Value | Significance |
|---|---|---|---|---|
| IFR-1 magic | `0x000000` | `0x000000` | `4E 56 47 49` = "NVGI" | Start of ROM |
| IFR-1 sub-type | `0x000004` | `0x000004` | CMP=`52` / A100=`8A` | ROM variant tag |
| IFR total-end ptr | `0x000008` | `0x000008` | CMP=`0x800006B4` / A100=`0x800006C0` | IFR span |
| RFFS standalone | `0x0006C0` | `0x0006D0` | `52 46 46 53` = "RFFS" | IFR-1 end cap |
| RFRD descriptor | `0x002000` | `0x002000` | `52 46 52 44` = "RFRD" | Flash layout |
| Image #1 base | `0x005E00` | `0x005000` | `55 AA` | PCI ROM start |
| PCIR | `0x005E70` | `0x005070` | DevID `0x20C2`/`0x20B0` | PCI device identity |
| NPDE (Img#1) | `0x005E90` | `0x005090` | last=`0x00` (MORE) | Chain continues |
| BIT anchor | `0x005EB0` | `0x0050B0` | `FF B8` | BIT block start |
| BIT magic | `0x005EB2` | `0x0050B2` | `42 49 54 00` = "BIT\0" | |
| BIT entries | `0x005EBC` | `0x0050BC` | 16 × 6-byte entries | |
| FALCON_DATA ptr | `0x0060D9` | `0x0052A5` | `0x6354` / `0x5F44` (imgrel) | Ucode catalog ptr |
| VBIOS date | `0x0060FB` | `0x0052C7` | `"05/12/21"` / `"02/13/20"` | Build timestamp |
| FALCON_DATA_V2 | `0x00C154` | `0x00AF44` | 6-entry catalog | Ucode manifest |
| Image #2 base | `0x00C700` | `0x00B500` | `55 AA 00 00` | Firmware container |
| NPDS (Img#2) | `0x00C720` | `0x00B520` | size=`0x1D8`/`0x1B5` blks | Image #2 size |
| NPDE (Img#2) | `0x00C740` | `0x00B540` | last=`0x80` (LAST) | Chain end |
| Falcon payload | `0x00C784` | `~0x00B584` | Falcon opcodes begin | PMU ucode |
| Image #2 end | `0x047700` | `0x041F00` | (computed) | Firmware end |
| 0x00 pad start | `0x047700` | `0x041F00` | both identical | Post-firmware |
| IFR-2 recovery | `0x060000` | `0x060000` | byte-identical to IFR-1 | |
| IFR-2 RFFS | `0x0606C0` | `0x0606D0` | same as primary | Recovery IFR end |

---

**Produced**: 2026-05-17 — Phase-3 data, binary-verified.
**Phase-4 extraction target**: FALCON_DATA_V2 at `0xC154` (CMP) — 6-entry catalog resolves all PMU/DEVINIT/HBM2e ucode file offsets.
