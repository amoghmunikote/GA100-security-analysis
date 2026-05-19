# 2.3 — Firmware Parsing Vulnerabilities

## Overview

The GA100 secure boot process relies on correct parsing of firmware metadata and proper validation of untrusted fields. This analysis documents the complete vulnerability tree in the firmware parsing logic, focusing on how parser gaps can be exploited to compromise firmware integrity without breaking RSA signatures.

---

## Vulnerability 1: SMC Instance Not Validated in Register Addressing

### Severity: CRITICAL

### Location
**File**: `uproc/acr/src/acrsec2shared/ampere/acr_dma_ga100.c`  
**Function**: Register access macros and DMA initialization  
**Macro**: `NV_GET_PGRAPH_SMC_REG(base, instance_id, offset)`

### Root Cause

Simultaneous Multi-Client (SMC) architecture allows multiple GPU contexts to run in parallel. Each context has independent register banks accessed through instance-based addressing:

```
Register Address = base_register + (instance_id * stride)
```

The critical vulnerability: **instance_id is not validated before use in register calculations**.

### Code Pattern

```c
// Pseudocode from acr_dma_ga100.c
void acr_dma_setup(uint32_t falconInstance) {
    // No bounds checking on falconInstance
    uint32_t reg_addr = DMA_BASE + (falconInstance * REG_STRIDE);
    
    // Write DMA configuration to computed address
    mmio_write(reg_addr + DMA_CONFIG_OFFSET, dma_config);
    mmio_write(reg_addr + DMA_CTRL_OFFSET, dma_ctrl);
}
```

### Attack Vector

**SMC Instance Misdirection**:
1. Firmware provides `falconInstance` value in LSF descriptor
2. ACR uses value without validation in register addressing
3. Attacker specifies out-of-bounds instance ID (e.g., 0xFFFFFFFF)
4. Register calculation accesses arbitrary memory location
5. MMIO write executes at attacker-chosen address

**DMA Configuration Abuse**:
```
Normal: instance=1 → address = 0x40000 + (1 * 0x10000) = 0x50000
Attack: instance=5 → address = 0x40000 + (5 * 0x10000) = 0x90000 (may be different hardware)
```

### Impact

1. **Arbitrary MMIO Write**: Write GPU registers at unintended locations
2. **DMA Misdirection**: Redirect DMA transfers to/from arbitrary memory
3. **Hardware State Corruption**: Modify GPU state without authorization
4. **Privilege Escalation**: Configure DMA for firmware code injection

### Exploitability Assessment

**Difficulty**: MEDIUM
- Requires understanding of register layout
- Needs to know valid writable register addresses
- May require repeated attempts to find useful targets

**Likelihood**: HIGH
- Direct code path from firmware to register write
- No cryptographic protection needed
- Straightforward exploitation once target identified

### Proof-of-Concept Outline

```python
# Craft malicious LSF with out-of-bounds instance ID
class MaliciousFirmwareImage:
    def __init__(self):
        self.instance_id = 0x10000  # Out of bounds
        self.target_register = 0x500000  # Some GPU register
        
# Expected behavior:
# - Normal: instance_id=1 → reg_base + (1 * stride) = 0x50000
# - Attack:  instance_id=0x10000 → reg_base + (0x10000 * stride) = arbitrary address
```

### Files Involved
- `acr_dma_ga100.c` - DMA setup and register addressing
- `dev_smcarb.h` - SMC register definitions
- `dev_graphics_nobundle.h` - General GPU registers

---

## Vulnerability 2: Dependency Map Array Bounds Violation

### Severity: ~~CRITICAL~~ **DOWNGRADED — NOT PRESENT IN GA100 PROD**

> **CORRECTION (Phase-3)**: `_acrlibCheckDependency_v2()` is the **GA10X v2-blob code path**. GA100 production binaries use **v1 blobs** and this function is absent from the prod-signed AHESASC binary. Anti-rollback on GA100 is enforced via the FPF fuse register `NV_FUSE_OPT_FPF_UCODE_ACR_HS_REV` at `0x824250`, not via depMap iteration. The OOB array access vulnerability does NOT apply to GA100 prod builds. See `7-2-phase3-binary-analysis.md` for binary confirmation.

### Location
**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c` (GA10X+ path only)  
**Function**: `_acrlibCheckDependency_v2()`  
**Data Structure**: Dependency map in LSF descriptor v2 blob (not used on GA100)

### Root Cause

The firmware dependency map is used for version tracking and anti-rollback checks. Each dependency entry specifies which firmware image to check, but the firmware ID is not validated before array access.

### Code Pattern

```c
// Simplified from acr_wpr_ctrl_ga10x.c
void _acrlibCheckDependency_v2(LSF_Descriptor* lsf) {
    for (int i = 0; i < lsf->depCount; i++) {
        uint8_t depFalconId = lsf->depMap[i];
        
        // CRITICAL: depFalconId used directly as array index
        // No validation that depFalconId < version_table_size
        uint32_t currentVersion = g_versionTable[depFalconId];
        uint32_t newVersion = lsf->binVersion;
        
        if (currentVersion > newVersion) {
            // Reject if version is older (rollback)
            return ACR_ERROR_ROLLBACK;
        }
    }
}
```

### Attack Vector

**Out-of-Bounds Array Read**:
1. Attacker creates LSF with crafted dependency map
2. `depMap[i]` contains index > version_table_size
3. Array read accesses uninitialized or sensitive memory
4. Information disclosed about GPU state or key material

**Multi-Stage Exploitation**:
```
Stage 1: Read memory to find target
├─ depMap = [0, 1, 2, 100, 50, 150, ...]
├─ Out-of-bounds reads leak memory contents
└─ Identify useful target for next stage

Stage 2: Corrupt array element
├─ Use integer overflow vulnerability (Vuln #7)
├─ Write to arbitrary version table entry
└─ Enable rollback of specific firmware
```

### Impact

1. **Information Disclosure**: Leak GPU memory contents
2. **Dependency Map Corruption**: Enable selective firmware rollback
3. **Version Table Manipulation**: Modify tracked firmware versions
4. **Denial of Service**: Crash bootloader with invalid memory access

### Exploitability Assessment

**Difficulty**: MEDIUM
- Requires crafting valid LSF with malicious depMap
- Needs to know useful memory locations to read
- May require binary analysis to determine memory layout

**Likelihood**: HIGH
- Direct path from LSF parsing to memory access
- No validation of array indices
- Repeatable and controlled

### Proof-of-Concept Outline

```python
class MaliciousDepMap:
    def __init__(self):
        # Craft depMap with out-of-bounds indices
        self.depMap = bytes([
            0,    # Valid index
            1,    # Valid index
            255,  # Out of bounds (assume table size < 255)
            100,  # Potential information leak
        ])
        self.depCount = 4
```

### Files Involved
- `acr_wpr_ctrl_ga10x.c` - Dependency map parsing
- `acr_sanity_checks_ga100.c` - Version validation logic
- Version table storage location (to be identified in binary)

---

## Vulnerability 3: AES Encryption Key Derivation Undocumented

### Severity: CRITICAL

### Location
**File**: `uproc/acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga100.c`  
**Function**: ~~AES-CBC decryption routine~~

> **CORRECTION (/4 binary analysis — see `6-1-crypto-auth-chain-map.md` §5, `6-2-verification-state-machine.md` §3.7):**  
> **GA100 does not use AES-CBC for LS firmware authentication.** The file `acr_decrypt_ls_ucode_ga100.c` exists but the GA100 production AHESASC binary uses the TU10X code path: AES-DM (Davies-Meyer) hash + AES-ECB KDF via SCP hardware slot 43. The AES-CBC path (`acr_decrypt_ls_ucode_ga10x.c`) is GA10X+ only and is confirmed absent from the GA100 prod AHESASC binary. The three hypotheses below and the code pattern are ## speculation; the actual mechanism is fully resolved.

### Root Cause (RESOLVED)

~~Encrypted firmware images use AES-CBC encryption~~ **LS authentication uses AES-DM + KDF + SCP slot 43**, the source and derivation of which are now fully documented:

1. ~~Keys are hardcoded (same for all GA100s)~~ — **WRONG.** Key is KDF-derived per falcon, but root is SCP slot 43.
2. ~~Keys are derived from a GPU-unique identifier~~ — **WRONG.** SCP slot 43 is the same across all GA100 dies (manufacturing-time secret, not per-GPU).
3. ~~Keys are stored in read-protected WPR~~ — **WRONG.** Root key is in SCP hardware (inaccessible from software); the per-falcon derived key is ephemeral in SCP registers during verification only.

**Actual authentication formula** (binary-confirmed):
```
dmHash     = DaviesMeyer_AES128(ucode_bytes_16B_blocks)   // via SCP R2/R3/R4
derivedKey = AES-ECB(key=SCP_slot43, plain=g_kdfSalt XOR falconId)
computedSig = AES-ECB(key=derivedKey, plain=dmHash)
PASS if computedSig == lsbHeader.signature[16B]
```

KDF salt (public, embedded in signed binary): `B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62`  
SCP slot: `falc_scp_secret(0x2B=43, SCP_R2)` — opcode `cci 0xc2b2` binary-confirmed.

### Investigation Areas

**Hardcoded Keys** (High Risk):
- If AES key is constant across all GA100s
- Encrypted firmware becomes effectively plaintext
- Enables reverse engineering of encrypted microcode
- Defeats confidentiality protection

**Derived Keys** (Medium Risk):
- If keys derived from GPU-unique identifier
- Must determine derivation formula
- May be breakable if PRNG is weak
- May be side-channel vulnerable

**WPR-Protected Keys** (Low Risk):
- If keys stored in read-protected WPR
- Still vulnerable to other attacks
- But confidentiality better protected

### Attack Vectors

**If Hardcoded**:
1. Extract AES key from any GA100 firmware image
2. Decrypt all encrypted GA100 microcode
3. Reverse engineer privileged firmware
4. Identify additional vulnerabilities

**If GPU-Unique**:
1. Determine GPU identifier (Serial number? Silicon ID?)
2. Derive AES key for target GPU
3. Decrypt encrypted firmware on target

### Impact

1. **Firmware Reverse Engineering**: Access to privileged microcode
2. **Vulnerability Discovery**: Find undisclosed hardware bugs
3. **Attack Surface Expansion**: Additional exploitation paths
4. **Information Disclosure**: Leaked algorithms and design details

### Exploitability Assessment

**Difficulty**: LOW (if hardcoded), HIGH (if GPU-unique)
- Hardcoded keys: Simple key extraction, trivial decryption
- GPU-unique keys: Requires identifier determination and derivation reverse engineering

**Likelihood**: HIGH
- Encryption shouldn't be relied on for boot sequence
- Typically only for confidentiality, not integrity

### Investigation Required

- [ ] Extract prebuilt GA100-sec firmware from archive
- [ ] Check for hardcoded AES key in binary
- [ ] Analyze key loading routine in `acr_decrypt_ls_ucode_ga100.c`
- [ ] Look for key derivation functions
- [ ] Check GPU identifier sources (fuses, registers)
- [ ] Attempt decryption with candidate keys

### Files Involved
- `acr_decrypt_ls_ucode_ga100.c` - AES decryption implementation
- Prebuilt firmware: `basic-ga100-sec`, `basic-ga100-gsp`, `basic-ga100-pmu`
- Key storage location (WPR or elsewhere - to be determined)

---

## Vulnerability 4: HBM2e Memory Training State Not Cryptographically Verified

### Severity: MEDIUM (attack surface is VBIOS/DEVINIT, not a Falcon ucode file)

> **CORRECTION (Phase-2)**: The original analysis referenced `fbflcn_gddr_boot_time_training_ga100.c` and framed this as a GDDR6 vulnerability. **Both are wrong for GA100.** GA100 uses **HBM2e** (not GDDR6), and no `fbflcn_gddr_boot_time_training_ga100.c` exists in the source tree. The GDDR6 training files (`fbflcn_gddr_boot_time_training_ga10x.c` and `_tu10x.c`) target other chips (GA102/TU10x). GA100 HBM2e initialization is handled by:
> - **DEVINIT**: VBIOS-embedded PMU scripted sequencer (at POST time; not a Falcon ucode covered by AES-DM)
> - **HULK**: HBM2e row-remap/training ucode (TargetID=5 = FBFalcon, embedded in VBIOS Image #2, confirmed in `2-6-vbios-ucode-catalog.md`)

### Location
**Target**: HULK ucode (`HULK_PROD` / `HULK_DBG` entries in VBIOS Image #2) + DEVINIT PMU script  
**Data**: HBM2e row-remap training results and timing parameters

### Root Cause

GA100 HBM2e requires signal integrity initialization and row-remapper configuration at POST time. The HULK ucode performs row-remap table updates and HBM2e training; the DEVINIT PMU scripted sequencer initializes the HBM2e PHY timing. These results are not cryptographically verified by the ACR chain — they are stored as mutable runtime state in WPR.

### Attack Vectors

**HULK/DEVINIT Tampering**:
1. Attacker modifies HULK ucode in VBIOS (via SPI flash write or crafted VBIOS update)
2. HULK writes incorrect row-remap entries or HBM2e timing parameters
3. Results stored in WPR runtime state without ACR re-verification
4. Memory accesses use corrupted configuration

**Fault Injection During HBM2e Training**:
1. Attacker fault-injects during DEVINIT/HULK execution (EM pulse, laser)
2. HBM2e training algorithm computes incorrect parameters
3. Incorrect parameters stored in mutable WPR/DRAM state
4. Result: Bit flips, data corruption, or denial of service

### Impact

1. **Denial of Service**: Corrupted HBM2e configuration makes GPU unusable
2. **Data Corruption**: Bit flips in HBM2e memory if timing parameters are wrong
3. **Persistent Compromise**: Corrupted state survives re-use if stored in non-volatile WPR regions

### Exploitability Assessment

**Difficulty**: HIGH
- Requires VBIOS modification or physical fault injection
- Hardware-specific parameters; requires HBM2e PHY knowledge
- Not practical for remote exploitation without VBIOS flash access

### Files Involved
- VBIOS Image #2: `HULK_PROD` @ CMP 0x2FEA0 (16,240 B), `HULK_DBG` @ 0x2BEF4 (16,240 B), TargetID=5 (FBFalcon)
- VBIOS DEVINIT script (PMU scripted sequencer, VBIOS-embedded)
- `uproc/acr/src/acrshared/ampere/acr_war_functions_ga100_only.c` — `_acrCheckWprRangeWithRowRemapperReserveFB_GA100`, `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100`

---

## Vulnerability 5: Firmware Offset Validation Missing

### Severity: HIGH

### Location
**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c`  
**Field**: LSF `binOffset` and `binSize`

### Root Cause

LSF descriptor contains `binOffset` specifying where in the firmware image the actual binary begins. This offset is not validated against the firmware image size before being used, enabling reads beyond the firmware image boundary.

### Code Pattern

```c
// From acr_wpr_ctrl_ga10x.c
void load_firmware(uint8_t* firmware_image, uint32_t firmware_size) {
    LSF_Descriptor* lsf = parse_lsf_header(firmware_image);
    
    // CRITICAL: binOffset not validated
    uint32_t offset = lsf->binOffset;
    uint32_t size = lsf->binSize;
    
    uint8_t* binary_start = firmware_image + offset;
    
    // If offset + size > firmware_size, reads beyond image
    // Data comes from driver memory (untrusted)
    memcpy(wpr_allocation, binary_start, size);
}
```

### Attack Vectors

**Firmware Image Manipulation**:
1. Attacker crafts firmware image with:
   - `binOffset = 0x1000` (points beyond image)
   - `binSize = 0x10000` (read 64KB of data)
   - Valid signature (covers original payload)
2. ACR loads image, extracts offset/size without validation
3. Read operation accesses data beyond firmware image
4. Data comes from uninitialized driver memory
5. Random data written to WPR

**Arbitrary WPR Write**:
1. Craft multiple firmware images with different binOffsets
2. Each image reads from different memory location
3. ACR writes to WPR at specified allocation
4. Attacker can write arbitrary data to WPR through repeated loads
5. Corrupt Falcon firmware or keys in WPR

**Signature Bypass**:
1. Original firmware image is signed
2. LSF header is part of signed payload
3. Attacker modifies `binOffset` and `binSize` fields
4. **If not covered by signature**: Signature still valid
5. **Impact**: Signature protection bypassed for key metadata

### Impact

1. **Out-of-Bounds Read**: Access memory beyond firmware image
2. **WPR Corruption**: Write arbitrary data to secure region
3. **Information Disclosure**: Leak driver memory contents
4. **Signature Bypass**: Modify firmware loading behavior without new signature

### Exploitability Assessment

**Difficulty**: LOW
- No validation logic needed
- Direct field modification in LSF
- Straightforward binary crafting

**Likelihood**: HIGH
- Covers common parsing oversight
- No cryptographic protection needed
- Repeatable and controlled

### Proof-of-Concept Outline

```python
class OffsetValidationBypass:
    def __init__(self, firmware_image):
        # Parse original LSF
        self.lsf = parse_lsf(firmware_image)
        
        # Modify binOffset to point beyond image
        self.lsf.binOffset = len(firmware_image) + 0x1000
        self.lsf.binSize = 0x10000  # Read 64KB beyond image
        
        # Keep signature unchanged (still valid)
```

### Files Involved
- `acr_wpr_ctrl_ga10x.c` - LSF parsing and firmware loading
- `acr_wpr_ctrl_ga10x.c` - WPR allocation logic

---

## Vulnerability 6: HBM2e VREF Voltage Control Unchecked

### Severity: MEDIUM (hardware access required; DEVINIT/HULK path, not GDDR6)

> **CORRECTION**: `fbflcn_gddr_boot_time_training_ga100.c` does NOT exist. GA100 uses HBM2e; VREF adjustments for HBM2e are performed by the DEVINIT PMU script and HULK ucode embedded in the VBIOS. The code pattern below is pseudocode for illustrative purposes only — it does not reflect actual GA100 source.

### Location
**Target**: HULK ucode (FBFalcon, VBIOS Image #2) + DEVINIT PMU script — not a standalone Falcon ucode file  
**Hardware**: HBM2e PHY voltage reference (not GDDR6 VREF)

### Root Cause

HBM2e initialization adjusts voltage reference (VREF) to find the optimal operating point. The DEVINIT script / HULK ucode writes these values to the HBM2e PHY without external range validation from the ACR chain. Over-voltage or under-voltage parameters could cause hardware damage or signal integrity failures.

### Code Pattern (pseudocode only — actual behavior is in DEVINIT script byte-code)

```c
// Pseudocode — NOT from fbflcn_gddr_boot_time_training_ga100.c (file does not exist)
void adjust_vref(uint32_t vref_code) {
    // CRITICAL: No validation of vref_code against hardware limits
    
    // Write directly to hardware register
    mmio_write(VREF_CONTROL_REG, vref_code);
    
    // If vref_code is out of range:
    // - Over-voltage: damages memory chip, GPU components
    // - Under-voltage: causes errors, signal integrity issues
}
```

### Attack Vectors

**Voltage Extremes**:
1. Training algorithm receives corrupted parameters
2. Computes vref_code outside valid range
3. Hardware register accepts any value without validation
4. Over-voltage/under-voltage condition triggered
5. Memory damage or immediate errors

**Hardware Damage**:
1. Sustained over-voltage causes permanent damage
2. Accelerated aging of memory components
3. GPU becomes unusable after damage

**Side-Channel**:
1. Voltage adjustments have measurable power consumption
2. Different voltage configurations have different timing
3. Training parameters might leak memory configuration

### Impact

1. **Hardware Damage**: Permanent GPU failure
2. **Denial of Service**: GPU becomes unusable
3. **Information Disclosure**: Memory layout information
4. **Adversarial Testing**: Reveal hardware limits through extreme values

### Exploitability Assessment

**Difficulty**: MEDIUM
- Requires understanding hardware limits
- Requires fault injection or corrupted training state
- May require knowledge of safe voltage range

**Likelihood**: LOW
- Training typically produces reasonable values
- Requires unusual attack scenario to reach extremes
- Hardware safeguards may limit damage

### Files Involved
- VBIOS Image #2: `HULK_PROD` ucode (FBFalcon, TargetID=5) — HBM2e row-remap and timing (no `fbflcn_gddr_boot_time_training_ga100.c` exists)
- Hardware register definitions for HBM2e PHY VREF control

---

## Vulnerability 7: Integer Overflow in Dependency Map Iteration

### Severity: HIGH

### Location
**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c`  
**Function**: `_acrlibCheckDependency_v2()` loop  
**Operation**: `i * 2` multiplication in array indexing

### Root Cause

Loop index is multiplied by 2 to calculate array offset, but the multiplication is not checked for overflow. If `i` is large, `i * 2` wraps to small value, accessing wrong array location.

### Code Pattern

```c
// From acr_wpr_ctrl_ga10x.c
void process_dependency_map(uint8_t* depMap, uint32_t depCount) {
    for (uint32_t i = 0; i < depCount; i++) {
        // CRITICAL: i*2 can overflow if i > 0x80000000
        uint32_t offset = i * 2;
        uint8_t dep = depMap[offset];
        
        // Process dependency
    }
}
```

### Attack Vectors

**Integer Wrap-Around**:
1. Attacker sets `depCount = 0xFFFFFFFF` (maximum uint32)
2. Loop iterations increment `i` from 0 to 0xFFFFFFFF
3. When `i = 0x80000001`, `i * 2 = 0x00000002` (overflow)
4. Array access wraps to wrong location
5. Different memory location read

**Multi-Iteration Exploitation**:
```
i=0: offset = 0x0 ✓
i=1: offset = 0x2 ✓
...
i=0x7FFFFFFF: offset = 0xFFFFFFFE ✓
i=0x80000000: offset = 0x00000000 (WRAP - overlaps with beginning)
i=0x80000001: offset = 0x00000002 (WRAP)
```

**Information Disclosure**:
1. Overflow causes repeated memory reads
2. Attacker can read specific memory regions multiple times
3. By adjusting depCount, target different addresses

### Impact

1. **Arbitrary Memory Read**: Access any memory location through iteration
2. **Information Disclosure**: Leak GPU memory contents
3. **Denial of Service**: Large depCount values may cause hangs
4. **Exploit Chain**: Enable other attacks through leaked information

### Exploitability Assessment

**Difficulty**: MEDIUM
- Requires understanding of overflow behavior
- Needs crafted depCount and depMap values
- Iteration-based access is repeatable

**Likelihood**: MEDIUM
- Overflow vulnerability, but requires specific conditions
- Combined with bounds check bypass (Vuln #2)
- Can be chained for significant impact

### Proof-of-Concept Outline

```python
class IntegerOverflowExploit:
    def __init__(self):
        self.depCount = 0x90000000  # Large value
        self.depMap = [0xFF] * 0x1000  # Enough entries
        
    def exploit(self):
        # When i = 0x80000000:
        #   offset = 0x80000000 * 2 = 0x00000000 (overflow)
        # Accesses wrong memory location
```

### Files Involved
- `acr_wpr_ctrl_ga10x.c` - Loop implementation with overflow
- Loop condition and multiplication in dependency map processing

---

## Vulnerability 8: Version Rollback Possible Through Unvalidated Field

### Severity: MEDIUM

### Location
**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c`  
**Field**: LSF `binVersion`

### Root Cause

Firmware version field is extracted from LSF descriptor and stored in version tracking table without validation. No minimum version check prevents loading of older, vulnerable firmware.

### Code Pattern

```c
// From acr_wpr_ctrl_ga10x.c
void update_firmware_version(LSF_Descriptor* lsf) {
    uint16_t newVersion = lsf->binVersion;
    
    // CRITICAL: No minimum version check
    // No verification that newVersion >= MINIMUM_VERSION
    
    // Write directly to version table
    g_versionTable[FIRMWARE_INDEX] = newVersion;
}
```

### Attack Vectors

**Known Vulnerability Loading**:
1. Security update released: Version 100 patches vulnerability
2. Attacker crafts firmware with version number 50
3. Bootloader checks only for rollback to PREVIOUS version
4. Version 50 < 100, but no minimum check
5. Vulnerable firmware version 50 loads
6. Known vulnerability executes

**Selective Regression**:
1. Different firmware components have different versions
2. Attacker can selectively downgrade specific components
3. Mix old and new firmware to cause incompatibility
4. Exploit known vulnerabilities in old components

### Impact

1. **Vulnerable Firmware Execution**: Run known-vulnerable code
2. **Security Regression**: Bypass security patches
3. **Selective Downgrade**: Mix compatible and incompatible versions
4. **Extended Attack Window**: Exploit patched vulnerabilities

### Exploitability Assessment

**Difficulty**: LOW
- Requires only modifying version field
- Straightforward to craft LSF with old version number
- No validation logic to bypass

**Likelihood**: MEDIUM
- Requires knowledge of vulnerability history
- Need to identify vulnerable versions
- Practical if historical vulnerabilities known

### Proof-of-Concept Outline

```python
class VersionRollbackExploit:
    def __init__(self):
        # Current version: 100
        # Vulnerable version: 50 (known vulnerability in feature X)
        
        self.lsf = LSF_Descriptor()
        self.lsf.binVersion = 50  # Rollback to vulnerable version
        
        # No minimum version check, so this bypasses protection
```

### Files Involved
- `acr_wpr_ctrl_ga10x.c` - Version field handling
- Version table storage location

---

## Exploitation Strategy

### Single Vulnerabilities
Each vulnerability can be exploited individually for limited impact:
- Vuln #1 (SMC instance): Arbitrary MMIO write
- Vuln #2 (depMap bounds): Out-of-bounds read
- Vuln #3 (AES key): Firmware reverse engineering
- etc.

### Vulnerability Chaining

**Chain 1: SMC + DMA Misdirection**
```
Exploit Vuln #1 (SMC instance not validated)
→ Direct MMIO write to DMA configuration
→ Configure DMA to read/write arbitrary memory
→ Gain control of firmware image loading
```

**Chain 2: depMap + Integer Overflow**
```
Exploit Vuln #2 (depMap bounds) + Vuln #7 (integer overflow)
→ Read arbitrary memory through overflow
→ Leak version table addresses
→ Corrupt version entries (Vuln #8)
→ Enable version rollback
```

**Chain 3: Offset + WPR Corruption**
```
Exploit Vuln #5 (offset validation missing)
→ Read beyond firmware image boundary
→ Write arbitrary data to WPR allocation
→ Corrupt Falcon firmware or keys
→ Achieve persistent firmware compromise
```

---

## Summary Table

| Vuln | Type | Severity | Component | Validation | Exploitable |
|------|------|----------|-----------|-----------|-------------|
| 1 | Register addressing | CRITICAL | DMA setup | No | YES |
| 2 | Array bounds | CRITICAL | depMap | No | YES |
| 3 | Key source | CRITICAL | AES decrypt | Unknown | YES (if hardcoded) |
| 4 | State verification | HIGH | Memory training | No | YES (with fault injection) |
| 5 | Offset validation | HIGH | LSF parsing | No | YES |
| 6 | Range validation | MEDIUM | VREF control | No | YES (with fault injection) |
| 7 | Integer overflow | HIGH | Loop iteration | No | YES |
| 8 | Version check | MEDIUM | Version tracking | Partial | YES |

---

## Next Steps

1. **Binary Analysis**:
   - Extract vulnerability code from prebuilt firmware
   - Confirm all assumptions in actual binary
   - Identify exact register addresses for SMC/DMA

2. **Exploitation Development**:
   - Develop proof-of-concept for each vulnerability
   - Test vulnerability chaining strategies
   - Validate impact of each attack

3. **Impact Assessment**:
   - Determine realistic exploitation difficulty
   - Identify practical attack scenarios
   - Document mitigation strategies

