# 2.2 — Firmware Containers: WPR and LSF Format

## Overview

The GA100 secure boot uses two critical data structures to manage firmware integrity:

1. **WPR (Write-Protected Region)**: GPU DRAM region containing sensitive firmware and cryptographic keys
2. **LSF (Load-Safe Format v2)**: Firmware image descriptor with embedded signatures and encryption metadata

Together, these structures implement the trust model where firmware binaries can be authenticated, encrypted, and safely loaded into GPU DRAM before Falcon execution.

---

## Write-Protected Region (WPR) Architecture

### Purpose
- Isolate firmware and cryptographic keys from untrusted driver code
- Prevent modification of verified firmware after signature check
- Store sensitive runtime state (memory training results, key material)
- Implement hardware-enforced read/write protection

### Physical Layout

```
GPU DRAM Layout (Simplified):
┌─────────────────────────────────────┐
│  Driver Memory (Untrusted)          │
├─────────────────────────────────────┤
│  WPR Start                          │
├─────────────────────────────────────┤
│  ACR Firmware                       │
├─────────────────────────────────────┤
│  Falcon Firmware                    │
├─────────────────────────────────────┤
│  GSP Firmware (RISC-V)              │
├─────────────────────────────────────┤
│  Cryptographic Keys                 │
├─────────────────────────────────────┤
│  Runtime State (Training Results)   │
├─────────────────────────────────────┤
│  WPR End                            │
├─────────────────────────────────────┤
│  Driver Memory (Untrusted)          │
└─────────────────────────────────────┘
```

### WPR Initialization Process

**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c`

1. **Allocation Phase**:
   - Calculate total WPR size needed
   - Allocate contiguous DRAM region
   - Align to hardware page boundaries

2. **Layout Phase**:
   - Assign firmware images to specific WPR offsets
   - Reserve space for keys and runtime state
   - Document offset for each sub-region (Sub-WPR)

3. **Load Phase**:
   - Copy verified firmware into WPR at assigned offset
   - Load RSA signature keys into WPR
   - Load AES decryption keys (if encrypted firmware)

4. **Lock Phase**:
   - Set write-protection on WPR address range
   - Configure FECS to prevent driver access
   - Lock configuration (prevent re-allocation)

### Sub-WPR Structure

Each WPR contains multiple sub-regions:

| Sub-WPR | Contents | Size | Access |
|---------|----------|------|--------|
| ACR | Bootloader firmware | Variable | Falcon only |
| Falcon | Memory management firmware | Variable | Falcon execution |
| GSP | GPU System Processor (RISC-V) | Variable | GSP execution |
| PMU | Power Management Unit (RISC-V) | Variable | PMU execution |
| SEC | Security Processor (RISC-V) | Variable | SEC execution |
| Keys | RSA public keys, AES keys | Fixed | Never readable |
| State | Runtime state, counters, flags | Variable | Falcon R/W |

### Protection Mechanisms

**Write Protection**:
- Hardware write-protect register prevents modifications
- Spans WPR address range
- ~~Cannot be disabled without full reset~~ **CORRECTION:** The ACR Unload path (`acrUnloadACR_TU10X`) explicitly clears `NV_PFB_PRI_MMU_WPR_ALLOW_READ/WRITE._WPR1` to `0x0` (all levels denied) and sets all sub-WPR access masks to `RMASK=0x0, WMASK=0x0` without requiring a GPU reset. WPR MMU registers can be reprogrammed by any HS (L3) code while the GPU is running. See `6-3-wpr-hardware-lockdown.md` §2.3.

**Read Protection** (Limited):
- Driver cannot read WPR contents
- Falcon firmware can read its own regions
- GSP/PMU/SEC have isolated read access

**Critical Gap**: Write-protection doesn't prevent relocation if offset calculation is mutable

---

## Load-Safe Format (LSF v2) Parsing

### Purpose
- Package firmware image with signature and encryption metadata
- Enable secure boot-time loading and verification
- Support encrypted firmware for confidentiality

### LSF Structure

```c
// Simplified LSF v2 structure
typedef struct {
    uint32_t signature[384/4];      // RSA-3072 signature (384 bytes)
    uint32_t binSize;               // Size of binary payload
    uint32_t binOffset;             // Offset to binary data in image
    uint16_t binVersion;            // Firmware version (anti-rollback)
    uint16_t binFlags;              // Encryption, compression flags
    uint8_t  depMap[...];           // Dependency map for loading order
    uint32_t depCount;              // Number of dependencies
    uint32_t aesKeyIdx;             // Index of AES key for decryption
} LSF_Descriptor;
```

### Parsing Flow

**File**: `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c`

1. **Header Parsing**:
   ```
   Parse LSF header from firmware image
   ├─ Validate signature field is present
   ├─ Extract binary size (binSize)
   ├─ Extract binary offset (binOffset)
   ├─ Extract firmware version (binVersion)
   └─ Extract encryption metadata (binFlags, aesKeyIdx)
   ```

2. **Signature Verification**:
   ```
   Verify RSA-3072 signature
   ├─ Extract signature from LSF header
   ├─ Hash binary payload with SHA-256
   ├─ RSA verify against NVIDIA public key
   ├─ Compare result against stored signature
   └─ Proceed only if verification succeeds
   ```

3. **Dependency Resolution** (Anti-Rollback):
   ```
   Check firmware version against dependency map
   ├─ For each dependency in depMap:
   │  ├─ Get dependency firmware index (depfalconId)
   │  ├─ Look up current version in runtime state
   │  ├─ Verify new firmware version >= current version
   │  └─ Update runtime state with new version
   └─ Reject if any version is older (rollback attempt)
   ```

   **Critical Vulnerability**: Array access without bounds checking
   - `depfalconId` used directly as array index
   - No validation that `depfalconId` < dependency map size
   - Out-of-bounds read possible

4. **Authentication** (LS signature verification):
   ```
   Authenticate binary payload via AES-DM + KDF + SCP slot 43
   ├─ Compute AES-DM (Davies-Meyer) hash over 16-byte blocks via SCP
   ├─ Derive per-falcon key: AES-ECB(key=SCP_slot43, plain=g_kdfSalt XOR falconId)
   ├─ Compute sig: AES-ECB(key=derivedKey, plain=dmHash)
   └─ Compare against stored 16-byte signature in LSB header
   ```
   > **CORRECTION (/4):** Original analysis assumed AES-CBC here. **GA100 does not use AES-CBC for LS authentication.** The AES-CBC path (`acr_decrypt_ls_ucode_ga10x.c`) is GA10X+ only and is confirmed absent from GA100 production AHESASC binary. See `6-1-crypto-auth-chain-map.md` §5 and `6-2-verification-state-machine.md` §3.7.

5. **WPR Allocation**:
   ```
   Allocate WPR space for firmware image
   ├─ Calculate total size (binSize)
   ├─ Check available WPR space
   ├─ Allocate at next available offset
   ├─ Store offset for later reference
   └─ Write firmware binary to allocated location
   ```

   **Critical Vulnerability**: Offset not validated
   - LSF can specify arbitrary binOffset
   - No bounds checking against firmware image size
   - Potential to write outside allocated region

### Encryption Metadata

**LS Authentication (GA100 actual):**
- **CORRECTION:** GA100 does not use AES-CBC. Authentication is AES-DM + KDF (see above).
- `aesKeyIdx` field in the LSF descriptor is not used on this path; the key is derived from SCP hardware slot 43 (a manufacturing-time secret, same value across all GA100 dies).
- The KDF salt `g_kdfSalt = {B6 C2 31 E9 03 B2 77 D7 0E 32 A0 69 8F 4E 80 62}` is a public value embedded unencrypted in the signed AHESASC binary.

**Key Storage (resolved, /4):**
- LS authentication root key = SCP hardware slot 43, loaded via `falc_scp_secret(0x2B, SCP_R2)` (binary-confirmed: opcode `cci 0xc2b2` in AHESASC). This is a die-level secret burned at manufacturing — **not software-readable**.
- ~~Question: Are keys hardcoded or derived per-GPU?~~ **ANSWERED:** Key is derived via KDF from SCP slot 43. The slot 43 secret is shared across all GA100 dies (not per-GPU). Compromise of one die's SCP secret enables LS signature forgery across all GA100s (W-3). See `6-1-crypto-auth-chain-map.md` §5.6.

---

## Vulnerability Analysis

### 1. Dependency Map Array Bounds Violation

**Location**: `acr_wpr_ctrl_ga10x.c` in `_acrlibCheckDependency_v2()`

**Issue**: Direct array indexing without validation
```c
// Pseudocode representation
for (int i = 0; i < depCount; i++) {
    uint8_t depfalconId = depMap[i];
    uint32_t currentVersion = versionTable[depfalconId];  // ← Unchecked index
    if (currentVersion < newVersion) {
        reject();  // Rollback detected
    }
}
```

**Vulnerability**:
- `depfalconId` extracted from firmware image (untrusted)
- No validation that `depfalconId < MAX_FALCON_INSTANCES`
- Array `versionTable[]` can be read out-of-bounds
- Information disclosure: Leak version state or other data

**Exploitability**: HIGH
- Can be combined with integer overflow to reach arbitrary memory
- Enables information disclosure for other vulnerabilities

### 2. Version Rollback Through Unvalidated Field

**Location**: `acr_wpr_ctrl_ga10x.c`

**Issue**: binVersion field not validated against minimum version

**Vulnerability**:
- `binVersion` extracted from LSF descriptor (untrusted)
- Written directly to version tracking table
- No check for minimum required version
- No cryptographic binding between version and firmware content

**Scenario**:
1. Version 100 firmware released with security fix
2. Attacker crafts firmware image with `binVersion = 50`
3. Bootloader loads firmware without version validation
4. Vulnerable version 50 code executes

**Exploitability**: HIGH
- Enables loading of known-vulnerable firmware versions
- Bypasses anti-rollback mechanism entirely

### 3. LSF Offset Validation Missing

**Location**: `acr_wpr_ctrl_ga10x.c`

**Issue**: `binOffset` not validated against firmware image size

**Vulnerability**:
```c
// Pseudocode
LSF_Descriptor* lsf = parseLSF(firmware_image);
uint32_t offset = lsf->binOffset;
uint8_t* binary = firmware_image + offset;  // ← No bounds check
memcpy(wpr_region, binary, lsf->binSize);  // ← Potential overflow
```

**Scenarios**:
1. `binOffset` points beyond firmware image end
2. `binOffset + binSize` overflows
3. `binSize` specifies more data than available
4. Reads from uninitialized memory and writes to WPR

**Exploitability**: MEDIUM
- Enables arbitrary WPR write location
- Requires other vulnerabilities to achieve full impact
- Can corrupt Falcon firmware or key material

### 4. Integer Overflow in Dependency Map Iteration

**Location**: `acr_wpr_ctrl_ga10x.c`

**Issue**: Loop index multiplication can overflow
```c
for (int i = 0; i < depCount; i++) {
    uint32_t offset = i * 2;  // ← Can overflow
    uint8_t dep = depMap[offset];
}
```

**Vulnerability**:
- `i * 2` can wrap around if `i` is large
- Accesses unintended memory locations
- Can read arbitrary data from GPU DRAM

**Exploitability**: MEDIUM
- Limited by `depCount` validation
- Enables arbitrary memory read when combined with bounds bypass

### 5. AES Key Source Unknown

**Location**: `acr_decrypt_ls_ucode_ga100.c`

**Issue**: Key derivation method not documented in source

**Vulnerability**:
- If keys are hardcoded, all GA100s share same encryption key
- Encrypted firmware becomes effectively plaintext
- Enables firmware decryption for reverse engineering
- **Unknown**: Whether key is hardcoded or derived per-GPU

**Investigation Required**:
- Binary analysis of prebuilt firmware
- Check for key derivation function vs. hardcoded values
- Determine if key material is in WPR or elsewhere

---

## Memory Layout Mutations

### Post-Verification Mutations

After signature verification completes, WPR allocation can still be modified through:

1. **Runtime Relocation**:
   - Firmware loaded at offset X after verification
   - Falcon can relocate firmware to offset Y
   - Re-verification not performed on relocated image
   - Payload interpretation changes based on offset

2. **Sub-WPR Corruption**:
   - Multiple firmware images share WPR
   - One corrupted image affects others
   - No isolation between sub-WPRs

3. **Runtime State Mutation**:
   - Training results stored in mutable WPR region
   - Falcon can modify without re-verification
   - Affects subsequent firmware execution

### Attack Scenario: Firmware Relocation

```
Initial State:
WPR[0x0000-0x4FFF]: Valid Falcon firmware (signature verified)

Attack:
1. Modify firmware metadata post-verification
2. Instruct Falcon to relocate firmware to WPR[0x1000]
3. Falcon executes relocated code without re-verification
4. Payload interpretation changes due to offset

Result: Code execution with different semantics
```

---

## Investigation Checklist

- [ ] Trace WPR allocation algorithm in `acr_wpr_ctrl_ga10x.c`
- [ ] Verify all LSF header fields are validated
- [ ] Check bounds on `depMap` array access
- [ ] Confirm `binOffset` and `binSize` validation
- [ ] Determine AES key source (hardcoded vs. derived)
- [ ] Map all post-verification firmware mutations
- [ ] Identify firmware relocation code in Falcon
- [ ] Document anti-rollback mechanism completely
- [ ] Extract LSF parser from bootloader binary

---

## Key Questions

**Q1**: Is the AES encryption key hardcoded across all GA100s?  
**A1**: UNKNOWN - Requires binary analysis to determine key source

**Q2**: Can LSF offset values cause reads/writes outside firmware image?  
**A2**: YES - No visible validation of offset against image size

**Q3**: Can dependency map array be exploited out-of-bounds?  
**A3**: YES - Direct array indexing without bounds check on untrusted `depfalconId`

**Q4**: Can firmware be relocated after verification without re-verification?  
**A4**: LIKELY - Evidence suggests WPR allocation is mutable

**Q5**: Are all LSF header fields validated before use?  
**A5**: NO - Evidence of missing validation on offset, version, and index fields

---

## Next Steps

1. **Binary Analysis**:
   - Extract LSF parser from bootloader binary
   - Trace AES key storage location
   - Map WPR allocation algorithm

2. **Vulnerability Confirmation**:
   - Craft malicious LSF with out-of-bounds offset
   - Test dependency map bounds bypass
   - Attempt firmware relocation

3. **Exploitation Development**:
   - Develop exploit chain using multiple vulnerabilities
   - Chain bounds violations for arbitrary memory read
   - Corrupt firmware or key material

