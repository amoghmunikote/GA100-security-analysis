# Post-Verification Mutations - Runtime State Corruption

## Overview

A critical assumption in GA100's secure boot model: **Firmware metadata remains immutable and trustworthy after cryptographic signature verification**. This analysis documents multiple post-verification mutation paths that enable compromise of verified firmware without breaking RSA signatures.

---

## Trust Model Gap

### Expected Trust Flow

```
Boot ROM
  ↓ (Verify signature)
ACR Bootloader
  ↓ (Signature valid - firmware trusted)
  ↓ (Immutable from this point)
Falcon Execution
  ↓ (No further modifications)
GPU Runtime
```

### Actual Trust Flow (With Gaps)

```
Boot ROM
  ↓ (Verify signature)
ACR Bootloader
  ↓ (Signature valid)
  ↓ (BUT: Post-verification window exists)
  ├─ Firmware loaded to WPR
  ├─ WPR allocated at runtime address
  ├─ Falcon code can be relocated
  ├─ Metadata fields are mutable
  ├─ Runtime state can be corrupted
  └─ No re-verification of modifications
  ↓
Falcon Execution
  ↓ (May be executing corrupted code)
GPU Runtime
```

---

## Post-Verification Mutation Window

### Timeline

```
T0: Bootloader receives firmware image
T1: Signature verification starts
T2: Signature verification completes (SUCCESS)
T3: ← MUTATION WINDOW OPENS
T4: Firmware loaded to WPR
T5: WPR allocation decided
T6: Firmware relocatable/reinterpretable
T7: Metadata fields written without re-verification
T8: Falcon execution begins
T9: ← MUTATION WINDOW CLOSES
```

### Window Duration

**Duration**: T2 to T8 (potentially dozens of cycles)  
**Attacker Action**: Modify firmware or metadata during this window  
**Recovery**: No re-verification until next boot

---

## Mutation Path 1: WPR Relocation

### Scenario

```c
// After signature verification
Firmware verified at offset X in firmware image
Loaded to WPR at address Y
WPR allocation decides final address

// Problem: WPR allocation is post-verification step
void allocate_wpr(uint8_t* firmware, uint32_t* allocated_address) {
    // 1. Firmware already verified
    // 2. Signature proof is complete
    
    // 3. BUT: Find allocation address
    *allocated_address = find_free_wpr_space();
    
    // 4. No re-verification of firmware
    // 5. Relocation can cause re-interpretation of instructions
}
```

### Attack: Instruction Re-Interpretation

```
Original firmware:
Offset 0x0000: Instruction A
Offset 0x0004: Instruction B
Offset 0x0008: Instruction C

If loaded at address 0x0000:
PC=0x0000 → Instruction A
PC=0x0004 → Instruction B
PC=0x0008 → Instruction C

If relocated to address 0x0002:
(Offset shifted by 2 bytes)

Data that was:
Offset 0x0002 (Instruction B's second byte) is now an instruction
Creates gadget: Modified_B'

Result: Different execution sequence due to offset change
```

### Real-World Impact

```
Scenario: Firmware relocation during boot
1. Firmware intended for WPR offset 0x0000 loaded at 0x4000
2. Firmware image contains overlapping code/data
3. When executed at different offset, instruction boundaries shift
4. Partial instructions become full instructions
5. Unintended gadgets create privilege escalation
6. Or security checks are bypassed
```

---

## Mutation Path 2: Firmware Metadata Modification

### Metadata Fields

```c
typedef struct {
    uint32_t signature[384/4];      // RSA signature (signed)
    uint32_t binSize;               // Firmware size (not signed!)
    uint32_t binOffset;             // Firmware offset (not signed!)
    uint16_t binVersion;            // Firmware version (not signed!)
    uint16_t binFlags;              // Encryption flags (not signed!)
    uint8_t depMap[];               // Dependency map (not signed!)
} LSF_Header;

// CRITICAL: Only signature field is cryptographically protected
// Metadata fields MAY NOT be covered by signature
```

### Attack: Modify Unprotected Fields

**If signature covers only code payload**:
```
Signed portion: Binary code (0x1000 - 0x5FFF)

Unsigned portion: 
├─ binSize (can be modified post-verification)
├─ binOffset (can be modified post-verification)
├─ binVersion (can be modified post-verification)
├─ binFlags (can be modified post-verification)
└─ depMap (can be modified post-verification)

Attack:
1. Firmware loads successfully (signature valid)
2. Modify binSize or binOffset after verification
3. Firmware is re-interpreted at different location
4. Different code executes
5. No signature check on modification
```

### Attack: Version Downgrade

```
Current state after verification:
- binVersion = 100

Post-verification modification:
- Write binVersion = 50 (older version)

Next boot:
- Bootloader reads binVersion = 50
- Loads vulnerable code (version 50)
- Security regression

No re-verification because metadata change happened post-verification
```

---

## Mutation Path 3: WPR Corruption After Lock

### WPR Lock Mechanism

```c
// After firmware loading, WPR should be locked
void lock_wpr(void) {
    // Set write-protection on WPR address range
    uint32_t ctrl = mmio_read(WPR_PROTECT_REG);
    ctrl |= WPR_WRITE_PROTECT_ENABLE;
    mmio_write(WPR_PROTECT_REG, ctrl);
    
    // Firmware now read-only
}
```

### Gap: Read-Only vs. Write-Protected

**Write-Protected**: Cannot modify WPR (hardware enforces)  
**Read-Protected**: Cannot read WPR (hardware enforces)

**Gap**: WPR write-protected but not read-protected

```
Falcon firmware (executing in WPR):
├─ Can read own WPR region
├─ Can read other firmware in WPR
├─ Cannot write WPR (protected)
└─ Cannot be detected modifying WPR

But what if:
- Falcon exploited to execute arbitrary code
- Arbitrary code (running in supervisor mode)
- CAN modify WPR through different mechanism
- Or bypass write-protection through privilege escalation
```

### Attack: Supervisor-Mode WPR Corruption

```
1. Falcon firmware has privilege escalation bug
2. Exploit bug to reach supervisor mode
3. Supervisor mode can disable write-protection
4. Corrupt firmware in WPR
5. Re-enable write-protection
6. Continue execution with corrupted firmware
7. Corruption persists across reset (in WPR)
```

---

## Mutation Path 4: Runtime State Corruption

### Mutable State Regions

```
WPR Layout Post-Verification:
┌──────────────────────────────┐
│ Firmware (write-protected)   │
├──────────────────────────────┤
│ Keys (read-protected)        │
├──────────────────────────────┤
│ Training State (mutable!)    │ ← Falcon can modify
├──────────────────────────────┤
│ Version Tracking (mutable!)  │ ← Falcon can modify
├──────────────────────────────┤
│ Configuration (mutable!)     │ ← Falcon can modify
└──────────────────────────────┘
```

### Attack: Dependency Map Corruption

```
Training state:
├─ version[0] = 100
├─ version[1] = 100
├─ version[2] = 100

Falcon corrupts dependency map:
├─ Write version[0] = 50 (downgrade)
├─ Write version[1] = 50
├─ Write version[2] = 50

Next component load:
├─ Checks dependency versions
├─ Sees version 50 (downgraded by Falcon)
├─ Loads corresponding component version
├─ Vulnerable code executes
```

### Attack: Configuration Poisoning

```
Configuration state:
├─ SMC instance count = 4
├─ Memory partition size = 4GB
├─ Clock frequency = 1.5 GHz

Malicious Falcon modifies:
├─ SMC instance count = 0 (disable isolation)
├─ Memory partition size = 0 (disable partition)
├─ Clock frequency = max (stress hardware)

Result:
├─ Isolation disabled
├─ All instances can access all memory
├─ Hardware overstressed
└─ System malfunction
```

---

## Mutation Path 5: Attestation Bypass

### Attestation Expectation

GPU supports attestation: prove to external party that firmware is unmodified

```
Attestation Flow:
1. External verifier asks GPU for proof
2. GPU returns firmware hash + signature
3. Verifier checks signature
4. Verifier confirms firmware is genuine

Expected security:
├─ Hash computed from actual firmware
├─ Signature proves authenticity
└─ Any modification detected

Vulnerability:
├─ Hash computed from WPR (mutable post-verification)
├─ If firmware in WPR is corrupted, hash is wrong
├─ But GPU reports corrupted hash as valid
└─ Attestation fails to detect corruption
```

### Attack: Attestation Evasion

```
1. Firmware boots successfully (verified)
2. Attacker modifies firmware in WPR post-verification
3. Attestation triggered by verifier
4. GPU reads corrupted firmware from WPR
5. Computes hash of corrupted firmware
6. Signatures match (signature is of corrupted firmware)
7. Verifier accepts corrupted firmware as valid
8. Malicious modifications go undetected
```

---

## Mutation Path 6: Recovery/Reset Escape

### Reset Mechanism

Expected behavior:
```
GPU Reset
  ├─ Clears all runtime state
  ├─ Clears all WPR (or loads from non-mutable source)
  ├─ Returns to known-good state
  └─ Attestation would pass
```

### Gap: Non-Volatile Persistence

If WPR is non-volatile (persists across reset):
```
1. Firmware compromised in WPR
2. Corruption stored persistently
3. GPU reset commanded
4. Reset clears DRAM but not WPR
5. Boot loads WPR again
6. Corrupted firmware loaded again
7. Same compromised state
8. No reset recovery possible
```

### Attack: Persistent Compromise

```
1. Exploit vulnerability to corrupt WPR firmware
2. Disable any detection/reporting
3. Reset GPU (appears to have no effect)
4. GPU boots with corrupted firmware
5. Compromise persists indefinitely
6. Undetectable without binary comparison
```

---

## Mutation Path 7: SMC/MIG Boundary Corruption

### Instance Isolation State

```
SMC Configuration:
├─ Instance 0: Enabled, 256MB memory
├─ Instance 1: Enabled, 256MB memory
├─ Instance 2: Enabled, 256MB memory
├─ Instance 3: Enabled, 256MB memory
└─ Isolation enforced between instances

Attack: Corrupt configuration
├─ Disable isolation between instances
├─ Instance 0 can now access Instance 1's memory
├─ Instance 1 unaware of boundary violation
├─ Complete information disclosure possible
```

### Attack: Isolation Disable

```
1. Compromise supervisor mode
2. Modify SMC configuration registers
3. Disable instance isolation
4. All instances become visible to each other
5. Cross-instance attacks become possible
6. DMA misdirection enabled
```

---

## Exploitation Chain: Complete Compromise

### Attack Sequence

```
Stage 1: Initial Exploit
├─ Use firmware parsing vulnerability (Vuln #2,5)
└─ Achieve out-of-bounds memory read

Stage 2: Privilege Escalation
├─ Use memory read to locate gadgets
├─ Trigger exception with crafted stack
├─ Jump to ROP gadget chain
└─ Reach supervisor mode

Stage 3: Post-Verification Corruption
├─ Supervisor code disables write-protection
├─ Modify firmware in WPR (mutation path #3)
├─ Install backdoor/disabler
└─ Re-enable write-protection

Stage 4: Disable Security Features
├─ Modify configuration in WPR (mutation path #4)
├─ Disable SMC isolation
├─ Disable training state verification
├─ Disable dependency map checking
└─ Disable all attestation reporting

Stage 5: Persistent Compromise
├─ Firmware now compromised in WPR
├─ Configuration disabled all detection
├─ Isolation boundaries disabled
├─ Reset won't fix (WPR persists)
└─ Compromise undetectable

Stage 6: Maintain Access
├─ Hide compromise from host driver
├─ Report fake attestation
├─ Intercept security-related operations
├─ Maintain persistent backdoor
└─ Full GPU control achieved
```

---

## Detection and Prevention

### What Should Be Done

**Signature Coverage**:
- [ ] Include all metadata fields in signature
- [ ] Sign all mutable state
- [ ] Use authenticated encryption

**Post-Verification Verification**:
- [ ] Re-verify firmware before execution
- [ ] Check relocation impact on code
- [ ] Validate all metadata fields

**WPR Protection**:
- [ ] Read-protect WPR (not just write-protect)
- [ ] Detect any WPR modification
- [ ] Use hardware attestation

**Recovery Mechanism**:
- [ ] Store original firmware in read-only region
- [ ] Reload firmware on reset/mismatch
- [ ] Make WPR volatile (clear on reset)

### Current Implementation

```c
// Observed in acr_wpr_ctrl_ga10x.c
void load_and_verify_firmware(uint8_t* firmware_image) {
    // 1. Verify signature
    if (!verify_signature(firmware_image)) {
        return ERROR;
    }
    
    // 2. MUTATION WINDOW OPENS HERE
    
    // 3. Allocate WPR (post-verification)
    uint32_t wpr_address = allocate_wpr();
    
    // 4. Load firmware (post-verification)
    copy_to_wpr(firmware_image, wpr_address);
    
    // 5. Apply runtime metadata (post-verification, no re-check)
    apply_metadata(firmware_image);
    
    // 6. MUTATION WINDOW CLOSES
    
    // 7. Execute firmware
    return SUCCESS;
}

// Gap: Metadata modification possible between steps 1 and 7
// No re-verification of modifications
```

---

## Investigation Checklist

- [ ] Identify signature coverage in LSF descriptor
- [ ] Map WPR allocation algorithm
- [ ] Test firmware relocation impact
- [ ] Verify metadata modification possible
- [ ] Test WPR write-protection enforcement
- [ ] Test WPR read-protection (likely missing)
- [ ] Check attestation implementation
- [ ] Analyze reset/recovery procedures
- [ ] Document all post-verification windows
- [ ] Identify corruption detection methods (should be missing)

---

## Key Questions

**Q1**: Does signature cover all metadata fields?  
**A1**: UNKNOWN - Requires signature analysis; likely incomplete

**Q2**: Can WPR be modified after write-protection is enabled?  
**A2**: LIKELY - Write-protection in software may be bypassable via supervisor escalation

**Q3**: Is WPR read-protected from firmware?  
**A3**: LIKELY NOT - Only write-protected, firmware can read and report

**Q4**: Can attestation detect post-verification corruption?  
**A4**: NO - Attestation uses corrupted WPR as source of truth

**Q5**: Is there a recovery mechanism from persistent WPR corruption?  
**A5**: UNKNOWN - Depends on firmware reset procedures

---

## Impact Summary

Post-verification mutations enable:
- [ ] Arbitrary firmware modification without RSA break
- [ ] Persistent compromise surviving reset
- [ ] Undetectable attestation evasion
- [ ] Complete isolation boundary bypass
- [ ] Privilege escalation without cryptographic break
- [ ] Indefinite GPU control

**Severity**: CRITICAL - Renders signature verification ineffective

---

## Next Steps

1. **Signature Analysis**:
   - Extract LSF signature verification code
   - Determine exact fields covered by signature
   - Identify post-verification mutation windows

2. **WPR Protection Testing**:
   - Test write-protection enforcement
   - Test read-protection availability
   - Verify corruption detection

3. **Exploitation Development**:
   - Develop post-verification mutation proof-of-concept
   - Test persistent WPR corruption
   - Verify reset recovery failure
   - Test attestation bypass

