# 1.2 — Reverse Engineering Methodology and Targets

## Overview

Complete source code analysis has identified vulnerabilities in firmware architecture and security logic. To confirm exploitability and develop practical attacks, binary reverse engineering is required on the prebuilt GA100 firmware artifacts in the archive.

This document provides a systematic roadmap for binary analysis.

---

## Prebuilt Firmware Artifacts

### Location
```
workspace/integ/gpu_drv/stage_rel/uproc/nvriscv/prebuilt/
```

### Artifacts Available

**File**: `basic-ga100-gsp` (GPU System Processor - RISC-V)
- Size: ~200KB
- Architecture: RISC-V
- Purpose: Boot management, clock control
- Vulnerability Interest: Medium

**File**: `basic-ga100-pmu` (Power Management Unit - RISC-V)
- Size: ~100KB
- Architecture: RISC-V
- Purpose: Power management, throttling
- Vulnerability Interest: Low

**File**: `basic-ga100-sec` (Security Processor - RISC-V)
- Size: ~150KB
- Architecture: RISC-V
- Purpose: Cryptographic operations, security enforcement
- Vulnerability Interest: CRITICAL

### Prebuilt Binary Analysis Difficulty

**RISC-V Artifacts**: Medium difficulty
- RISC-V ISA well-documented
- Fewer gadgets than x86
- Disassembly tools mature (Ghidra, IDA)
- Relatively straightforward analysis

---

## Critical Reverse Engineering Targets

### Target 1: AES Key Derivation (Vuln #3)

**Objective**: Determine if AES encryption key is hardcoded or derived

**Location**: `basic-ga100-sec` firmware

**Strategy**:

1. **Disassemble the binary**:
   ```
   Load basic-ga100-sec into Ghidra
   Apply RISC-V processor definition
   Auto-analyze
   ```

2. **Search for AES-related functions**:
   - Search for "aes" string references
   - Look for AES round constants (0x01, 0x02, 0x04, 0x08, 0x10, etc.)
   - Find AES sbox references (256-byte tables)

3. **Trace AES key loading**:
   ```
   Find: aes_encrypt() or decrypt_block()
   Trace backwards from function call
   Identify:
   ├─ Key source (hardcoded vs. derived)
   ├─ Key storage location
   ├─ Key derivation algorithm (if used)
   └─ Key size (128-bit, 256-bit, etc.)
   ```

4. **Hardcoded Key Search**:
   - Search binary for 32-byte aligned constant data
   - Look for patterns: potential keys
   - Verify against AES known plaintexts
   - Test decryption of known encrypted firmware

5. **Derived Key Analysis**:
   - Look for PRNG or KDF functions
   - Identify input parameters (GPU ID, fuses, etc.)
   - Trace derivation algorithm
   - Determine reproducibility across GPUs

**Success Criteria**:
- [ ] AES key source identified
- [ ] If hardcoded, key extracted
- [ ] If derived, derivation method understood
- [ ] Practical impact assessed

**Expected Outcome**: CRITICAL
- If hardcoded: All encrypted firmware easily decrypted
- If weak derivation: Brute-force or side-channel attack feasible

---

### Target 2: Falcon ISA and Privilege Boundaries (Vuln #6)

**Objective**: Extract Falcon instruction set and identify privilege escalation gadgets

**Location**: Falcon firmware (not in prebuilt, extract from driver or reverse engineer)

**Strategy**:

1. **Locate Falcon Firmware**:
   - Check ACR bootloader for embedded Falcon code
   - Search driver memory for Falcon images
   - Extract from WPR if accessible
   - Recover from debug symbols (if available)

2. **Disassemble Falcon Code**:
   - Falcon ISA not standard (requires custom disassembler)
   - Analyze instruction patterns
   - Identify instruction mnemonics from context
   - Build ISA dictionary

3. **Identify Key Functions**:
   - Exception handlers (privileged operations)
   - ROP gadgets (return instructions)
   - Privilege mode transitions (mode switches)
   - Memory access functions

4. **Privilege Boundary Mapping**:
   ```
   Find supervisor vs. user code regions:
   ├─ Exception vectors (supervisor)
   ├─ Interrupt handlers (supervisor)
   ├─ Memory training (user or supervisor)
   ├─ DMA setup (supervisor)
   └─ Register configuration (supervisor)
   ```

5. **ROP Gadget Collection**:
   - Find all RET instructions
   - Extract preceding instructions (gadgets)
   - Build gadget database
   - Chain gadgets for arbitrary operations

**Success Criteria**:
- [ ] Falcon ISA understood
- [ ] Privilege modes identified
- [ ] ROP gadgets catalogued
- [ ] Escalation paths identified

**Expected Outcome**: HIGH
- Multiple privilege escalation paths likely
- Gadgets sufficient for complex ROP chains
- Supervisor code modifiable via stack overflow

---

### Target 3: WPR Allocation Algorithm (Vuln #5)

**Objective**: Reverse engineer WPR allocation to enable offset validation bypass

**Location**: `acr_wpr_ctrl_ga10x.c` (source) or ACR binary (reverse engineer)

**Strategy**:

1. **Identify WPR Allocation Function**:
   - Source: Look for "allocate_wpr" or similar
   - Binary: Search for WPR address calculations

2. **Trace Allocation Logic**:
   ```
   Function: allocate_wpr_space(size_t firmware_size)
   ├─ Find free space in WPR
   ├─ Check WPR limits
   ├─ Calculate allocation address
   ├─ Store offset in metadata
   └─ Return allocation address
   ```

3. **Identify Offset Validation**:
   - Search for checks on firmware offsets
   - Look for size bounds validation
   - Verify address range checking

4. **Mutation Window Analysis**:
   ```
   Timeline:
   T1: allocate_wpr() executes
   T2: firmware loaded to allocated address
   T3: Offset field writable?
   T4: Address recomputable?
   T5: Re-verification occurs?
   ```

**Success Criteria**:
- [ ] Allocation algorithm extracted
- [ ] Offset validation gaps identified
- [ ] Mutation window timed
- [ ] Post-verification writability confirmed

**Expected Outcome**: HIGH
- Allocation likely dynamic (post-verification)
- Offset validation missing
- Firmware reinterpretable at different offsets

---

### Target 4: SMC Instance Validation (Vuln #1)

**Objective**: Confirm SMC instance ID validation is missing

**Location**: `acr_dma_ga100.c` or DMA setup code

**Strategy**:

1. **Find NV_GET_PGRAPH_SMC_REG Macro**:
   - Search in register header files
   - Find in compiled code patterns
   - Identify all usages

2. **Trace Instance ID Flow**:
   ```
   Entry: instance_id from firmware
   ├─ Any bounds check before use?
   ├─ Any range validation?
   ├─ Directly used in calculation?
   └─ Address calculation overflow checked?
   ```

3. **DMA Setup Code Analysis**:
   ```
   Function: setup_dma(instance_id, ...)
   ├─ Load instance_id
   ├─ Check: if (instance_id >= MAX_INSTANCES)?
   ├─ Calculate: dma_addr = base + (id * stride)
   ├─ Check: overflow in calculation?
   └─ Write to register
   ```

4. **Register Access Patterns**:
   - Identify all instance-based register accesses
   - Check for validation on each path
   - Document unvalidated paths

**Success Criteria**:
- [ ] NV_GET_PGRAPH_SMC_REG usage catalogued
- [ ] Validation gaps confirmed
- [ ] Register access patterns documented
- [ ] Misdirection targets identified

**Expected Outcome**: CRITICAL
- No validation on unchecked paths
- Multiple attack targets (DMA, SMC, FECS)
- Register overflow exploitable

---

### Target 5: Dependency Map Parsing (Vuln #2)

**Objective**: Confirm dependency map bounds are unchecked

**Location**: `acr_wpr_ctrl_ga10x.c` function `_acrlibCheckDependency_v2()`

**Strategy**:

1. **Find Dependency Check Function**:
   - Source: `_acrlibCheckDependency_v2`
   - Binary: Search for version table access patterns

2. **Analyze Loop Logic**:
   ```c
   for (int i = 0; i < depCount; i++) {
       uint8_t depFalconId = depMap[i];
       
       // Check for validation:
       if (depFalconId >= MAX_FALCON_ID) {
           return ERROR;  // Should be here
       }
       
       // What actually happens?
       uint32_t version = versionTable[depFalconId];
   }
   ```

3. **Bounds Checking Verification**:
   - Is there a check before array access?
   - Is check sufficient (>= vs. >)?
   - Is check always executed (no shortcuts)?

4. **Integer Overflow in Loop** (Vuln #7):
   ```c
   for (uint32_t i = 0; i < depCount; i++) {
       uint32_t offset = i * 2;  // Check for overflow
       
       // Does calculation overflow?
       if (depCount = 0xFFFFFFFF) {
           when i = 0x80000000:
           offset = 0x00000000  // Wrapped!
       }
   }
   ```

**Success Criteria**:
- [ ] Bounds check identified as missing
- [ ] Integer overflow confirmed possible
- [ ] Array access confirmed unchecked
- [ ] Out-of-bounds read confirmed

**Expected Outcome**: CRITICAL
- No bounds checking on array index
- Multiple out-of-bounds read opportunities
- Integer overflow wraps address

---

### Target 6: Training State Verification (Vuln #4)

**Objective**: Confirm training state lacks cryptographic verification

**Location**: GA100 uses HBM2e, NOT GDDR6. `fbflcn_gddr_boot_time_training_ga100.c` does NOT exist in the source tree. The relevant target is the **HULK** ucode (FBFalcon, TargetID=5 in VBIOS Image #2) and the **DEVINIT** PMU scripted sequencer embedded in the VBIOS.

**Strategy**:

1. **Find Training State Storage**:
   - Identify training result save function
   - Locate WPR training state region
   - Extract training state structure

2. **Verify No MAC/Signature**:
   ```
   Training state save:
   ├─ Save pi_offset[]
   ├─ Save vref[]
   ├─ Save dfe_tap[]
   ├─ Check for: compute_mac(state)?
   ├─ Check for: add_signature(state)?
   ├─ Check for: hash_training_results()?
   └─ Result: None of above (vulnerable)
   ```

3. **Training Load Function**:
   ```
   Training state load:
   ├─ Load pi_offset[]
   ├─ Load vref[]
   ├─ Load dfe_tap[]
   ├─ Check for: verify_mac()?
   ├─ Check for: validate_signature()?
   ├─ Check for: check_hash()?
   └─ Result: Load without verification
   ```

4. **Parameter Validation**:
   ```
   apply_training:
   ├─ Check: if (pi_offset < 128)?
   ├─ Check: if (vref < SAFE_VOLTAGE)?
   ├─ Check: if (dfe_tap < 16)?
   └─ Result: No range validation observed
   ```

**Success Criteria**:
- [ ] No MAC on training state confirmed
- [ ] No signature on training state confirmed
- [ ] No range validation on parameters confirmed
- [ ] Mutable state confirmed unprotected

**Expected Outcome**: HIGH
- Training state completely mutable
- No integrity checking
- No range validation
- Corruption undetectable

---

### Target 7: LSF Offset Validation (Vuln #5)

**Objective**: Confirm binOffset and binSize not validated

**Location**: LSF parsing in ACR bootloader

**Strategy**:

1. **Find LSF Parser**:
   - Locate parse_lsf_header() or similar
   - Identify all field extractions

2. **Analyze Offset Validation**:
   ```
   Parse binOffset:
   ├─ Extract field from LSF header
   ├─ Check: if (binOffset >= firmware_size)?
   ├─ Check: if (binOffset + binSize > firmware_size)?
   ├─ Check overflow: (binOffset > MAX_OFFSET)?
   └─ Result: No checks found (vulnerable)
   ```

3. **Memory Copy Analysis**:
   ```
   After offset extracted:
   ├─ binary_data = firmware_image + binOffset
   ├─ memcpy(wpr_alloc, binary_data, binSize)
   └─ Check for bounds checking in memcpy (likely none)
   ```

**Success Criteria**:
- [ ] Offset not validated against image size
- [ ] Size not validated against remaining image
- [ ] Overflow not checked
- [ ] Out-of-bounds read possible

**Expected Outcome**: HIGH
- Offset validation completely missing
- Out-of-bounds read from driver memory
- Write to WPR at attacker-chosen offset possible

---

## Tools and Techniques

### Disassemblers
- **Ghidra**: Free, open-source, excellent for RISC-V
- **IDA Pro**: Commercial, powerful, supports custom architectures
- **Radare2**: Free, scriptable, good for automation

### Analysis Workflow

```
1. Load binary in Ghidra
   ├─ File → Open → basic-ga100-sec
   ├─ Select RISC-V processor
   └─ Let auto-analysis complete

2. Search for targets
   ├─ Search → String → "aes" (for AES key)
   ├─ Search → Instruction → Pattern matching
   └─ Cross-reference analysis

3. Manual analysis
   ├─ Follow function calls
   ├─ Trace data dependencies
   ├─ Annotate findings
   └─ Document important functions

4. Export results
   ├─ Create report
   ├─ Document key findings
   ├─ Provide code references
   └─ Enable reproduction
```

### Automated Analysis

**Python Scripts**:
```python
# Find all memory writes
import subprocess
for line in gdb_output:
    if "write" in line:
        analyze_write(line)

# Find all conditional branches
for addr, instruction in disassembly:
    if instruction.is_conditional_branch():
        trace_branch(addr)

# Build gadget database
gadgets = find_all_rets(binary)
for gadget in gadgets:
    if is_useful_gadget(gadget):
        add_to_database(gadget)
```

### Key Search Techniques

**For Hardcoded AES Key** (if encrypted firmware exists):
```
1. Find AES sbox in binary (256-byte constant)
2. Find round constants (0x01, 0x02, 0x04, etc.)
3. Find AES encrypt function
4. Search for key usage
5. Look for 32-byte constant near AES code
6. Verify against known plaintexts
```

**For Gadget Chains**:
```
1. Extract all RET instruction addresses
2. For each RET, look back 1-15 bytes
3. Check if preceding bytes form useful instructions
4. Build gadget database
5. Chain gadgets for:
   ├─ Load register with value
   ├─ Write to memory
   ├─ Compute addresses
   └─ Call functions
```

---

## Expected Findings

### Confirmed (Very High Confidence)
- [ ] No bounds checking on SMC instance_id (Vuln #1)
- [ ] No bounds checking on depMap array access (Vuln #2)
- [ ] No validation on LSF offsets (Vuln #5)
- [ ] No MAC on training state (Vuln #4)
- [ ] Integer overflow in depMap loop (Vuln #7)
- [ ] No version range checking (Vuln #8)

### Likely (High Confidence)
- [ ] AES key hardcoded (Vuln #3)
- [ ] No VREF range validation (Vuln #6)
- [ ] Post-verification mutation window (Chap 9)
- [ ] Inadequate WAR functions (Chap 10)

### Possible (Medium Confidence)
- [ ] ROP gadgets sufficient for escalation (Chap 6)
- [ ] Stack overflow to exception handler (Chap 6)
- [ ] WPR write-protection bypassable (Chap 9)
- [ ] Attestation spoofable (Chap 9)

---

## Analysis Timeline

**Week 1**: Tool setup and initial disassembly
- [ ] Install Ghidra, IDA, or Radare2
- [ ] Load basic-ga100-sec
- [ ] Begin auto-analysis

**Week 2**: Target 1-3 analysis (Highest priority)
- [ ] AES key analysis
- [ ] Falcon ISA extraction
- [ ] WPR allocation reverse engineering

**Week 3**: Target 4-7 analysis
- [ ] SMC instance validation
- [ ] Dependency map parsing
- [ ] Training state verification
- [ ] LSF offset validation

**Week 4**: Comprehensive analysis and documentation
- [ ] Verify all findings
- [ ] Build complete mapping
- [ ] Create documentation
- [ ] Develop proof-of-concepts

---

## Next Steps

1. **Extract Artifacts**:
   - Locate prebuilt firmware in archive
   - Copy to analysis system
   - Verify integrity (SHA-256)

2. **Disassemble**:
   - Load in Ghidra
   - Apply processor definitions
   - Execute auto-analysis

3. **Manual Analysis**:
   - Follow each target systematically
   - Document findings
   - Cross-reference source code

4. **Verification**:
   - Confirm findings against source
   - Test assumptions on hardware (if available)
   - Develop proof-of-concepts

5. **Exploitation**:
   - Develop exploits based on findings
   - Test on GA100 hardware
   - Document attack chains

---

## Success Criteria

Complete reverse engineering analysis is successful when:

- [ ] All 8 vulnerabilities confirmed in binary
- [ ] AES key source determined
- [ ] Falcon ISA sufficiently understood
- [ ] ROP gadget chains identified
- [ ] Attack feasibility proven
- [ ] Proof-of-concept code developed
- [ ] Complete documentation provided

