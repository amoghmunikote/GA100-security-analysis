# AI Agent Archive Traversal Prompt

## How to Contribute to This Analysis Using AI Agents

This document provides step-by-step prompts for AI agents (or researchers) to systematically explore the NVIDIA GPU driver archive and validate/extend the GA100 security analysis.

---

## 🤖 Agent Instructions

### Purpose
Systematically explore the lapsus archive to:
1. Validate existing vulnerability findings
2. Identify additional vulnerabilities
3. Fill analysis gaps
4. Confirm architectural details
5. Extract supporting evidence

### Archive Location
```
d:\lapsus\integ\gpu_drv\stage_rel\
    ├── uproc/           (Microprocessor firmware - HIGHEST PRIORITY)
    ├── drivers/         (GPU driver subsystems)
    ├── tools/           (Build utilities)
    └── docs/            (Documentation)
```

### Total Files
- 404,078 total files in archive
- 570 GA100-specific files identified
- 50+ security-critical files to examine

---

## Task 1: Validate SMC Instance Selection Vulnerability

### Objective
Confirm that `falconInstance` field is not validated before register address computation.

### Agent Prompt

```
TASK: Validate SMC Instance Selection Vulnerability

GOAL: Determine whether NV_GET_PGRAPH_SMC_REG() macro validates 
the SMC instance ID before computing a GPU register address.

ARCHIVE PATH: d:\lapsus\integ\gpu_drv\stage_rel\

INVESTIGATION STEPS:

1. LOCATE THE VULNERABLE CODE:
   - Open: uproc/acr/src/acrsec2shared/ampere/acr_dma_ga100.c
   - Find function: acrlibSetupFecsDmaThroughArbiter_GA100()
   - Extract lines that use NV_GET_PGRAPH_SMC_REG()
   
2. FIND THE MACRO DEFINITION:
   - Search archive for: "define NV_GET_PGRAPH_SMC_REG"
   - Likely locations:
     * drivers/common/inc/hwref/ampere/ga100/dev_smcarb.h
     * drivers/common/inc/hwref/ampere/ga100/dev_graphics_nobundle.h
     * Any *smcarb*.h file
   
3. ANALYZE THE MACRO:
   - What computation does it perform?
   - Format: likely "base + offset + (instance_id * stride)"
   - Is there bounds checking in the macro?
   - Is there validation before calling the macro?
   
4. DETERMINE BOUNDS:
   - Find: Maximum valid SMC instance ID
   - Search for: "SMC_COUNT" or "NUM_INSTANCE" or "MAX_SMC"
   - Check: How many SMC instances exist on GA100?
   
5. VALIDATE VULNERABILITY:
   - If macro returns address without bounds check: VULNERABILITY CONFIRMED
   - If validation exists elsewhere: DOCUMENT IT
   - If bounds are enforced: EXPLANATION NEEDED
   
6. DOCUMENT FINDINGS:
   - Extract the actual macro code
   - Show how falconInstance is used
   - Demonstrate out-of-bounds access scenario
   
OUTPUT: 
- Provide the macro definition
- Provide the vulnerable code snippet
- Confirm vulnerability YES/NO with confidence
- List any mitigating controls found
```

### Expected Findings
You should find:
- ✅ Macro that computes `base + offset + (instance * stride)`
- ✅ No visible bounds check in macro
- ✅ falconInstance comes from firmware descriptor
- ✅ Reference to Bug #2565457 in code comments

---

## Task 2: Investigate Dependency Map Array Bounds

### Agent Prompt

```
TASK: Validate Dependency Map Array Bounds Vulnerability

GOAL: Confirm that depfalconId is used as an array index 
without bounds validation in anti-rollback checking.

INVESTIGATION STEPS:

1. LOCATE VULNERABLE CODE:
   - File: uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c
   - Function: _acrlibCheckDependency_v2()
   - Extract complete function code
   
2. ANALYZE ARRAY ACCESS PATTERN:
   - Find: for (i=0; i < depMapCount; i++)
   - Find: pBinVersions[depfalconId] access
   - Question: Is depfalconId validated before array access?
   
3. FIND ARRAY DEFINITION:
   - Where is pBinVersions allocated?
   - How many elements?
   - Where is this function called from?
   - What calls _acrlibCheckDependency_v2()?
   
4. TRACE DATA FLOW:
   - depMapCount: from firmware descriptor (untrusted)
   - depMap: from firmware descriptor (untrusted)
   - pBinVersions: parameter (where does it come from?)
   
5. SEARCH FOR MITIGATIONS:
   - Search for: "MAX_DEPMAP" or similar constant
   - Search for: bounds checking before array access
   - Search for: validation of depfalconId
   - Search for: safety mechanisms
   
6. IDENTIFY INTEGER OVERFLOW:
   - Code: idx = ((NvU32*)depMap)[i*2]
   - Can i*2 overflow for large depMapCount?
   - If depMapCount = 0x80000001, what happens?
   
7. CALCULATE IMPACT:
   - What data is adjacent to pBinVersions in memory?
   - What sensitive data could be leaked?
   - Can we read crypto keys? WPR addresses? Firmware offsets?

OUTPUT:
- Complete function code
- Identified arrays and their sizes
- Vulnerability confirmation YES/NO
- Impact assessment
- Proof of concept (pseudocode)
```

### Expected Findings
You should find:
- ✅ Array access without bounds check
- ✅ depMapCount and depMap from untrusted source
- ✅ No validation of depfalconId before array indexing
- ✅ Integer overflow possible in i*2 computation

---

## Task 3: Trace AES Decryption Key Derivation

### Agent Prompt

```
TASK: Determine AES-CBC Key Source for Firmware Decryption

GOAL: Establish whether AES key is:
  (a) Hardcoded (same for all GA100s) - CRITICAL
  (b) Device-specific (unique per GPU) - ACCEPTABLE
  (c) Derived from secrets - ACCEPTABLE
  (d) From host/driver - DEPENDS

INVESTIGATION STEPS:

1. LOCATE DECRYPTION CODE:
   - File: uproc/acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga100.c
   - Find: AES decryption function
   - Extract: How is the key obtained?
   
2. TRACE KEY VARIABLE:
   - Find: "key" variable or similar
   - Search backwards: Where does it come from?
   - Is it:
     * static const? (HARDCODED - BAD)
     * Parameter? (DEPENDS)
     * Computed? (GOOD - if secure)
     * From WPR? (DEPENDS)
   
3. SEARCH FOR KEY VALUES:
   - Grep for: hexadecimal patterns (AES keys are typically 32 bytes)
   - Look for: 0x[hex]{64} patterns (256-bit key)
   - Check if found in source: KEY IS HARDCODED (BAD)
   
4. FIND KEY DERIVATION:
   - If key is computed, how is it derived?
   - Inputs: ROM secrets? Device ID? Firmware version?
   - Algorithm: HMAC? KDF? Custom?
   - Entropy: How many bits of entropy?
   
5. CHECK STORAGE:
   - Is key stored in:
     * Code section? (EXPOSED)
     * WPR? (PROTECTED)
     * RAM? (VOLATILE)
     * Header? (EXPOSED)
   - Is key ever logged/dumped? (EXPOSURE RISK)
   
6. COMPARE WITH STANDARD:
   - Standard approach: Per-device encryption keys
   - GA100 approach: ___________
   - Assessment: Secure? YES / NO
   
7. SEARCH FOR COMMENTS:
   - Comments about key security
   - Known vulnerabilities mentioned
   - Related bugs referenced

OUTPUT:
- Key source (hardcoded/derived/device-specific)
- Actual key value (if exposed)
- Derivation algorithm (if applicable)
- Security assessment
- Impact if key is shared across all GA100s
```

### Expected Findings
You might find:
- ⚠️ Hardcoded key (worst case)
- ⚠️ Device ID in key derivation (limited entropy)
- ⚠️ Weak KDF (insufficient entropy)
- ✅ Secure per-device key material
- ❓ Undocumented key source (requires binary analysis)

---

## Task 4: Investigate Memory Training State Verification

### Agent Prompt

```
TASK: Confirm Training State Is Not Cryptographically Verified

GOAL: Establish that GDDR6 training results (VREF, DFE, PI values)
are not protected against modification or fault injection.

INVESTIGATION STEPS:

1. LOCATE TRAINING CODE:
   - File: uproc/fbflcn/src/fbflcn_gddr_boot_time_training_ga100.c
   - Find: Where training results are stored
   - Identify: All training phases
   
2. SEARCH FOR VERIFICATION:
   - Search for: "verify" (grep case-insensitive)
   - Search for: "checksum" in memory training code
   - Search for: "CRC" related to training
   - Search for: "hash" of training results
   - Search for: "signature" of training data
   
   Result: Verification mechanism found? YES / NO
   
3. MAP STORAGE LOCATIONS:
   - Training results stored in:
     * SRAM? (Volatile)
     * DRAM? (Volatile)
     * Persistent memory? (Permanent)
     * WPR? (Protected)
     * Unprotected memory? (Exposed)
   
4. IDENTIFY RESULTS:
   - What values are "learned" during training?
     * VREF (voltage reference)
     * DFE (Decision Feedback Equalization)
     * PI (Phase/Interval offset)
     * Eye diagram measurements
   
5. TRACE RESULT USAGE:
   - Where are learned values used after training?
   - Which memory operations depend on them?
   - Can they be modified between learning and use?
   - What happens if they're corrupted?
   
6. ASSESS FAULT INJECTION WINDOWS:
   - During training: Which operations are vulnerable?
   - After training: Can results be overwritten?
   - On reset: Are values preserved?
   - On recovery: Are values re-verified?
   
7. SEARCH FOR MITIGATIONS:
   - Redundant training?
   - Shadow copies?
   - Integrity protection?
   - Recovery mechanism?

OUTPUT:
- Training phases and state machine
- Storage locations for results
- Verification mechanisms (if any)
- Vulnerability confirmation YES/NO
- Fault injection window assessment
- Impact: what corruption causes
```

### Expected Findings
You should find:
- ✅ Training state machine with 6+ phases
- ✅ Results stored in DRAM or SRAM
- ✅ No cryptographic verification post-execution
- ✅ Results used in subsequent memory operations
- ✅ Vulnerable to EM/laser fault injection

---

## Task 5: Map Complete Offset Validation Gaps

### Agent Prompt

```
TASK: Identify All Offset Validation Gaps in LSF Parsing

GOAL: Find all places where firmware image offsets are used
without proper bounds checking.

INVESTIGATION STEPS:

1. COLLECT ALL OFFSET FIELDS:
   - File: uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c
   - Find: All *Offset fields in structures
   - List:
     * ucodeOffset
     * blDataOffset
     * appCodeOffset
     * appDataOffset
     * manifestOffset
     * monitorCodeOffset
     * monitorDataOffset
     * (others?)
   
2. FOR EACH OFFSET, FIND:
   - Where is it set/written?
   - Where is it read/used?
   - Is it validated before use?
   - What happens if out-of-bounds?
   
3. TRACE READ OPERATIONS:
   - Find: memcpy operations using offsets
   - Find: pointer arithmetic using offsets
   - Find: array indexing using offsets
   
   Question: Are firmware image bounds enforced?
   
4. IDENTIFY VALIDATION GAPS:
   - Expected: if (offset + size > image_size) return error;
   - Found: (YES / NO)
   - Gap severity: CRITICAL / HIGH / MEDIUM / LOW
   
5. CALCULATE EXPLOITATION IMPACT:
   - If LSB offset can point anywhere in firmware
   - Can we make signature point to attacker data?
   - Can we make code point to attacker data?
   - Can we bypass signature verification?

OUTPUT:
- List of all offset fields
- Which have validation: ___________
- Which lack validation: ___________
- Exploitation scenario
- Risk level: CRITICAL / HIGH / MEDIUM
```

### Expected Findings
You should find:
- ✅ Multiple offset fields without validation
- ✅ Direct writes without bounds checks
- ✅ No firmware image size limit enforcement
- ✅ Potential for signature spoofing

---

## Task 6: Extract Workaround Functions and Disabled Checks

### Agent Prompt

```
TASK: Inventory All Revision-Specific Workarounds and Disabled Checks

GOAL: Document hardware errata, workarounds, and disabled security checks
that might be exploitable.

INVESTIGATION STEPS:

1. LOCATE WAR FUNCTIONS:
   - Files:
     * uproc/acr/src/acrshared/ampere/acr_war_functions_ga100.c
     * uproc/acr/src/acrshared/ampere/acr_war_functions_ga100_only.c
     * uproc/acr/src/acrshared/ampere/acr_sanity_checks_ga100.c
   
2. FOR EACH FUNCTION:
   - What hardware bug does it work around?
   - What revision(s) are affected? (A0, A1, A2, A3)
   - What security check is affected?
   - Is check bypassed for specific revisions?
   
3. SEARCH FOR PATTERNS:
   - "#ifdef DEBUG" or "#ifdef PRODUCTION"
   - "if (chip_rev < X)" - revision-specific logic
   - "// WAR for bug" - workaround documentation
   - "skip check" - disabled security checks
   - "TODO:" or "FIXME:" - known issues
   
4. EXTRACT DISABLED CHECKS:
   - For each #ifdef or version check
   - Document: What is being disabled?
   - Why: What bug does it address?
   - Implication: Can it be exploited?
   
5. IDENTIFY PRIVILEGE ESCALATION PATHS:
   - Can we trigger specific revision logic?
   - Can we fool revision detection?
   - Can disabled checks be re-enabled in firmware?
   
6. ASSESS IMPACT:
   - Per-revision vulnerabilities
   - Cross-revision vulnerabilities
   - Errata that indicate instability
   - Workarounds that add complexity

OUTPUT:
- Complete list of WAR functions
- Revision-specific logic map
- Disabled security checks
- Potential exploitation paths
- Privilege escalation assessment
```

### Expected Findings
You should find:
- ✅ Multiple revision-specific workarounds
- ✅ Disabled checks for production builds
- ✅ Hardware bugs that suggest instability
- ✅ Opportunities for revision-specific exploits

---

## Task 7: Complete FECS DMA Arbitration Analysis

### Agent Prompt

```
TASK: Complete Analysis of FECS DMA Arbitration Setup

GOAL: Document all DMA configuration steps and identify
opportunities for isolation bypass or redirection.

INVESTIGATION STEPS:

1. LOCATE DMA SETUP CODE:
   - File: uproc/acr/src/acrsec2shared/ampere/acr_dma_ga100.c
   - Function: acrlibSetupFecsDmaThroughArbiter_GA100()
   
2. UNDERSTAND DMA DIRECTION:
   - Parameter: bIsPhysical - what does this mean?
   - If TRUE: Physical memory access
   - If FALSE: Virtual memory access
   - Who decides? Can it be overridden?
   
3. IDENTIFY REGISTER FIELDS:
   - _CMD_OVERRIDE_PHYSICAL_WRITES: What does ALLOWED mean?
   - _CMD: Value PHYS_VID_MEM - what other values exist?
   - _ENABLE: ON vs. OFF - what's the difference?
   
4. FIND REGISTER DEFINITIONS:
   - Files: dev_fbpa.h, dev_smcarb.h
   - For each register accessed:
     * Extract bit field definitions
     * Identify allowed values
     * Document side effects
   
5. TRACE DMA ISOLATION:
   - How does instance selection isolate FECS instances?
   - Can FECS_0 access FECS_1's memory?
   - Can user GPU access FECS memory?
   - Are there other DMA engines?
   
6. ASSESS REDIRECTION ATTACKS:
   - If instance ID can be overridden
   - Can we redirect FECS_0's DMA to another core?
   - Can we read another core's memory?
   - Can we write another core's memory?

OUTPUT:
- Complete register definitions
- DMA configuration sequence
- Isolation boundaries
- Redirection vulnerability assessment
- Exploitation impact
```

### Expected Findings
You should find:
- ✅ Multiple DMA configuration registers
- ✅ Potential for instance ID corruption
- ✅ DMA isolation boundaries
- ✅ Cross-core access possibilities

---

## General Search Strategies

### Finding Related Code

```
STRATEGY: Search for related vulnerabilities

EXAMPLES:

1. Find all uses of "depfalconId":
   grep -r "depfalconId" d:\lapsus\integ\gpu_drv\stage_rel\
   
2. Find all "BAR0" accesses:
   grep -r "BAR0" --include="*.c" d:\lapsus\integ\gpu_drv\stage_rel\
   
3. Find all "WPR" references:
   grep -r "WPR\|Write.*Protected" --include="*.c" d:\lapsus\integ\gpu_drv\stage_rel\
   
4. Find all SMC instance uses:
   grep -r "smcInstance\|SMC_ID\|instance_id" --include="*.c" d:\lapsus\integ\gpu_drv\stage_rel\
   
5. Find AES operations:
   grep -r "AES\|aes" --include="*.c" d:\lapsus\integ\gpu_drv\stage_rel\
   
6. Find validation functions:
   grep -r "validate\|bounds\|check" --include="*.c" d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\
```

### Finding Documentation

```
Helpful resources:
- Register files: d:\lapsus\integ\gpu_drv\stage_rel\drivers\common\inc\hwref\ampere\ga100\
- Header definitions: Look for "dev_*.h" files
- Config files: d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\build\sign\*.cfg
- Prebuilt firmware: d:\lapsus\integ\gpu_drv\stage_rel\uproc\nvriscv\prebuilt\
```

---

## Documentation Format

When submitting findings, use this format:

```markdown
## Vulnerability: [Name]

**File**: Path/to/file.c  
**Function**: function_name()  
**Lines**: 42-67  

**Root Cause**:
Description of why vulnerability exists

**Attack Vector**:
How would an attacker exploit this?

**Impact**:
What is the consequence?

**Evidence**:
Code snippet showing the vulnerability

**Confirmation Status**:
- [ ] Source code reviewed
- [ ] Macro/definition verified
- [ ] Bounds analyzed
- [ ] Exploitation path confirmed
```

---

## What to Do When You Find Something

1. **Document it thoroughly**:
   - File path and line numbers
   - Root cause explanation
   - Code snippets
   - Exploitation scenario

2. **Create a pull request**:
   - New or updated README section
   - Supporting evidence
   - Architecture diagrams if applicable
   - Cross-references

3. **Report high-confidence findings**:
   - Update relevant document
   - Link to related vulnerabilities
   - Add to executive summary

---

## Getting Help

If you encounter:

- **Unclear code**: Document what you found and where you got stuck
- **Missing pieces**: Note the gap and suggest where to look
- **Contradictions**: Document both findings and ask for clarification
- **New vulnerabilities**: Extract evidence and create documentation

---

**Next Steps**: Begin with Task 1 (SMC Instance Validation), then Task 2 (Dependency Map), etc.

**Expected Time**: 20-40 hours for complete archive analysis

**Skills Needed**: C code analysis, GPU architecture familiarity, security mindset

