# GA100 Security Analysis - Investigation Guide

**How to systematically investigate and validate the findings in this analysis**

---

## Phase 1: Understanding the Architecture (Week 1)

### Day 1: Boot Chain Overview
**Goal**: Understand the complete 4-stage boot process

**Tasks**:
1. Read `01_SECURE_BOOT_CHAIN.md` completely
2. Examine these source files:
   ```
   d:\lapsus\integ\gpu_drv\stage_rel\
   ├── uproc/acr/src/asb/ampere/acr_ls_falcon_boot_ga100.c
   ├── uproc/booter/src/load/ampere/booter_sig_verif_ga100.c
   └── uproc/acr/src/ahesasc/ampere/acr_signature_manager_ga100.c
   ```
3. Create a diagram showing:
   - ROM → Bootloader → ACR → Falcon progression
   - Trust handoff at each stage
   - Who verifies whom

**Questions to Answer**:
- [ ] Where do RSA public keys come from?
- [ ] What happens if a signature verification fails?
- [ ] Where are verified firmware images loaded in memory?
- [ ] How does the WPR get initialized?

---

### Day 2: LSF Format & WPR Structure
**Goal**: Understand firmware image format and memory layout

**Tasks**:
1. Read `02_WPR_AND_LSF_PARSING.md` completely
2. Examine these files:
   ```
   d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\src\acrshared\ampere\
   ├── acr_wpr_ctrl_ga10x.c  (LSF v2 structures and handlers)
   └── acr_sub_wpr_ga100.c   (WPR allocation)
   ```
3. Create a detailed diagram of:
   - LSF_LSB_HEADER_V2 structure
   - LSF_UCODE_DESC_V2 signature layout
   - WPR memory regions

**Questions to Answer**:
- [ ] What is the purpose of each LSF_* structure?
- [ ] How are firmware offsets computed?
- [ ] What data is signed vs. unsigned?
- [ ] How does WPR layout change between stages?

---

### Day 3: Vulnerability Landscape
**Goal**: Understand all 8 identified vulnerabilities

**Tasks**:
1. Read `03_FIRMWARE_PARSING_VULNERABILITIES.md` completely
2. For each vulnerability, note:
   - File location and function name
   - Root cause
   - Attack scenario
   - Expected impact
3. Create a vulnerability matrix:
   ```
   | Vuln # | Name | Severity | Requires RSA Break | Exploitability |
   |--------|------|----------|-------------------|-----------------|
   | 1 | SMC instance | CRITICAL | NO | High |
   | ... |
   ```

**Questions to Answer**:
- [ ] Which vulnerabilities can be exploited independently?
- [ ] Which require chaining?
- [ ] Which require binary analysis to confirm?

---

### Day 4: Hardware Interfaces
**Goal**: Understand register addressing and isolation

**Tasks**:
1. Read `04_SMC_MIG_ISOLATION.md` and `05_FECS_DMA_AND_MMIO.md`
2. Extract from header files:
   ```
   d:\lapsus\integ\gpu_drv\stage_rel\drivers\common\inc\hwref\ampere\ga100\
   ├── dev_graphics_nobundle.h   (Register definitions)
   ├── dev_smcarb.h              (SMC Arbitrator)
   └── dev_fbpa.h                (Frame Buffer Physical Address)
   ```
3. Map out:
   - Which registers are accessed for each operation
   - How SMC instance selection works
   - DMA arbitration setup sequence

**Questions to Answer**:
- [ ] What is the SMC register stride?
- [ ] How many SMC instances exist?
- [ ] What validates instance IDs?
- [ ] What is NV_GET_PGRAPH_SMC_REG() macro?

---

### Day 5: Privilege Boundaries
**Goal**: Understand who can do what

**Tasks**:
1. Read `06_FALCON_PRIVILEGE_BOUNDARIES.md`
2. Create an access matrix:
   ```
   Operation | User Mode | Falcon | ACR | ROM
   ----------|-----------|--------|-----|-----
   Read WPR  | NO        | YES    | YES | YES
   Write WPR | NO        | ???    | YES | YES
   MMIO Read | Limited   | YES    | YES | YES
   ...
   ```
3. Identify privilege escalation paths

**Questions to Answer**:
- [ ] What privilege modes exist in Falcon?
- [ ] How are context switches protected?
- [ ] What can user GPU code do vs. kernel GPU code?

---

## Phase 2: Vulnerability Confirmation (Week 2-3)

### Vulnerability #1: SMC Instance Selection

**Hypothesis**: The `falconInstance` field in firmware descriptor is not validated before use in register addressing, allowing out-of-bounds MMIO writes.

**Investigation Steps**:

1. **Source code verification**:
   ```
   File: d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\src\acrsec2shared\ampere\acr_dma_ga100.c
   Function: acrlibSetupFecsDmaThroughArbiter_GA100()
   
   Question: Is falconInstance validated before NV_GET_PGRAPH_SMC_REG()?
   Answer: ___________
   ```

2. **Macro expansion**:
   ```
   Find and analyze: NV_GET_PGRAPH_SMC_REG() macro definition
   Location: Likely in dev_smcarb.h or related headers
   
   Question: What does it compute? Is there bounds checking?
   Answer: ___________
   ```

3. **Instance bounds**:
   ```
   Search: "num.*instance" or "max.*smc" or "SMC_INSTANCE_COUNT"
   
   Questions:
   - How many SMC instances exist? ___________
   - What's the register stride? ___________
   - Are instances validated by architecture? ___________
   ```

4. **Bug reference**:
   ```
   Code comment: "Tracked in bug 2565457"
   Search for references to this bug number in other files
   
   Question: What does the bug report say about SMC_INFO vulnerability?
   Answer: ___________
   ```

5. **Exploitation path**:
   ```
   If falconInstance = 0x1000:
   - Register address = base + offset + (0x1000 * stride)
   - What register would this access?
   - Could it cause DMA misdirection?
   ```

**Confirmation Checklist**:
- [ ] Located falconInstance field in firmware descriptor structure
- [ ] Confirmed no validation occurs before use
- [ ] Found NV_GET_PGRAPH_SMC_REG() macro definition
- [ ] Identified register stride and bounds
- [ ] Determined out-of-bounds register access is possible
- [ ] Found evidence (comments, bugs) suggesting vulnerability

---

### Vulnerability #2: Dependency Map Array Bounds

**Hypothesis**: The `depfalconId` field in the dependency map is used as an array index without bounds checking, allowing out-of-bounds reads.

**Investigation Steps**:

1. **Source code verification**:
   ```
   File: d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\src\acrshared\ampere\acr_wpr_ctrl_ga10x.c
   Function: _acrlibCheckDependency_v2()
   
   Task: Extract the exact vulnerable code snippet
   ```

2. **Array sizing**:
   ```
   Find: pBinVersions array definition and allocation
   
   Questions:
   - How many elements? ___________
   - Where is it allocated? ___________
   - What's the maximum valid falconId? ___________
   ```

3. **Bounds checking**:
   ```
   Search for:
   - "if (depfalconId" checks before array access
   - "MAX_FALCON" definitions
   - "NUM_FALCON" defines
   
   Result: Bounds checking present? YES / NO
   ```

4. **Integer overflow**:
   ```
   Code pattern:
   for (i=0; i < depMapCount; i++) {
       idx = ((NvU32*)depMap)[i*2];  // i*2 could overflow!
   }
   
   Questions:
   - What's max depMapCount? ___________
   - What values of i would cause i*2 overflow? ___________
   - Is depMapCount validated? ___________
   ```

5. **Exploitation scenario**:
   ```
   Attack:
   - Set depMapCount = 0x80000001
   - Set depMap[0] = falconId, depMap[1] = version
   - When i=0x40000000, i*2 overflows and wraps to 0
   - Reads from depMap[0] at attacker-chosen index
   
   Is this possible? YES / NO (explain):
   ```

**Confirmation Checklist**:
- [ ] Located _acrlibCheckDependency_v2() function
- [ ] Confirmed array access without bounds check
- [ ] Found array definition and sizing
- [ ] Identified integer overflow possibility in loop
- [ ] Determined OOB read is possible
- [ ] Mapped out information that could be leaked

---

### Vulnerability #3: AES Decryption Key

**Hypothesis**: AES-CBC key for firmware decryption is hardcoded (same for all GA100s), breaking firmware confidentiality.

**Investigation Steps**:

1. **Key derivation search**:
   ```
   File: d:\lapsus\integ\gpu_drv\stage_rel\uproc\acr\src\ahesasc\ampere\acr_decrypt_ls_ucode_ga100.c
   
   Search for:
   - "AES_Decrypt" function calls
   - "key" variable definitions
   - How is 'key' obtained?
   
   Result: Key is ___________
   ```

2. **Key storage**:
   ```
   Search:
   - "static const" AES keys
   - "#define KEY" patterns
   - Keys in WPR?
   - Keys from host?
   
   Result: Key stored in ___________
   ```

3. **Per-device vs. hardcoded**:
   ```
   Questions:
   - Is key derived from device secrets? YES / NO
   - Is key unique per GPU? YES / NO
   - Is key algorithm documented? ___________
   - Is key exposed in headers/configs? ___________
   ```

4. **Impact if hardcoded**:
   ```
   If all GA100s use same AES key:
   - Attacker can decrypt any GA100 firmware
   - Can modify encrypted firmware
   - Can create custom firmware
   - Break firmware confidentiality
   
   Probability this is true: ___________
   ```

**Confirmation Checklist**:
- [ ] Located AES key initialization
- [ ] Determined key source (hardcoded vs. derived)
- [ ] Found key value or derivation algorithm
- [ ] Assessed impact of potential hardcoding
- [ ] Documented entropy of key material
- [ ] Verified through related source files

---

### Vulnerability #4: Memory Training State

**Hypothesis**: GDDR6 training results (VREF, DFE, PI values) are not cryptographically verified post-execution, allowing fault-injection attacks to create persistent memory corruption.

**Investigation Steps**:

1. **Training state storage**:
   ```
   File: d:\lapsus\integ\gpu_drv\stage_rel\uproc\fbflcn\src\fbflcn_gddr_boot_time_training_ga100.c
   
   Search for:
   - Where are training results stored?
   - SRAM locations?
   - DRAM locations?
   - Persistent storage?
   
   Result: ___________
   ```

2. **Post-training verification**:
   ```
   Search for:
   - "verify" after training
   - "checksum" of training results
   - "hash" of VREF/DFE values
   - "CRC" of training data
   
   Result: Verification found? YES / NO
   ```

3. **Training state usage**:
   ```
   Trace:
   - Where are learned values used?
   - Which operations depend on them?
   - What happens if corrupted?
   
   Example scenarios:
   - Corrupted VREF → bit errors
   - Corrupted DFE → signal degradation
   - Corrupted PI → timing errors
   ```

4. **Fault injection windows**:
   ```
   During training:
   - Which operations are critical?
   - Where could EM glitch be effective?
   - Which values, if corrupted, persist?
   
   After training:
   - Are results recomputed?
   - Can they be overwritten?
   - Are they re-verified?
   ```

**Confirmation Checklist**:
- [ ] Located training result storage
- [ ] Confirmed no post-execution verification
- [ ] Found training phases and state machines
- [ ] Identified fault injection windows
- [ ] Mapped persistence of corrupted values
- [ ] Assessed impact on memory stability

---

## Phase 3: Exploit Chain Construction (Week 3-4)

### Building a Complete Attack

**Objective**: Chain 2-3 vulnerabilities to achieve firmware compromise

**Approach**:

1. **Start with the easiest vulnerability**:
   - Dependency map array bounds is low-hanging fruit
   - No RSA break required
   - Direct code path

2. **Chain to information disclosure**:
   - Use OOB read to leak WPR layout
   - Learn firmware base address
   - Extract any available crypto keys

3. **Chain to firmware modification**:
   - Use offset validation gap
   - Corrupt LSB offset to point to attacker data
   - Reinterpret firmware signature as data

4. **Achieve persistence**:
   - Modify firmware in WPR
   - Survive resets by maintaining WPR state
   - Maintain access to privileged operations

---

## Phase 4: Binary Reverse Engineering (Week 4+)

### Critical Reverse Engineering Targets

1. **NV_GET_PGRAPH_SMC_REG() macro**
   - Find in dev_smcarb.h
   - Understand address computation
   - Confirm bounds assumptions

2. **Falcon ISA and privilege modes**
   - Disassemble prebuilt firmware
   - Identify privilege transitions
   - Find exception handlers

3. **AES key storage**
   - Scan memory for known plaintext
   - Analyze key derivation
   - Check entropy

4. **WPR allocation algorithm**
   - Trace sub-WPR allocation
   - Understand layout
   - Identify corruption opportunities

---

## Investigation Checklist

**Understanding Phase**:
- [ ] Read all documentation
- [ ] Understand boot chain
- [ ] Map privilege boundaries
- [ ] Identify trust boundaries

**Confirmation Phase**:
- [ ] Verify SMC instance vulnerability
- [ ] Confirm depMap array bounds issue
- [ ] Investigate AES key derivation
- [ ] Assess training state verification

**Exploitation Phase**:
- [ ] Plan information disclosure attack
- [ ] Design firmware modification path
- [ ] Develop persistence mechanism
- [ ] Test exploit chain

**Documentation Phase**:
- [ ] Document findings
- [ ] Create proof-of-concept
- [ ] Prepare responsible disclosure
- [ ] Publish analysis

---

## Key Questions to Answer

1. **Is SMC instance selection really vulnerable?**
   - Answer: _________________________
   - Confidence: High / Medium / Low

2. **Can we leak information via array bounds?**
   - Answer: _________________________
   - Impact: Crypto keys / Firmware addresses / Other: ________

3. **Is AES key hardcoded or per-device?**
   - Answer: _________________________
   - If hardcoded: Which values? ________

4. **Can we corrupt memory training results?**
   - Answer: _________________________
   - Persistence: Survives reset? YES / NO

5. **What is the complete exploit chain?**
   - Step 1: _________________________
   - Step 2: _________________________
   - Step 3: _________________________
   - Step 4: _________________________

---

## Resources

- **Archive location**: `d:\lapsus\integ\gpu_drv\stage_rel\`
- **Register definitions**: `drivers/common/inc/hwref/ampere/ga100/`
- **ACR code**: `uproc/acr/src/`
- **Falcon firmware**: `uproc/fbflcn/src/`
- **Prebuilt binaries**: `uproc/nvriscv/prebuilt/`

---

**Next**: Start with `01_SECURE_BOOT_CHAIN.md` → `03_FIRMWARE_PARSING_VULNERABILITIES.md` → vulnerability confirmation

