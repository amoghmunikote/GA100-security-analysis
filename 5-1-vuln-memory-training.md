# 5.1 — Vulnerability Analysis: Memory Training

> **CRITICAL CORRECTION (Phase-2, confirmed Phase-3)**: The entire original document below was written under the false assumption that GA100 uses **GDDR6** memory. **GA100 uses HBM2e.** There is no `fbflcn_gddr_boot_time_training_ga100.c` in the source tree. The GDDR6 code paths (`fbflcn_gddr_boot_time_training_ga10x.c` / `_tu10x.c`) target GA102/TU1x chips, not GA100.
>
> **Correct GA100 HBM2e training architecture:**
> - **DEVINIT**: VBIOS-embedded PMU scripted sequencer. Runs at POST time from the VBIOS. Initializes HBM2e PHY timing, voltages, and training parameters. Not a standalone Falcon ucode — it is a byte-code script interpreted by a PMU scripted sequencer engine embedded in the VBIOS. Not covered by ACR's AES-DM verification chain.
> - **HULK ucode**: HBM2e row-remap / memory training ucode. Runs on FBFalcon (TargetID=5). Embedded in VBIOS Image #2 as `HULK_PROD` (@ CMP 0x2FEA0, 16,240 B) and `HULK_DBG`. Covered by the VBIOS trust chain, not the ACR LS chain.
> - **ACR WAR functions** (`acr_war_functions_ga100_only.c`): `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` and `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100` — these are WPR placement validators that are HBM2e row-remapper-aware. They run inside AHESASC and are covered by HS verification.
>
> **The core security concern is valid** (training results stored without ACR re-verification), but the attack surface is the VBIOS DEVINIT script and HULK ucode, not a standalone Falcon ucode file. See `2-3-firmware-parsing-vulns.md §Vulnerability 4` (corrected) and `2-6-vbios-ucode-catalog.md` for binary-confirmed HULK layout.
>
> The remainder of this document is **retained as historical context** for the Phase-1 analysis. All code snippets are pseudocode based on the (incorrect) GDDR6 assumption and do NOT represent actual GA100 behavior.

## Overview (SUPERSEDED — see correction above)

~~GDDR6~~ **HBM2e** memory requires signal integrity initialization at boot time. GA100's DEVINIT PMU script and HULK ucode perform this training, but the results are not re-verified by the ACR cryptographic chain. This enables fault injection attacks against DEVINIT/HULK execution and persistent WPR state corruption.

**Critical Gap**: HBM2e training results (DEVINIT output, row-remap tables) are stored as mutable runtime state without ACR re-verification

**Original (incorrect) text follows for historical reference:**

---

## GDDR6 Memory Training Fundamentals

### Training Purpose

GDDR6 training determines three critical parameters:

1. **PI (Phase/Interval) Offset**: Bit timing alignment
2. **VREF (Voltage Reference)**: Optimal voltage level  
3. **DFE (Decision Feedback Equalization)**: Signal equalization

Each parameter must be individually calibrated for each memory channel based on:
- Memory chip manufacturing variations
- PCB layout and signal routing
- Operating temperature
- Voltage stability

### Why Training is Necessary

```
Raw Signal (without training):
┌───┐   ┌───┐   ┌───┐
│   │   │   │   │   │
└───┘   └───┘   └───┘
  Bad timing, unclear signal levels, high error rate

Trained Signal:
┌─────┐┌─────┐┌─────┐
│     ││     ││     │
└─────┘└─────┘└─────┘
  Perfect timing, clear levels, reliable operation
```

### Training Failure Consequences

If training fails or uses wrong parameters:
- Bit flip errors (single and multi-bit)
- Data corruption
- Silent failures (undetected errors)
- GPU becoming unusable
- Permanent memory damage (from over-voltage)

---

## Training Algorithm Phases

### Initial Scan

```c
void training_phase_1(void) {
    // Find rough PI offset
    for (uint32_t pi = 0; pi < 256; pi++) {
        set_pi_offset(pi);
        
        // Test memory read/write
        uint32_t errors = test_memory_pattern();
        
        if (errors == 0) {
            // Found working pi_offset
            save_pi_offset(pi);
            break;
        }
    }
}
```

**Purpose**: Find any stable PI offset  
**Output**: Approximate PI value

### PI Fine-Tuning

```c
void training_phase_2(void) {
    uint32_t pi_base = load_pi_offset();
    
    // Fine-tune around rough value
    for (int32_t offset = -5; offset <= 5; offset++) {
        set_pi_offset(pi_base + offset);
        
        uint32_t errors = test_memory_pattern();
        
        if (errors < best_errors) {
            best_pi = pi_base + offset;
            best_errors = errors;
        }
    }
    
    save_pi_offset(best_pi);
}
```

**Purpose**: Optimize PI for minimum errors  
**Output**: Optimal PI value

### VREF Coarse Adjustment

```c
void training_phase_3(void) {
    // Find voltage reference range
    for (uint32_t vref = 0; vref < 256; vref += 10) {
        set_vref(vref);
        
        uint32_t errors = test_memory_pattern();
        
        if (errors == 0) {
            // Found working vref
            save_vref(vref);
            break;
        }
    }
}
```

**Purpose**: Find stable voltage range  
**Output**: Approximate VREF value

### VREF Fine-Tuning

```c
void training_phase_4(void) {
    uint32_t vref_base = load_vref();
    
    // Fine-tune voltage reference
    for (int32_t offset = -5; offset <= 5; offset++) {
        set_vref(vref_base + offset);
        
        uint32_t errors = test_memory_pattern();
        
        if (errors < best_errors) {
            best_vref = vref_base + offset;
            best_errors = errors;
        }
    }
    
    save_vref(best_vref);
}
```

**Purpose**: Optimize VREF for minimum errors  
**Output**: Optimal VREF value

### -6: DFE and Advanced Adjustments

```c
void training_phase_5(void) {
    // Optimize DFE (equalization) parameters
    // Similar iterative refinement process
    for (uint32_t dfe_tap = 0; dfe_tap < 16; dfe_tap++) {
        set_dfe_tap(dfe_tap);
        
        uint32_t errors = test_memory_pattern();
        
        if (errors < best_errors) {
            best_dfe = dfe_tap;
            best_errors = errors;
        }
    }
    
    save_dfe_tap(best_dfe);
}
```

---

## Training State Storage

### Runtime State Structure

```c
typedef struct {
    uint32_t pi_offset[NUM_CHANNELS];      // Timing offset per channel
    uint32_t vref[NUM_CHANNELS];           // Voltage reference per channel
    uint32_t dfe_tap[NUM_CHANNELS];        // Equalization per channel
    uint32_t training_status;              // Completion flags
    uint32_t error_count;                  // Errors found during training
    uint32_t temperature;                  // Temperature at training time
    uint32_t timestamp;                    // Training completion time
} Memory_Training_State;
```

### Storage Location

```
WPR Layout:
┌─────────────────────────────────┐
│ Firmware Images                 │
├─────────────────────────────────┤
│ Cryptographic Keys (protected)  │
├─────────────────────────────────┤
│ Training State (mutable!)       │ ← No integrity check
├─────────────────────────────────┤
│ Runtime Configuration           │
└─────────────────────────────────┘

Training state stored in WPR:
✓ Write-protected from driver
✗ No MAC/signature for integrity
✗ No hash for corruption detection
✗ Mutable by Falcon firmware
```

### State Usage

```c
void apply_training_state(void) {
    Memory_Training_State* state = load_training_state();
    
    for (uint32_t ch = 0; ch < NUM_CHANNELS; ch++) {
        // Load training results from WPR
        set_pi_offset(state->pi_offset[ch]);
        set_vref(state->vref[ch]);
        set_dfe_tap(state->dfe_tap[ch]);
        
        // CRITICAL: No verification of values
        // No check that pi_offset is in valid range
        // No check that vref is reasonable
    }
}
```

---

## Vulnerability Analysis

### Vulnerability 1: No Cryptographic Verification

**Issue**: Training state not protected by MAC or signature

**Impact**:
```
1. Training completes (values stored in WPR)
2. Attacker corrupts training state in WPR
3. No integrity check detects corruption
4. Next boot uses corrupted training parameters
5. Memory operates with wrong settings
6. Silent data corruption or GPU malfunction
```

**Exploitability**:
```
Attacker capability: Can corrupt WPR (via DMA misdirection, Vuln #1+#5)
Attack: Modify pi_offset to invalid value
Result: Memory bit flip errors during operation
```

### Vulnerability 2: No Range Validation

**Issue**: Training parameters not validated against hardware limits

**Code**:
```c
void apply_training_state(void) {
    // CRITICAL: No range check
    set_pi_offset(state->pi_offset);  // What if > 256?
    set_vref(state->vref);            // What if > safe_voltage?
    set_dfe_tap(state->dfe_tap);      // What if > 15?
}
```

**Attack**:
```
1. Corrupt training state with out-of-range values
2. set_vref(0xFFFFFFFF) → Over-voltage → Hardware damage
3. set_pi_offset(0xFFFFFFFF) → Wrap-around → Wrong timing
4. set_dfe_tap(0xFFFFFFFF) → Invalid equalizer settings → Errors
```

### Vulnerability 3: Fault Injection During Training

**Issue**: Training process vulnerable to fault injection attacks

**Scenario**:
```
During ## (PI fine-tuning):
1. Algorithm iterates through PI offsets
2. Attacker injects fault (electromagnetic pulse, laser)
3. Fault causes test_memory_pattern() to return 0 errors
4. Algorithm thinks current offset is optimal (it's not)
5. Stops training prematurely with suboptimal value
6. Memory operates at margin
7. Silent data corruption during normal operation
```

**Fault Injection Techniques**:
- Electromagnetic pulses (EM pulse generators)
- Laser-based fault injection
- Timing manipulation (glitch attacks)
- Voltage fluctuations

### Vulnerability 4: Temperature-Dependent Sensitivity

**Issue**: Training dependent on temperature, but not re-validated

**Scenario**:
```
1. Training at ambient temperature (25°C)
2. GPU heats up during operation (80°C)
3. Memory characteristics change at higher temperature
4. Training parameters no longer optimal
5. Bits start flipping as temperature rises
6. Silent data corruption
```

**Attack**:
```
1. Force GPU to high temperature during normal operation
2. Memory parameters designed for 25°C no longer work
3. Induce bit flips through thermal stress
4. Corrupt GPU memory without obvious cause
```

### Vulnerability 5: No Replay Protection

**Issue**: Training state from previous boot used without verification

**Scenario**:
```
Boot 1: GPU trained for condition X
        Training state saved to WPR

Boot 2: Different condition Y (different memory chip, PCB variant)
        Old training state from Boot 1 still in WPR
        No verification that state is appropriate for condition Y
        Load old training state
        Memory parameters wrong for current hardware
        Operation fails or corrupts data
```

**Attack Variant**:
```
1. Downgrade training state to earlier (suboptimal) values
2. Force GPU to use obsolete calibration
3. Trigger bit flips through parameter degradation
```

---

## Hardware Configuration Registers

### PI Offset Register

```c
#define PI_OFFSET_REG          0x900000
#define PI_OFFSET_MASK         0xFF

// Setting PI offset
void set_pi_offset(uint32_t offset) {
    uint32_t val = mmio_read(PI_OFFSET_REG);
    val = (val & ~PI_OFFSET_MASK) | (offset & PI_OFFSET_MASK);
    
    // CRITICAL: No validation
    mmio_write(PI_OFFSET_REG, val);
}
```

**Valid Range**: 0-127 (128 possible values)  
**Gap**: No range check before write

### VREF Control Register

```c
#define VREF_CONTROL_REG       0x900004
#define VREF_CONTROL_MASK      0xFF

// VREF adjusts voltage from (V_min = 0) to (V_max = 1.1V)
// Each unit ≈ 4.3mV
void set_vref(uint32_t vref_code) {
    // CRITICAL: No range validation
    // If vref_code > safe_max, hardware over-voltages
    // Can damage memory and GPU
    mmio_write(VREF_CONTROL_REG, vref_code);
}
```

**Valid Range**: 0-255 (practical: 0-200 for safe operation)  
**Over-voltage**: Damages components  
**Gap**: No validation, no over-voltage protection in firmware

### DFE Tap Register

```c
#define DFE_TAP_REG           0x900008
#define DFE_TAP_MASK          0x0F

void set_dfe_tap(uint32_t tap_value) {
    uint32_t val = mmio_read(DFE_TAP_REG);
    val = (val & ~DFE_TAP_MASK) | (tap_value & DFE_TAP_MASK);
    
    // CRITICAL: Doesn't validate tap_value
    // If tap_value has bits above 0x0F, truncated but no warning
    mmio_write(DFE_TAP_REG, val);
}
```

**Valid Range**: 0-15 (4 bits)  
**Gap**: No validation

---

## Exploitation Scenarios

### Scenario 1: Persistent Memory Corruption

```
1. Attacker crafts malicious training state
   ├─ pi_offset = 200 (too high)
   ├─ vref = 180 (too high)
   └─ dfe_tap = 14 (saturated)

2. Corrupt WPR training state (via DMA misdirection)
   └─ Write malicious state to training region

3. Next GPU boot
   ├─ Load corrupted training state
   ├─ Apply invalid parameters
   └─ Memory operates at extreme margin

4. During normal operation
   ├─ Bit flip errors occur randomly
   ├─ Data corruption detected or silent
   ├─ GPU malfunctions or data loss
   └─ Error sources unclear (not signature violation)
```

### Scenario 2: Hardware Damage

```
1. Corrupt VREF value to maximum (0xFF = 1.1V+ applied)
2. Normal operation continues
3. VREF always at max voltage
4. Voltage regulator stressed
5. Capacitors and MOSFETS degrade
6. Hardware eventually fails
7. GPU becomes permanently unusable
```

### Scenario 3: Selective Channel Attack

```
1. Corrupt training state for specific memory channel
   └─ pi_offset[0] = suboptimal
   └─ other channels = normal

2. That channel operates at margin
3. Additional load on that channel causes bit flips
4. Corruption affects all data using that channel
5. Appears random but highly targeted
```

### Scenario 4: Denial of Service

```
1. Corrupt all training parameters
2. GPU becomes unusable immediately
3. Cannot recover without re-training
4. Re-training impossible if corrupted state
5. GPU in permanent failed state
```

---

## Defense Mechanisms (Should Be Present)

### Missing: Integrity Protection

```c
// Should use MAC for training state integrity
void save_training_state(Memory_Training_State* state) {
    // Compute MAC over training state
    uint32_t mac = compute_mac(state, secret_key);
    
    // Store state + MAC
    store_to_wpr(&state, sizeof(state));
    store_to_wpr(&mac, sizeof(mac));
}

void load_training_state(Memory_Training_State* state) {
    // Load state + MAC
    load_from_wpr(&state, sizeof(state));
    load_from_wpr(&mac, sizeof(mac));
    
    // Verify MAC
    uint32_t expected_mac = compute_mac(state, secret_key);
    if (mac != expected_mac) {
        return ERROR_CORRUPTED_STATE;
    }
}
```

### Missing: Range Validation

```c
// Should validate parameters before use
void apply_training_state(Memory_Training_State* state) {
    // Validate each parameter
    if (state->pi_offset[ch] >= 128) {
        return ERROR_INVALID_PI;
    }
    if (state->vref[ch] > VREF_MAX_SAFE) {
        return ERROR_VREF_OVERVOLTAGE;
    }
    if (state->dfe_tap[ch] >= 16) {
        return ERROR_INVALID_DFE;
    }
    
    // Only apply if all valid
    set_pi_offset(state->pi_offset[ch]);
    set_vref(state->vref[ch]);
    set_dfe_tap(state->dfe_tap[ch]);
}
```

### Missing: Hardware Protection

```c
// Should enable hardware safeguards
void initialize_voltage_protection(void) {
    // Set hardware over-voltage limit
    mmio_write(VREF_LIMIT_REG, VREF_ABSOLUTE_MAX);
    
    // Enable automatic limit enforcement in hardware
    uint32_t ctrl = mmio_read(VREF_CTRL_REG);
    ctrl |= VREF_LIMIT_ENABLE;
    mmio_write(VREF_CTRL_REG, ctrl);
}
```

---

## Investigation Checklist (updated for actual GA100 HBM2e architecture)

- [x] Identified correct training path: DEVINIT PMU script + HULK ucode (not GDDR6 fbflcn file)
- [x] HULK ucode confirmed in VBIOS Image #2: `2-6-vbios-ucode-catalog.md`
- [x] ACR WARs for HBM2e row-remapper confirmed: `_acrCheckWprRangeWithRowRemapperReserveFB_GA100`, `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100`
- [ ] Extract and analyze DEVINIT script from `<GPU ROM archive>` VBIOS Image #2 (BIT token 'd')
- [ ] Analyze HULK ucode (binary, FBFalcon) for HBM2e row-remap write primitives
- [ ] Verify whether HULK training results are stored in ACR-verifiable WPR state
- [ ] Identify all HBM2e parameters written by DEVINIT and HULK
- [x] `fbflcn_gddr_boot_time_training_ga100.c` confirmed non-existent: Phase-2 §1.1

---

## Key Questions

**Q1**: Is training state cryptographically protected by ACR?  
**A1**: NO — DEVINIT runs before ACR; HULK is VBIOS-trust-chain (not AES-DM). Results stored as mutable runtime state.

**Q2**: Which file implements GA100 HBM2e training?  
**A2**: No standalone Falcon ucode file. DEVINIT PMU script (VBIOS-embedded) + HULK ucode (FBFalcon, VBIOS Image #2). `fbflcn_gddr_boot_time_training_ga100.c` does NOT exist.

**Q3**: What memory type does GA100 use?  
**A3**: HBM2e. NOT GDDR6. GDDR6 training files in this tree (`ga10x`, `tu10x`) target other chips.

**Q4**: Are ACR WARs present for HBM2e?  
**A4**: YES — `_acrCheckWprRangeWithRowRemapperReserveFB_GA100` and `_acrDisableMemoryLockRangeRowRemapWARBug2968134_GA100` in AHESASC (binary-confirmed; see `7-2-phase3-binary-analysis.md` §2).

**Q5**: What is the impact of training state corruption?  
**A5**: MEDIUM — HBM2e timing corruption via DEVINIT/HULK tampering can cause GPU malfunction; requires VBIOS flash access or fault injection. ACR does not re-verify DEVINIT outputs.

---

## Next Steps

1. **Verification**:
   - Binary analysis of training algorithm
   - Confirm no integrity checking
   - Identify training state location in WPR

2. **Exploitation Development**:
   - Corrupt training state via DMA misdirection
   - Develop fault injection attack
   - Test hardware damage scenarios
   - Create reliable corruption proof-of-concept

3. **Impact Assessment**:
   - Measure bit flip rates with corrupted training
   - Test hardware safeguards
   - Document recovery procedures
   - Assess persistent compromise capability

