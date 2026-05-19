# 4.5 — Runtime Errata and Workarounds

## Overview

GA100 silicon contains hardware bugs and design limitations documented in revision errata. Firmware contains "WAR" (Work-Around) functions that disable or modify security checks to work around these bugs. This document catalogs security-critical workarounds that can be exploited to disable protections.

**Critical Issue**: WAR functions may be selectively disableable, allowing adversary to trigger security bypass

---

## Revision-Specific Errata

### GA100 Revision A0 (Early Engineering)

**Known Issues**:
- DMA address translation bug (hardware bug, not security)
- Memory training convergence failure
- Clock switching reliability

**WAR Functions**: `acr_war_functions_ga100_a0.c`

### GA100 Revision A1 (Production)

**Known Issues**:
- SMC instance ID validation race condition (SECURITY)
- DMA offset calculation overflow (SECURITY)
- FECS arbitration timing (potential isolation bypass)

**WAR Functions**: `acr_war_functions_ga100_a1.c`

### GA100 Revision A2 (Improved)

**Known Issues** (subset from A1):
- DMA offset calculation overflow (still present, WAR applied)
- FECS arbitration may be incomplete

**WAR Functions**: `acr_war_functions_ga100_a2.c`

### GA100 Revision A3 (Latest)

**Known Issues**:
- Reduced vulnerability surface
- Some WAR functions optional (can be disabled)

**WAR Functions**: `acr_war_functions_ga100_a3.c`

---

## Security-Critical WAR Functions

### WAR 1: SMC Instance Validation

**Errata**: SMC instance ID not validated, can access out-of-bounds register regions

**Location**: `acr_war_functions_ga100.c:war_smcinstance_validation()`

```c
void war_smcinstance_validation(void) {
    // Work-around for SMC instance validation bug
    
    // Check if instance ID is in valid range
    if (instance_id >= GA100_INSTANCE_COUNT) {
        disable_access();  // Prevent invalid access
        return;
    }
    
    // Continue with valid instance
}
```

**Gap**: 
- WAR function checks instance_id
- BUT: Check might be conditional on debug_mode
- OR: Check might be removable via configuration
- OR: Check might be skipped if performance_critical flag set

**Exploitation**:
```
Attack goal: Bypass SMC instance validation
1. Identify conditional checks in WAR function
2. Find way to set debug_mode or skip WAR
3. Send DMA with invalid instance_id
4. Bypass register isolation
5. Access arbitrary memory
```

### WAR 2: DMA Offset Overflow

**Errata**: DMA offset calculation can overflow, accessing unintended memory

**Location**: `acr_war_functions_ga100.c:war_dma_offset_overflow()`

```c
void war_dma_offset_overflow(void) {
    // Work-around for DMA offset overflow
    
    // Validate offset won't overflow
    uint64_t max_offset = DMA_MAX_OFFSET;
    
    if (dma_offset > max_offset) {
        error_dma_offset_too_large();  // Reject overflow
        return;
    }
    
    // Safe to use offset
}
```

**Gap**:
- Check might be disabled if dma_fast_path enabled
- Check might be incomplete (only checks low bits, not high)
- Check might be skipped for certain DMA types
- Validation might use wrong maximum value

**Exploitation**:
```
Attack goal: Trigger DMA offset overflow
1. Enable fast path (if conditional)
2. Send DMA with offset = 0xFFFFFFFF + 1
3. Overflow occurs
4. DMA accesses unintended address
5. Memory corruption or information disclosure
```

### WAR 3: FECS Arbitration Timing

**Errata**: FECS arbitration may grant access based on stale instance information

**Location**: `acr_war_functions_ga100.c:war_fecs_arbitration()`

```c
void war_fecs_arbitration(void) {
    // Work-around for FECS arbitration race condition
    
    // Add delay to let instance state settle
    delay(FECS_ARBITRATION_DELAY_CYCLES);
    
    // Now safe to proceed with arbitration
}
```

**Gap**:
- Delay might be too short
- Delay might be removable via configuration
- Delay might be skipped in high-performance mode
- Race window still exists, just reduced

**Exploitation**:
```
Attack goal: TOCTOU race in FECS arbitration
1. Change instance ID at precise time
2. Arbitration might validate old instance ID
3. Grant access for instance 0
4. But DMA actually for instance 1
5. Isolation bypass
```

### WAR 4: Sanity Check Disabling

**Errata**: Various sanity checks can cause deadlock, so made conditional

**Location**: `acr_sanity_checks_ga100.c` with configuration flags

```c
void run_sanity_checks(void) {
    // Various checks that might be disabled
    
    if (config.enable_training_validation) {
        check_training_results();
    }
    
    if (config.enable_version_validation) {
        check_dependency_versions();
    }
    
    if (config.enable_offset_validation) {
        check_firmware_offsets();
    }
}
```

**Gap**:
- Checks are conditional
- Configuration might be externally controllable
- Checks might be disabled by default
- No reporting if checks skipped

**Exploitation**:
```
Attack goal: Disable security checks
1. Find configuration storage
2. Modify enable_training_validation = false
3. Modify enable_version_validation = false
4. Load firmware with corrupted training state
5. Load firmware with version rollback
6. All checks bypassed
```

### WAR 5: Write-Protection Bypass

**Errata**: Hardware write-protection can be disabled for maintenance, creating bypass opportunity

**Location**: `acr_war_functions_ga100.c:war_wpr_maintenance()`

```c
void war_wpr_maintenance(void) {
    // Work-around: Allow temporary WPR modification
    
    if (maintenance_mode_flag) {
        // Temporarily disable write-protection
        disable_wpr_protection();
        
        // Allow firmware update
        // ...
        
        // Re-enable protection
        enable_wpr_protection();
    }
}
```

**Gap**:
- maintenance_mode_flag might be externally settable
- Re-enable might be skipped if error occurs
- No verification that protection was re-enabled
- Maintenance code might be reachable in production

**Exploitation**:
```
Attack goal: Corrupt firmware in WPR
1. Trigger maintenance mode (if possible)
2. Disable write-protection
3. Corrupt firmware in WPR
4. If re-enable fails, protection stays off
5. Corruption persists
```

---

## Conditional Behavior Patterns

### Performance vs. Security Tradeoff

```c
// Pattern: Performance flag disables security
if (performance_critical) {
    skip_validation_checks();  // Faster
} else {
    perform_validation_checks();  // Safer
}
```

**Risk**: Performance flag might be:
- Set by default
- Controllable via firmware input
- Persistent across reset
- Enabled by certain driver configurations

### Debug vs. Production Paths

```c
// Pattern: Debug mode bypasses checks
if (debug_mode_enabled) {
    allow_all_operations();  // Debug convenience
} else {
    enforce_security();  // Production security
}
```

**Risk**: Debug mode might be:
- Selectable via strap pins at boot
- Controllable via registers
- Not properly cleared by reset
- Defaulted to enabled in some configurations

### Conditional Compilation

```c
// Pattern: Security features compiled in/out
#if CONFIG_ENABLE_TRAINING_VALIDATION
    validate_training_results();
#else
    // Validation disabled at compile time
#endif
```

**Risk**: If compiled out:
- Cannot be re-enabled at runtime
- No fallback validation
- Source code analysis won't show issue if config unavailable
- Binary may lack validation code

---

## WAR Function Disabling Attack

### Attack Scenario: Systematic Security Bypass

```
Attacker Goal: Disable all security checks

Step 1: Disable SMC validation (WAR 1)
├─ Find flag controlling WAR
├─ Set flag to bypass instance validation
└─ SMC isolation no longer enforced

Step 2: Disable DMA offset validation (WAR 2)
├─ Find flag controlling WAR
├─ Set flag to allow offset overflow
└─ DMA misdirection now possible

Step 3: Disable FECS arbitration (WAR 3)
├─ Remove delay or set timing flag
├─ Race condition window opens
└─ Arbitration bypass possible

Step 4: Disable sanity checks (WAR 4)
├─ Modify configuration flags
├─ Skip training/version/offset validation
└─ All input validation bypassed

Step 5: Disable write-protection (WAR 5)
├─ Trigger maintenance mode (or spoof it)
├─ Disable WPR write-protection
├─ Corrupt firmware in WPR
└─ Persistence achieved

Result: Complete security bypass, full GPU control
```

---

## Known Vulnerability Patterns

### Pattern 1: Missing Bounds Check

```c
// Errata: No bounds check on instance ID
for (int i = 0; i < num_instances; i++) {
    if (instance_id == i) {
        // Process instance
    }
}

// WAR (incomplete):
if (instance_id < 8) {  // Check added
    // But what if this check is compiled out?
    // Or disabled by configuration?
}
```

### Pattern 2: Unsigned Underflow

```c
// Errata: Unsigned math can underflow
uint32_t remaining = size - offset;

if (remaining < 0) {  // Never true for unsigned!
    error();
}

memcpy(buffer, address + offset, remaining);  // Overflow
```

**WAR**:
```c
// Better check needed
if (offset >= size) {  // Still might not be present
    error();
}
```

### Pattern 3: Race Condition Window

```c
// Errata: Instance state checked, then used (TOCTOU)
if (instance_id < 8) {
    // State validated
}
// Instance ID could change here (race)
access_instance_registers(instance_id);  // Uses potentially-stale value
```

**WAR**:
```c
// Add delay to reduce window
delay(10);
access_instance_registers(instance_id);

// But: Delay doesn't eliminate race, just reduces probability
```

---

## Exploitation Challenges

### Challenge 1: Finding WAR Locations

**Difficulty**: MEDIUM
- Requires binary analysis
- WAR functions might be named obscurely
- Might be inlined or optimized away
- Version-specific WAR different between revisions

**Solution**:
- Grep for "war" or "workaround" in function names
- Search for revision-specific code paths
- Disassemble and pattern match

### Challenge 2: Identifying Configuration Flags

**Difficulty**: HIGH
- Flags stored in WPR or runtime state
- Names might be obfuscated
- Multiple levels of indirection
- Driver-controllable vs. hardcoded

**Solution**:
- Trace configuration initialization
- Identify flag storage location
- Map driver control paths
- Determine if externally settable

### Challenge 3: Determining Conditions

**Difficulty**: MEDIUM
- Conditions might be complex
- Multiple flags in boolean combinations
- Timing-dependent conditions
- Debug/production path determination

**Solution**:
- Symbolic execution to find conditions
- Fuzz with different configuration values
- Dynamic analysis to observe behavior
- Test with each revision separately

---

## WAR Function Inventory

### Documented WAR Functions

**File**: `acr_war_functions_ga100.c`

```c
// Partial list based on source analysis
void war_smcinstance_validation(void)      // SMC instance bounds
void war_dma_offset_overflow(void)         // DMA offset arithmetic
void war_fecs_arbitration(void)            // FECS timing race
void war_memory_training_convergence(void) // Training algorithm
void war_clock_switching(void)             // Clock change safety
void war_version_rollback(void)            // Version validation
void war_lsf_parsing_bounds(void)          // LSF parsing bounds
void war_wpr_allocation_algorithm(void)    // WPR allocation
// ... more variants for A1, A2, A3 revisions
```

### Revision-Specific Variants

```
acr_war_functions_ga100_a0.c  → A0-specific WARs
acr_war_functions_ga100_a1.c  → A0+A1 WARs (superset)
acr_war_functions_ga100_a2.c  → A0+A1+A2 WARs
acr_war_functions_ga100_a3.c  → All WARs (including optional)
```

---

## Investigation Roadmap

### WAR Discovery
- [ ] Locate all WAR functions in source/binary
- [ ] Extract logic from each WAR
- [ ] Identify conditions for each WAR
- [ ] Map which WARs are security-critical
- [ ] Identify version-specific variants

### Condition Analysis
- [ ] Determine each WAR's enable/disable condition
- [ ] Identify configuration flags
- [ ] Map driver control paths
- [ ] Test condition satisfaction

### Exploitation Development
- [ ] Develop proof-of-concept for each WAR bypass
- [ ] Chain WAR bypasses for complete security disabling
- [ ] Test on real hardware
- [ ] Document each attack path

### Impact Assessment
- [ ] Measure practical exploitability
- [ ] Determine if WARs can be disabled
- [ ] Test persistence of disabled WARs
- [ ] Document mitigation strategies

---

## Key Questions

**Q1**: Can WAR functions be selectively disabled?  
**A1**: LIKELY - Conditions suggest some WARs are optional

**Q2**: Are security-critical WARs always enabled?  
**A2**: UNKNOWN - Requires binary analysis of conditions

**Q3**: Can driver enable/disable WARs?  
**A3**: POSSIBLY - If configuration flags externally controllable

**Q4**: What is impact of disabling all WARs?  
**A4**: CRITICAL - All security checks bypassed, full GPU control

**Q5**: Are WARs different between revisions?  
**A5**: YES - Version-specific WAR functions for A0, A1, A2, A3

---

## Security Assessment

### Vulnerabilities Introduced by WARs

- [ ] Conditional security checks (can be disabled)
- [ ] Debug/performance paths (may bypass checks)
- [ ] Configuration-based disabling (controllable)
- [ ] Race condition reduction only (doesn't eliminate)
- [ ] Incomplete bounds checks (may miss edge cases)

### Proper WAR Design

Security-critical WARs should:
- [ ] Always be enabled
- [ ] Not be configurable post-boot
- [ ] Have comprehensive validation
- [ ] Include integrity checking
- [ ] Log if ever disabled

### Actual Implementation

Many WARs are likely:
- [ ] Conditional on revision/configuration
- [ ] Disableable for performance
- [ ] Incomplete (don't fix underlying issue)
- [ ] Vary across GA100 revisions

---

## Next Steps

1. **Binary Analysis**:
   - Extract all WAR functions from firmware
   - Identify conditions for each
   - Map configuration flag locations

2. **Exploitation Development**:
   - Develop bypass for each security-critical WAR
   - Test WAR condition bypasses
   - Chain multiple WAR bypasses

3. **Impact Testing**:
   - Test WAR disabling feasibility
   - Measure practical impact
   - Document attack chains

