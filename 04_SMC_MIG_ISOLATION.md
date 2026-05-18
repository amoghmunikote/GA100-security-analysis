# SMC/MIG Isolation - Multi-Instance Architecture

## Overview

GA100 introduces Simultaneous Multi-Client (SMC) architecture, allowing multiple independent GPU contexts to execute in parallel. This provides higher throughput but introduces new security boundaries: each client must be isolated from others through register-based multiplexing and hardware arbitration.

**Key Concept**: Multiple clients share GPU hardware but access instance-specific register banks through address offset calculations.

---

## SMC Architecture

### Purpose

**Traditional GPU**: Single context at a time
```
GPU Resources: [Register Bank] [Memory Controller] [Execution Engines]
     ↑
   Single Client
```

**SMC GPU**: Multiple contexts simultaneously
```
GPU Resources: [Register Bank 0] [Memory Controller] [Execution Engines]
                [Register Bank 1]         ↑
                [Register Bank 2]    Multiple Clients
                [Register Bank 3]
```

### Instance-Based Addressing

Each SMC client has independent register banks accessed through calculated offsets:

```c
// Base formula for instance-specific register access
uint32_t get_instance_register(uint32_t base_reg, uint32_t instance_id) {
    return base_reg + (instance_id * REGISTER_STRIDE);
}

// Example:
// Base: 0x600000 (DMA controller)
// Stride: 0x10000 (64KB per instance)
// Instance 0: 0x600000
// Instance 1: 0x610000
// Instance 2: 0x620000
// Instance 3: 0x630000
```

### Hardware Components

**Register Banks**:
- Each instance has isolated register set
- DMA configuration registers
- Memory controller registers
- Context state registers
- Interrupt handlers

**Hardware Arbiters**:
- FECS (Front-End Coherence System) - DMA arbitration
- SMC arbiter - Register access routing
- Interrupt controller - Per-instance handling

**Shared Resources**:
- Main memory (partitioned by MIG)
- Bandwidth allocation (QoS)
- Power budgets

---

## NV_GET_PGRAPH_SMC_REG Macro

### Purpose
Central macro for instance-aware register access throughout GPU driver and firmware

### Implementation

```c
// From register header files
#define NV_GET_PGRAPH_SMC_REG(base, instance, offset) \
    ((base) + ((instance) * SMC_REG_STRIDE) + (offset))

// Usage:
uint32_t reg = NV_GET_PGRAPH_SMC_REG(0x600000, 2, 0x100);
// Result: 0x600000 + (2 * 0x10000) + 0x100 = 0x620100
```

### Trust Model

**Implicit Assumptions**:
1. `instance` parameter is in valid range [0, SMC_INSTANCE_COUNT)
2. `base` register address is legitimate
3. `offset` within base register region
4. No overflow in address calculation
5. Calculated address doesn't cross privilege boundaries

**Critical Gap**: **No validation of `instance` parameter**

### Vulnerability Window

```c
// Vulnerable usage pattern
void configure_dma_for_instance(uint32_t instance) {
    // No validation
    uint32_t dma_config_reg = NV_GET_PGRAPH_SMC_REG(DMA_BASE, instance, CONFIG_OFFSET);
    mmio_write(dma_config_reg, config_value);  // ← MMIO write to computed address
}

// Attack:
// - Attacker sets instance = 0xFFFFFFFF (invalid)
// - Computed address = DMA_BASE + (0xFFFFFFFF * 0x10000) + CONFIG_OFFSET
// - Address wraps or points to different hardware region
// - Firmware configures unintended register
```

---

## SMC Instance Isolation Enforcement

### Isolation Levels

**Level 1: Register Bank Isolation**
- Each instance has separate register set
- Instance 0 cannot directly read/write Instance 1's registers
- Register addressing automatically routes to correct bank
- **Gap**: Address calculation assumes valid instance ID

**Level 2: Memory Partition Isolation** (MIG)
- Physical memory divided into per-instance partitions
- Instance 0 cannot access Instance 1's memory
- Hardware enforces address range checking
- **Gap**: FECS arbitration uses unchecked instance ID

**Level 3: Interrupt Isolation**
- Per-instance interrupt handling
- Instance 0 interrupts don't affect Instance 1
- **Gap**: Interrupt routing may use unchecked instance ID

### Isolation Bypass Scenarios

**Scenario 1: Instance ID Validation Bypass**
```
Step 1: Firmware receives instance ID from driver (untrusted)
Step 2: No validation of instance ID range
Step 3: Instance ID used in NV_GET_PGRAPH_SMC_REG macro
Step 4: Address calculation overflows or wraps
Step 5: MMIO write targets wrong hardware region
Result: Register isolation bypass
```

**Scenario 2: DMA Misdirection**
```
Step 1: DMA controller configured for instance X
Step 2: Instance ID used in FECS arbitration
Step 3: Calculated address points to other instance's memory
Step 4: DMA transfers between wrong memory regions
Result: Memory isolation bypass
```

**Scenario 3: Cross-Instance Write**
```
Step 1: Configure register for instance 0
Step 2: Overflow address calculation
Step 3: Target instance 1's register region
Step 4: Write privileged configuration register
Result: Privilege escalation between instances
```

---

## FECS (Front-End Coherence System)

### Purpose
DMA arbiter managing physical memory access from GPU to system RAM

### Architecture

```
GPU Clients → FECS Arbiter → System Memory

Instance 0 DMA Request → [Queue 0] ─┐
Instance 1 DMA Request → [Queue 1] ─┼→ [Arbitration Logic] → Memory Controller
Instance 2 DMA Request → [Queue 2] ─┤
Instance 3 DMA Request → [Queue 3] ─┘
                                ↑
                        Instance ID determines
                        which request is granted access
```

### DMA Request Structure

```c
typedef struct {
    uint32_t source_address;       // Source data location
    uint32_t dest_address;         // Destination data location
    uint32_t transfer_size;        // Number of bytes
    uint32_t instance_id;          // Which client owns this request
    uint32_t direction;            // READ or WRITE
    uint32_t priority;             // QoS priority
} DMA_Request;
```

### Instance-Based Arbitration

**FECS Decision Logic**:
```
For each DMA request:
1. Read instance_id from request
2. Calculate instance's memory partition using:
   partition_base = MEMORY_BASE + (instance_id * PARTITION_SIZE)
3. Validate source/dest within partition
4. Grant access if within partition
5. Otherwise, reject request
```

**Critical Gap**: If instance_id not validated in step 1-2, wrong partition boundaries applied

### Vulnerability: Unvalidated Instance ID

```c
// In FECS arbitration code
void arbitrate_dma(DMA_Request* req) {
    uint32_t instance_id = req->instance_id;  // From firmware (untrusted)
    
    // CRITICAL: No validation
    // instance_id should be [0, SMC_INSTANCE_COUNT)
    
    uint64_t partition_base = PARTITION_BASE + (instance_id * PARTITION_STRIDE);
    
    if (req->source >= partition_base && req->source < partition_base + PARTITION_SIZE) {
        // Allow DMA
    }
}
```

**Exploit**:
1. Set `instance_id = 0xFFFFFFFF` (invalid)
2. Calculate partition: `base + (0xFFFFFFFF * stride)`
3. Address wraps to negative offset or different partition
4. Partition boundary check fails or passes incorrectly
5. DMA access redirected to attacker-chosen address

---

## Register Definitions

### SMC Registers (From dev_smcarb.h)

```c
// SMC Arbiter Base Address
#define NV_PSMCARB_BASE                     0x00600000

// Per-instance stride
#define NV_SMCARB_STRIDE                    0x00010000 (64KB)

// Instance count (GA100-specific)
#define NV_GA100_SMCARB_INSTANCE_COUNT      8

// Register offsets within each instance
#define NV_SMCARB_CONFIG_OFFSET             0x00000000
#define NV_SMCARB_STATUS_OFFSET             0x00000004
#define NV_SMCARB_INTERRUPT_OFFSET          0x00000008
#define NV_SMCARB_PRIORITY_OFFSET           0x0000000C

// Example: Access instance 2's config register
uint32_t addr = 0x600000 + (2 * 0x10000) + 0x00 = 0x620000
```

### FECS Registers (From dev_fbfalcon_csb.h)

```c
// FECS Base Address
#define NV_PFECS_BASE                       0x00400000

// DMA configuration registers
#define NV_PFECS_DMA_CONFIG_OFFSET          0x00000100
#define NV_PFECS_DMA_STATUS_OFFSET          0x00000104
#define NV_PFECS_DMA_INTERRUPT_OFFSET       0x00000108

// Instance-aware DMA access
uint32_t dma_reg = 0x400000 + (instance_id * 0x10000) + 0x100
```

### Memory Partition Registers

```c
// Memory controller - per-instance configuration
#define NV_PFBPA_BASE                       0x00900000
#define NV_FBPA_STRIDE                      0x00010000

// Instance-specific memory partition
// Registers for configuring address range per instance
#define NV_PFBPA_PARTITION_BASE_OFFSET      0x00000200
#define NV_PFBPA_PARTITION_LIMIT_OFFSET     0x00000204
```

---

## MIG (Multi-Instance GPU)

### Purpose
Hardware-based partitioning enabling isolated GPU regions with independent resources

### MIG Architecture

```
GPU Resources:
├─ Compute Cores:      [SMs 0-10] [SMs 11-20] [SMs 21-31]
├─ Memory:             [Partition 0] [Partition 1] [Partition 2]
├─ Bandwidth:          [QoS 0] [QoS 1] [QoS 2]
└─ Power Budget:       [Watts 0] [Watts 1] [Watts 2]

Each instance is allocated a fixed subset of resources
```

### Instance Configuration

```c
typedef struct {
    uint32_t compute_units;    // Number of SMs allocated
    uint64_t memory_base;      // Start of memory partition
    uint64_t memory_limit;     // End of memory partition
    uint32_t bandwidth_limit;  // GB/s allocated
    uint32_t power_limit;      // Watts allocated
} MIG_Instance_Config;
```

### Isolation Enforcement

**Hardware Level**:
- Memory access checking: Address must be in [base, limit]
- Register routing: Instance ID routes to correct bank
- Interrupt handling: Per-instance interrupt vector

**Firmware Level**:
- Instance ID validation (SHOULD occur, often missing)
- Quota enforcement (memory, bandwidth, power)
- Error handling and isolation breach recovery

### Interaction with SMC

**SMC + MIG Combined**:
```
SMC provides register-level isolation (virtual)
MIG provides memory-level isolation (hardware)

Both rely on instance ID being valid and properly validated
```

---

## Vulnerability Analysis

### Vuln #1: SMC Instance Not Validated (Detailed)

**Attack Surface Expanded**:
1. DMA configuration: Direct MMIO access to DMA registers
2. Memory configuration: Modify memory partition boundaries
3. Interrupt configuration: Redirect interrupts to other instances
4. Register access: Read/write other instance's state
5. Privilege escalation: Configure registers affecting all instances

**Exploitability Chain**:
```
Step 1: Firmware accepts instance ID from LSF descriptor
Step 2: No range check (0 to 7 valid for GA100)
Step 3: Use in NV_GET_PGRAPH_SMC_REG with invalid value
Step 4: Calculate address = base + (invalid_id * stride)
Step 5: MMIO write to calculated address
Step 6: Compromise target hardware/instance
```

**Register Targets** (valuable exploitation targets):
- DMA configuration (control data movement)
- Memory partition limits (expand instance memory)
- Interrupt vectors (redirect exceptions)
- Clock gating (disable instance resources)
- Reset signals (crash instance)

### Mitigation Gaps

**Missing Validation Checks**:
```c
// Should have but probably missing:
if (instance_id >= GA100_INSTANCE_COUNT) {
    return error;
}
if (instance_id >= runtime_active_instances) {
    return error;
}
```

**No Address Boundary Checking**:
```c
// Should validate calculated address:
uint32_t calculated_addr = base + (instance_id * stride);
if (calculated_addr < base || calculated_addr > address_space_limit) {
    return error;
}
```

---

## Investigation Roadmap

### Phase 1: Understand Instance ID Flow
- [ ] Trace instance ID from driver through firmware
- [ ] Identify all uses of NV_GET_PGRAPH_SMC_REG macro
- [ ] Document places where instance ID is used without validation
- [ ] Extract register definitions (dev_smcarb.h, dev_fbfalcon_csb.h)

### Phase 2: Validate Vulnerability
- [ ] Confirm maximum valid instance ID for GA100
- [ ] Check if instance ID validation exists
- [ ] Test with out-of-bounds instance ID in binary
- [ ] Identify address calculation results

### Phase 3: Map Exploitation Surface
- [ ] Identify valuable register targets
- [ ] Test register write impact
- [ ] Determine memory layout (address space positions)
- [ ] Develop proof-of-concept exploit

### Phase 4: Impact Assessment
- [ ] Can instance isolation be completely bypassed?
- [ ] Can firmware from one instance compromise another?
- [ ] Can persistent compromise be achieved?
- [ ] What is impact on GPU functionality?

---

## Key Questions

**Q1**: Is instance ID validated before use in register addressing?  
**A1**: NO - Source code shows direct use without bounds checking in `acr_dma_ga100.c`

**Q2**: What are the consequences of invalid instance ID?  
**A2**: Address calculation overflows or wraps, accessing unintended memory regions

**Q3**: Can an attacker selectively compromise one instance?  
**A3**: LIKELY - Instance ID from firmware can be crafted, enabling single-instance attack

**Q4**: Can instance isolation be completely bypassed?  
**A4**: LIKELY - Combined with other vulnerabilities (LSF parsing), full isolation bypass possible

**Q5**: What registers should be protected?  
**A5**: DMA config, memory partition limits, interrupt vectors, reset signals, clock control

---

## Next Steps

1. **Confirmation Testing**:
   - Binary analysis of `acr_dma_ga100.c`
   - Confirm instance ID validation is missing
   - Extract NV_GET_PGRAPH_SMC_REG implementations

2. **Exploitation Planning**:
   - Craft LSF with invalid instance ID
   - Calculate target register addresses
   - Test MMIO write impact

3. **Impact Demonstration**:
   - Develop proof-of-concept bypass
   - Show cross-instance compromise
   - Document practical attack scenarios

