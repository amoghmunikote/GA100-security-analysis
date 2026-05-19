# 3.1 — Falcon Privilege Boundaries and Architecture

## Overview

The Falcon microcontroller is the central execution engine for GPU firmware, with responsibility for memory management, thermal control, runtime security enforcement, and privilege arbitration. Understanding Falcon's privilege model, exception handling, and code regions is essential for identifying privilege escalation paths and exploit chains.

---

## Falcon Architecture

### Processor Characteristics

**ISA**: Custom 32-bit Harvard-architecture core with Renesas-like ISA
- NOT x86, x86-64, or x86-like; the resemblance is superficial register naming only
- NVIDIA proprietary design; load/store architecture with explicit IMEM/DMEM separation
- Includes privileged HS/LS mode instructions for hardware access
- HS (High Secure) and LS (Low Secure) privilege transitions via hardware authentication

**Memory Model**:
- Flat address space (no segmentation)
- Privilege levels enforced in hardware
- Different code/data regions for privilege levels

**Execution Contexts**:
- Supervisor mode: Full hardware access
- User mode: Restricted operations
- Exception handlers: Privilege escalation window

### Block Diagram

```
┌─────────────────────────────────────────┐
│  Falcon Microcontroller (GA100)         │
├─────────────────────────────────────────┤
│  Privilege Mode 0 (Supervisor)          │
├─ Instruction Memory (Read/Write)        │
├─ Data Memory (Read/Write)               │
├─ All Hardware Registers (Read/Write)    │
└─ Exception Vectors                      │
├─────────────────────────────────────────┤
│  Privilege Mode 1 (User)                │
├─ Instruction Memory (Execute, Limited)  │
├─ Data Memory (Read/Write, Limited)      │
├─ Restricted Hardware Registers          │
└─ Cannot directly escalate privilege     │
└─────────────────────────────────────────┘
```

---

## Privilege Modes

### Mode 0: Supervisor

**Characteristics**:
- Full hardware access
- Can execute privileged instructions
- Can modify privilege state
- Can change register protection

**Accessible Resources**:
- All MMIO registers
- Exception vectors (interrupt table)
- Watchdog timers
- System counters
- Other instance registers (via SMC)

**Typical Code**:
- Boot initialization
- Interrupt handlers
- Fault handlers
- Security enforcement

**Attack Surface**:
- If compromised, complete GPU control
- Can disable security checks
- Can access other instances
- Can modify running instances' code

### Mode 1: User

**Characteristics**:
- Limited hardware access
- Cannot execute privileged instructions
- Cannot directly change privilege level
- Memory-based restriction

**Accessible Resources**:
- Own instruction memory (execute)
- Own data memory (read/write)
- Subset of registers (control registers)
- Cannot access exception vectors

**Typical Code**:
- Memory management algorithms
- Thermal monitoring
- Routine device control
- Non-security-critical operations

**Escalation Paths**:
1. Exception handler entry (trap to supervisor)
2. Privilege escalation gadgets (code in supervisor memory)
3. Hardware vulnerability (timing, side-channel)

---

## Exception Handling

### Exception Vector Table

```c
// Falcon exception vectors (supervisor memory)
typedef struct {
    uint32_t vector_0;   // Exception 0 handler address
    uint32_t vector_1;   // Exception 1 handler address
    uint32_t vector_2;   // Exception 2 handler address
    // ... more vectors
    uint32_t vector_31;  // Exception 31 handler address
} Exception_Vector_Table;

// Vector table base register
#define FALCON_VECTOR_BASE_REG     0x00000000  // Set by supervisor
```

### Exception Types

| Exception | Trigger | Handler | Impact |
|-----------|---------|---------|--------|
| 0 (Reset) | Power-on, Reset signal | Supervisor init | Full reset |
| 1 (NMI) | Non-maskable interrupt | Supervisor handler | Forced execution |
| 2 (Trace) | Instruction execution | Supervisor handler | Single-step capable |
| 3-7 | Reserved | - | - |
| 8 (Breakpoint) | BRK instruction | Supervisor handler | Debug capability |
| 9 (Invalid Opcode) | Illegal instruction | Supervisor handler | Trap mechanism |
| 10-15 | Interrupt (0-5) | Supervisor handler | External signals |
| 16-31 | Reserved | - | - |

### Exception Handling Flow

```
User-Mode Code
    ↓
Trigger Exception (e.g., divide by zero)
    ↓
Hardware: Save PC, switch to supervisor mode
    ↓
Read exception vector from table
    ↓
Jump to handler address (supervisor code)
    ↓
Handler: Process exception
    ↓
Handler: Return to user mode (RET instruction)
    ↓
User-Mode Code Continues
```

### Privilege Escalation Opportunity

**Window of Opportunity**:
```
Exception Handler
├─ Executes in supervisor mode
├─ Full hardware access
├─ Can modify privilege state
├─ Can be exploited if compromised
└─ Can load user-provided code

Attack:
1. Trigger exception (divide by zero, invalid opcode)
2. Handler loads corrupted exception vector
3. Jump to attacker-controlled supervisor code
4. Execute privileged operations
5. Return to user mode with privilege granted
```

---

## Memory Layout

### Instruction Memory

```
Falcon Instruction Memory:
0x00000 - 0x0FFFF: Supervisor Code (64KB)
│ ├─ Boot code
│ ├─ Exception handlers
│ ├─ Memory training algorithm
│ ├─ Interrupt handlers
│ └─ System utilities

0x10000 - 0x1FFFF: User Code (64KB)
│ ├─ Memory management
│ ├─ Thermal monitoring
│ ├─ Device control
│ └─ Routine operations

0x20000 - 0x2FFFF: Shared/Dynamic (optional)
```

### Data Memory

```
Falcon Data Memory:
0x00000 - 0x03FFF: Supervisor Data (16KB)
│ ├─ Exception vectors
│ ├─ System state
│ ├─ Hardware configuration
│ └─ Keys and sensitive data

0x04000 - 0x07FFF: User Data (16KB)
│ ├─ Memory training results
│ ├─ Temperature sensors
│ ├─ Device status
│ └─ Routine state

0x08000 - 0x0FFFF: Stack (32KB)
```

### Protection Enforcement

```c
// Data memory protection (supervisor-only)
#define DATA_PROT_SUPERVISOR_ONLY   0x1
#define DATA_PROT_USER_READABLE     0x2
#define DATA_PROT_USER_WRITABLE     0x4

// Each address range has protection flags
// Hardware enforces access based on privilege mode
```

---

## Watchdog Timer and Panic Handlers

### Watchdog Mechanism

```c
// Watchdog timer for detecting firmware hangs
typedef struct {
    uint32_t counter;        // Counts down to zero
    uint32_t threshold;      // Reset value when counter reaches zero
    uint32_t enable_flag;    // 1 = enabled
    uint32_t interrupt_flag; // 1 = trigger interrupt on timeout
} Watchdog_Timer;
```

**Watchdog Flow**:
```
Timer enabled
    ↓
Counter decrements every cycle
    ↓
Reaches zero?
    ├─ YES: Interrupt triggered
    │  ├─ Handler executes (supervisor)
    │  ├─ Can recover or reset
    │  └─ System continues or restarts
    └─ NO: Reload threshold and continue
```

### Panic Handler

```c
void panic(const char* msg) {
    // Trigger exception that enters supervisor mode
    // Supervisor panic handler:
    //   ├─ Log error message
    //   ├─ Disable interrupts
    //   ├─ Disable user code execution
    //   ├─ Wait for watchdog reset OR
    //   └─ Manual reset by host driver
}
```

**Vulnerability Window**: During panic handler, supervisor code executes. If panic handler is compromised, full GPU control possible.

---

## Context Switching and State Preservation

### Register State

```c
// Falcon register set (pseudocode — actual registers are $r0..$r15 in Renesas-like 32-bit ISA)
// NOTE: eax/ebx/eip/eflags naming below is conceptual only; Falcon does NOT use x86 registers
typedef struct {
    uint32_t r[16];         // 16 general-purpose 32-bit registers ($r0 .. $r15)
    uint32_t pc;            // Program counter
    uint32_t sp;            // Stack pointer ($r15 typically)
    uint32_t iv[2];         // Exception vectors (IV0, IV1)
    uint32_t csw;           // Control/status word (privilege level)
} Falcon_Registers;
```

### Context Preservation on Exception

```
User Code
    ↓
Exception triggered
    ↓
Hardware saves state:
├─ Current PC (instruction pointer)
├─ EFlags (including privilege bit)
├─ All general registers
└─ Stack pointer

Handler executes
    ↓
Handler prepares return:
├─ Restores saved registers (except EIP)
├─ Sets return address
├─ RET instruction
    ↓
Hardware:
├─ Loads return address
├─ Restores privilege mode
├─ Continues execution
```

### Stack Manipulation Attack

```
Attack Scenario:
1. User code triggers exception (controlled)
2. Handler saves registers to stack
3. Malicious user code corrupts stack
4. Handler attempts to restore state
5. Return address corrupted
6. Execution continues at attacker address
7. Privilege escalation achieved
```

---

## Instruction Set Features

### Privileged Instructions

```c
// Examples of privileged instructions (supervisor only)
MOV reg, privileged_register  // Read protected register
MOV privileged_register, reg  // Write protected register
IRET                         // Return from interrupt (mode switch)
STI                          // Enable interrupts
CLI                          // Disable interrupts
HLT                          // Halt execution
```

### Non-Privileged Instructions

```c
// User code can execute
MOV reg, value              // General operations
ADD, SUB, MUL, DIV          // Arithmetic
JMP, CALL, RET              // Control flow
LOAD, STORE                 // Memory access (limited)
```

### Instruction-Based Detection

Illegal instruction in user mode triggers exception:
```
User Code: MOV reg, privileged_register
    ↓
Hardware detects privileged instruction in user mode
    ↓
Exception 9 (Invalid Opcode) triggered
    ↓
Handler executes in supervisor mode
    ↓
Handler can: Emulate, reject, or execute privileged op
```

---

## Privilege Escalation Gadgets

### ROP (Return-Oriented Programming)

If supervisor code can be manipulated, return-oriented programming enables privilege escalation:

```c
// Gadget 1: Load register with supervisor-only value
// loc_12345: MOV eax, [privileged_mem]
//            RET

// Gadget 2: Execute privileged instruction
// loc_12346: MOV [control_reg], eax
//            RET

// Gadget 3: Disable security check
// loc_12347: MOV [security_flag], 0
//            RET

// Attack: Chain gadgets
// 1. Return to gadget 1 (load sensitive value)
// 2. Return to gadget 2 (modify control register)
// 3. Return to gadget 3 (disable security)
// 4. Return to attacker payload
```

### Code Injection Attack

If supervisor code region is writable:
```
1. User code modifies supervisor memory (via bug)
2. Injects malicious supervisor code
3. Triggers exception
4. Exception handler jumps to injected code
5. Malicious code executes in supervisor mode
6. Disables all security checks
7. Allows any operations
```

---

## Threat Model

### User-Mode Attacker

**Capabilities**:
- Execute user-mode code
- Read/write user memory
- Trigger exceptions
- Make MMIO reads (limited)

**Limitations**:
- Cannot execute privileged instructions
- Cannot modify exception vectors
- Cannot access supervisor memory
- Cannot change privilege level directly

**Attack Path**:
```
User code
    ↓
Discover privilege escalation gadget
    ↓
Trigger exception with crafted stack
    ↓
Exception handler executes gadget
    ↓
Supervisor code execution achieved
    ↓
Disable security, grant privileges
```

### Supervisor-Mode Attacker

**Capabilities**:
- Full instruction set
- Modify exception vectors
- Disable security checks
- Configure hardware (SMC, MIG, etc.)
- Access other instances

**Attack Path**:
```
Compromise supervisor code
    ↓
Disable all isolation boundaries
    ↓
Compromise other instances
    ↓
Persistent firmware modification
```

---

## Known Vulnerabilities in Falcon

### 1. Privilege Escalation via Exception Handler

**Location**: Exception vector table in supervisor memory

**Vulnerability**: If exception handler can be controlled, privilege escalation possible

**Exploitation**:
```
1. Craft corrupted stack frame
2. Trigger exception (divide by zero, etc.)
3. Handler tries to restore corrupted registers
4. Return address overwritten
5. Jump to attacker payload
6. Payload executes in supervisor mode
```

### 2. Memory Corruption in Supervisor Region

**Location**: Supervisor data/code regions

**Vulnerability**: If user code can write to supervisor memory, arbitrary code execution possible

**Exploitation**:
```
1. Find memory corruption bug in user code
2. Write malicious supervisor code
3. Trigger exception
4. Exception handler jumps to malicious code
5. Supervisor privilege gained
```

### 3. Stack Overflow

**Location**: Shared stack between modes

**Vulnerability**: Stack overflow can corrupt supervisor data, exception vectors

**Exploitation**:
```
1. Large buffer allocation in user mode
2. Overflow stack into supervisor region
3. Overwrite exception vector or return address
4. Trigger exception
5. Jump to attacker code
```

### 4. Side-Channel Attacks

**Location**: Instruction timing, cache timing

**Vulnerability**: Supervisor code timing might leak sensitive information

**Exploitation**:
```
1. Measure execution time of exception handler
2. Different times for different secret values
3. Deduce secret through statistical analysis
4. Extract keys or privilege boundaries
```

---

## Security Properties

### What Should Be Protected

- [ ] Exception vectors in read-only supervisor memory
- [ ] Privilege mode register (hardware-enforced)
- [ ] Supervisor instruction/data memory (no user write access)
- [ ] Stack isolation (separate stack per mode)
- [ ] Instruction decode (prevent privilege escalation in user mode)
- [ ] Context switching (validate saved state before restoration)

### Current Implementation Gaps

- [ ] Exception vector table location may be writable
- [ ] Stack may be shared and vulnerable to overflow
- [ ] Supervisor code may be relocatable post-verification
- [ ] Return address validation may be missing
- [ ] Instruction profiling may leak privilege state

---

## Investigation Roadmap

### Extract Falcon ISA
- [ ] Disassemble prebuilt GA100-gsp firmware
- [ ] Identify instruction set extensions
- [ ] Extract privileged instructions
- [ ] Map exception handling code

### Analyze Privilege Boundaries
- [ ] Locate exception vector table
- [ ] Identify privilege mode enforcement
- [ ] Map supervisor/user memory regions
- [ ] Find protection enforcement mechanism

### Identify Escalation Paths
- [ ] Find exception handlers in code
- [ ] Analyze stack handling
- [ ] Identify ROP gadgets
- [ ] Test stack overflow impact

### Develop Exploit
- [ ] Craft malicious exception frame
- [ ] Test privilege escalation
- [ ] Achieve supervisor code execution
- [ ] Disable security checks

---

## Key Questions

**Q1**: Can exception vectors be modified post-verification?  
**A1**: LIKELY - If supervisor memory is writable after boot

**Q2**: Are there privilege escalation gadgets in Falcon code?  
**A2**: LIKELY - Custom 32-bit RISC-like ISA with load/store architecture; ROP gadgets possible but analysis requires actual binary disassembly (see `7-2-phase3-binary-analysis.md`)

**Q3**: Can stack overflow corrupt exception vectors?  
**A3**: UNKNOWN - Depends on memory layout and stack isolation

**Q4**: Are instruction profiling differences observable?  
**A4**: POSSIBLY - Side-channels may leak privilege state

**Q5**: What is the impact of Falcon compromise?  
**A5**: CRITICAL - Full GPU control, disable all isolation, compromise other instances

---

## Next Steps

1. **Binary Analysis**:
   - Extract Falcon ISA from firmware binaries
   - Map privilege mode enforcement in hardware
   - Identify all exception handlers

2. **Vulnerability Assessment**:
   - Test for stack overflow in supervisor
   - Analyze exception handler for weaknesses
   - Identify ROP gadget chains

3. **Exploitation**:
   - Develop privilege escalation proof-of-concept
   - Test supervisor code execution
   - Document complete attack chain

