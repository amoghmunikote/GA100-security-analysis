# IPC and Command Interfaces - Host-Firmware Communication

## Overview

The GPU driver and Falcon firmware communicate through well-defined interfaces: MMIO command submission, ring buffers, and permission-based command dispatch. These interfaces are the attack surface for host-initiated exploits and privilege escalation attacks.

---

## IPC Architecture

### Communication Channels

```
CPU Driver
    ↓
PCIe/BAR0 (MMIO)
    ↓
GPU Registers
    ↓
Falcon Firmware
    ↓
GPU Resources
```

### Message Types

**Host → Firmware**:
- Graphics command submissions
- Power management requests
- Memory configuration
- Diagnostic commands

**Firmware → Host**:
- Completion notifications
- Error reporting
- Performance metrics
- Status information

---

## MMIO Command Submission

### Command Queue Registers

```c
// Registers for command submission (BAR0 offsets)
#define CMD_QUEUE_BASE              0x00100000
#define CMD_QUEUE_STRIDE            0x00001000  // Per-instance stride
#define CMD_QUEUE_HEAD              0x00000000  // Read pointer
#define CMD_QUEUE_TAIL              0x00000004  // Write pointer
#define CMD_QUEUE_CONTROL           0x00000008  // Enable/disable
#define CMD_QUEUE_STATUS            0x0000000C  // Full/empty flags
#define CMD_QUEUE_INTERRUPT         0x00000010  // Interrupt config

// Calculated address for instance N:
// base = CMD_QUEUE_BASE + (N * CMD_QUEUE_STRIDE)
// register_addr = base + offset
```

### Command Format

```c
// Standard command structure
typedef struct {
    uint32_t header;           // Command type and flags
    uint32_t payload[3];       // Command-specific data
    uint64_t timestamp;        // Optional timestamp
} Command;

// Header fields
#define CMD_TYPE_MASK           0x00FF0000
#define CMD_TYPE_GRAPHICS       0x00010000
#define CMD_TYPE_COMPUTE        0x00020000
#define CMD_TYPE_POWER          0x00030000
#define CMD_TYPE_DIAGNOSTIC     0x000F0000

#define CMD_SUBTYPE_MASK        0x0000FF00
#define CMD_FLAGS_MASK          0x000000FF
```

---

## Ring Buffers

### Ring Buffer Structure

```c
typedef struct {
    uint64_t buffer_address;   // Virtual address of ring buffer
    uint32_t buffer_size;      // Size in bytes (typically 4MB)
    uint32_t head;             // Current read position
    uint32_t tail;             // Current write position
    uint32_t entry_size;       // Size of each entry
    uint32_t max_entries;      // Total entries available
} Ring_Buffer;
```

### Buffer Layout

```
Ring Buffer (4MB):
┌─────────────────────────┐
│ Entry 0 (256 bytes)     │ ← Head (read pointer)
├─────────────────────────┤
│ Entry 1 (256 bytes)     │
├─────────────────────────┤
│ Entry 2 (256 bytes)     │
├─────────────────────────┤
│ ...                     │
├─────────────────────────┤
│ Entry N (256 bytes)     │ ← Tail (write pointer)
├─────────────────────────┤
│ Empty space             │
└─────────────────────────┘
```

### Ring Buffer Operations

**Enqueue Command** (Driver):
```c
void enqueue_command(Ring_Buffer* rb, Command* cmd) {
    // 1. Check if space available
    if ((rb->tail + 1) % rb->max_entries == rb->head) {
        return RING_FULL;  // No space
    }
    
    // 2. Write command to buffer
    uint8_t* entry = rb->buffer_address + (rb->tail * rb->entry_size);
    memcpy(entry, cmd, sizeof(Command));
    
    // 3. Update tail pointer
    rb->tail = (rb->tail + 1) % rb->max_entries;
    
    // 4. Notify firmware (MMIO write)
    mmio_write(TAIL_REGISTER, rb->tail);
}
```

**Dequeue Command** (Firmware):
```c
Command* dequeue_command(Ring_Buffer* rb) {
    // 1. Check if commands available
    if (rb->head == rb->tail) {
        return NULL;  // Ring empty
    }
    
    // 2. Get command from buffer
    uint8_t* entry = rb->buffer_address + (rb->head * rb->entry_size);
    Command* cmd = (Command*)entry;
    
    // 3. Update head pointer
    rb->head = (rb->head + 1) % rb->max_entries;
    
    // 4. Return command
    return cmd;
}
```

### Ring Buffer Vulnerabilities

**Vulnerability 1: Unchecked Buffer Address**
```c
// Driver specifies ring buffer address in WPR or driver memory
if (ring_buffer_address > WPR_LIMIT) {
    return ERROR;  // May be missing validation
}
```

**Attack**: Point ring buffer to sensitive memory, read/write firmware data

**Vulnerability 2: Buffer Overflow**
```c
// Firmware doesn't validate entry_size
uint8_t* entry = rb->buffer_address + (rb->tail * 0x1000);
if (entry + cmd_size > rb->buffer_address + rb->buffer_size) {
    // May not check this
    memcpy(entry, cmd, cmd_size);  // Can overflow
}
```

**Attack**: Overflow command buffer to corrupt WPR

**Vulnerability 3: Use-After-Free**
```c
// Driver doesn't validate tail pointer
Command* cmd = (Command*)(buffer + driver_controlled_tail * entry_size);
// If driver updates tail while firmware is processing command
// Firmware reads already-processed command
```

**Attack**: Re-process commands with side effects

---

## Command Permission Checking

### Permission Model

```c
// Each command type has permission requirements
typedef struct {
    uint16_t command_id;
    uint8_t required_privilege;  // SUPERVISOR, USER, PUBLIC
    uint8_t required_context;    // Graphics, Compute, System
    uint32_t allowed_registers;  // Bitmap of accessible registers
} Command_Permission;

// Permission levels
#define PRIVILEGE_PUBLIC       0  // Any context
#define PRIVILEGE_USER         1  // Privileged user context
#define PRIVILEGE_SUPERVISOR   2  // GPU supervisor only
```

### Permission Check Flow

```
Driver submits command
    ↓
Firmware receives command
    ↓
Extract command ID
    ↓
Look up permission table:
├─ Get required privilege level
├─ Get required context
├─ Get allowed registers
    ↓
Validate submitter privilege:
├─ If required != PUBLIC
│  ├─ Check driver privilege
│  └─ Verify authorization
    ↓
Validate command payload:
├─ Check registers accessed are allowed
├─ Validate data ranges
    ↓
Grant or deny execution
```

### Permission Table

```c
// Example permission entries
Command_Permission permissions[] = {
    { CMD_GRAPHICS_SUBMIT,    PRIVILEGE_PUBLIC,     CTX_GRAPHICS, 0x0000FFFF },
    { CMD_POWER_SHUTDOWN,     PRIVILEGE_SUPERVISOR, CTX_SYSTEM,   0xFFFFFFFF },
    { CMD_MEMORY_CONFIG,      PRIVILEGE_USER,       CTX_SYSTEM,   0x00FF0000 },
    { CMD_DIAGNOSTIC_READ,    PRIVILEGE_SUPERVISOR, CTX_SYSTEM,   0xFFFFFFFF },
};
```

### Vulnerability: Incomplete Permission Checks

**Missing Privilege Validation**:
```c
// Permission check missing
case CMD_POWER_CONFIG:
    // Should check PRIVILEGE_SUPERVISOR
    // But might not if code path bypassed
    execute_command(cmd);  // Executes without privilege check
```

**Attack**: Submit privileged command without authorization

**Missing Payload Validation**:
```c
case CMD_MEMORY_CONFIG:
    uint64_t address = cmd->payload[0];
    uint32_t size = cmd->payload[1];
    
    // Missing range check
    // What if address + size overflows?
    // What if address is in WPR?
    configure_memory(address, size);
```

**Attack**: Configure arbitrary memory region

---

## Command Dispatch Tables

### Dispatch Logic

```c
// Central command dispatcher
void handle_command(Command* cmd) {
    uint32_t cmd_id = cmd->header & CMD_TYPE_MASK;
    uint32_t cmd_subtype = cmd->header & CMD_SUBTYPE_MASK;
    
    // Lookup handler function
    Command_Handler handler = dispatch_table[cmd_id][cmd_subtype];
    
    if (handler == NULL) {
        return INVALID_COMMAND;
    }
    
    // Call handler
    return handler(cmd);
}

// Dispatch table (array of function pointers)
Command_Handler dispatch_table[256][256] = {
    // Entry [0x01][0x00] = graphics_submit_handler
    // Entry [0x03][0x02] = power_shutdown_handler
    // etc.
};
```

### Dispatch Table Vulnerabilities

**Vulnerability 1: Uninitialized Entries**
```c
// Dispatch table not fully initialized
dispatch_table[0x10][0x00] = NULL;  // Uninitialized

// If command sent with this ID
if (dispatch_table[cmd_id][cmd_sub] != NULL) {
    // NULL pointer dereference
    ((void (*)(Command*))dispatch_table[cmd_id][cmd_sub])(cmd);
}
```

**Attack**: Crash firmware or cause undefined behavior

**Vulnerability 2: Overlapping Handlers**
```c
// Two command types use same handler
dispatch_table[0x01][0x00] = graphics_handler;  // Graphics
dispatch_table[0x02][0x00] = graphics_handler;  // Compute (wrong!)

// If compute command uses graphics semantics
// Unintended behavior or privilege escalation
```

**Attack**: Confuse handler logic, bypass permission checks

**Vulnerability 3: Out-of-Bounds Dispatch**
```c
// Command ID not properly masked
uint32_t cmd_id = cmd->header;  // Full word, not masked

// Array access might be out-of-bounds
if (cmd_id > 256) {
    // Should reject, but might not
}
handler = dispatch_table[cmd_id];  // OOB read
```

**Attack**: Read arbitrary memory, gain information for further exploitation

---

## Data Path Security

### Command Data Integrity

**Concern**: Command data could be modified in transit (ring buffer → firmware)

**Example Attack**:
```
1. Driver writes command to ring buffer
2. Firmware starts reading command from ring buffer
3. Driver modifies command while firmware is processing it
4. Firmware uses inconsistent data (TOCTOU - Time of Check, Time of Use)
```

### Data Validation

**What Should Be Done**:
```c
// Firmware should make local copy of command
Command cmd_copy;
memcpy(&cmd_copy, ring_buffer_entry, sizeof(Command));

// Use local copy for all validation and execution
validate_command(&cmd_copy);
execute_command(&cmd_copy);
```

**What Might Happen**:
```c
// Firmware might read directly from ring buffer
Command* cmd = (Command*)(ring_buffer + offset);

// If driver modifies ring buffer entry during processing
// Firmware uses modified data
validate_command(cmd);  // Check with original data
execute_command(cmd);   // Execute with modified data (possible inconsistency)
```

### Vulnerability: Race Condition

**Scenario**:
```
Time T0: Firmware reads command type (valid graphics command)
Time T1: Driver modifies command type to supervisor-only operation
Time T2: Firmware checks permission (sees graphics, grants access)
Time T3: Firmware executes command (now a supervisor command!)
```

**Impact**: Privilege escalation through TOCTOU race condition

---

## IPC Attack Surface Summary

### Ring Buffer Attacks
- [ ] Arbitrary address ring buffer → read/write any GPU memory
- [ ] Overflow ring buffer → corrupt WPR
- [ ] Race condition in head/tail pointer → re-process commands
- [ ] Invalid buffer address → crash or exploit

### Command Submission Attacks
- [ ] Send unpermitted command → execute privileged operation
- [ ] Craft malicious command payload → overflow, corruption
- [ ] Modify command in transit → TOCTOU exploitation
- [ ] Send invalid command ID → dispatch table OOB read

### Permission Bypass
- [ ] Missing privilege checks → supervisor command execution
- [ ] Missing payload validation → arbitrary writes
- [ ] Dispatch table confusion → wrong handler execution
- [ ] Context confusion → privilege escalation

### Information Disclosure
- [ ] Dispatch table OOB read → leak memory
- [ ] Invalid command handling → error message leaks
- [ ] Timing side-channel → infer secret state
- [ ] Ring buffer address disclosure → leak WPR location

---

## Vulnerability Scenario: Unauthorized Shutdown

### Exploit Outline

**Goal**: Execute supervisor-only power shutdown command without privilege

**Prerequisites**:
- Know command ID for power shutdown
- Know permission table implementation
- Find permission check bypass

**Attack Steps**:

```
Step 1: Send power shutdown command
├─ Command ID = CMD_POWER_SHUTDOWN
└─ Send through driver as normal user

Step 2: Firmware receives command
├─ Dequeue from ring buffer
├─ Extract command ID
└─ Lookup in dispatch table

Step 3: Permission check (supposed to fail)
├─ Should check PRIVILEGE_SUPERVISOR
├─ Should verify driver authorization
├─ Gap: Check might be missing or bypassable

Step 4: If check fails
├─ Command rejected
├─ No privilege escalation
└─ Exploit unsuccessful

Step 5: If check missing/bypassed
├─ Command accepted
├─ Execute power_shutdown handler
├─ GPU powers down
└─ Denial of service achieved
```

### Exploitation Technique 1: Direct Bypass

```c
// Permission check might be missing entirely
case CMD_POWER_SHUTDOWN:
    // No privilege check!
    execute_shutdown(cmd);  // Vulnerable
```

### Exploitation Technique 2: Context Confusion

```c
// Command handler uses wrong context
// Graphics context accepted where system context required
dispatch_table[graphics_context][CMD_POWER] = shutdown_handler;

// Driver sends from graphics context, bypasses supervisor check
```

### Exploitation Technique 3: Payload Corruption

```
1. Send command with power shutdown + extra payload
2. Firmware misinterprets payload as separate command
3. Execute two commands for the price of one
4. Bypass permission for second command
```

---

## Investigation Checklist

- [ ] Extract ring buffer address from GPU memory
- [ ] Dump command queue registers
- [ ] Identify all command types and handler functions
- [ ] Extract permission table from firmware
- [ ] Trace command dispatch logic
- [ ] Find all permission checks
- [ ] Test each command with/without privilege
- [ ] Look for TOCTOU race conditions
- [ ] Test ring buffer boundary conditions
- [ ] Identify information disclosure paths

---

## Key Questions

**Q1**: Are all commands validated before execution?  
**A1**: UNKNOWN - Requires binary analysis of command handlers

**Q2**: Can ring buffer address be controlled by driver?  
**A2**: LIKELY - Driver specifies ring buffer location initially

**Q3**: Are permissions checked for all commands?  
**A3**: UNKNOWN - Some handlers might skip checks

**Q4**: Can commands be modified after submission but before execution?  
**A4**: YES - Ring buffer shared memory vulnerable to TOCTOU

**Q5**: What is the impact of command submission vulnerability?  
**A5**: HIGH - Can achieve arbitrary operations with firmware privileges

---

## Next Steps

1. **Binary Analysis**:
   - Extract dispatch table from firmware
   - Identify all command handlers
   - Trace permission checking logic
   - Map ring buffer implementation

2. **Vulnerability Testing**:
   - Test each command with invalid privilege
   - Attempt ring buffer overflow
   - Test TOCTOU race conditions
   - Try command injection

3. **Exploitation Development**:
   - Develop command submission exploit
   - Chain with other vulnerabilities
   - Achieve arbitrary code execution
   - Test privilege escalation

