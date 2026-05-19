# 2.1 — Secure Boot Chain Overview

## Overview

The NVIDIA Ampere GA100 secure boot chain consists of a four-stage authentication and verification process that establishes a cryptographic trust root from immutable ROM through to executable Falcon microcontroller firmware. Each stage verifies and hands off control to the next, implementing RSA-3072 signature verification and AES-CBC decryption.

**Trust Root**: Immutable boot ROM with NVIDIA public key (production and debug variants)  
**Final Execution**: Falcon microcontroller with full GPU resource access  
**Verification Mechanism**: RSA-3072 + SHA-256 with AES-CBC symmetric decryption

> **CORRECTION (/4 binary analysis — see `6-1-crypto-auth-chain-map.md` §5, `6-2-verification-state-machine.md` §3):**  
> The "AES-CBC" claim above is **wrong for GA100 LS falcon authentication**. GA100 uses the TU10X code path, not the GA10X path. LS ucode authentication is AES-DM (Davies-Meyer 128-bit hash over 16-byte blocks via SCP) + AES-ECB KDF via **SCP slot 43** — not AES-CBC. The GA10X AES-CBC path (`acr_decrypt_ls_ucode_ga10x.c`) is absent from the GA100 production binary (## confirmed). RSA-3072-PSS-SHA256 is correct but only for Booter's verification of GSP-RM (layer L3). All other LS falcons (PMU, SEC2, FECS, GPCCS, NVDEC) are authenticated via the AES-DM scheme.  

---

## Stage 1: Boot ROM (Immutable Root)

**Purpose**: Establish cryptographic trust root without relying on any mutable state

**Responsibilities**:
- Verify bootloader signature using hardcoded NVIDIA RSA-3072 public key
- Support both production and debug key pairs (selectable via strap pins)
- Load bootloader from GPU DRAM into secure execution environment
- Hand off control to bootloader after verification succeeds

**Key Materials**:
- Production RSA-3072 public key (embedded in ROM)
- Debug RSA-3072 public key (embedded in ROM, conditional)
- SHA-256 hash of bootloader image
- No mutable state: ROM is immutable by design

**Attack Surface**:
- Key selection: Debug key presence enables signature bypass if selectable at runtime
- Verification implementation: Buffer overflows in RSA verification
- Bootloader location assumptions: If bootloader location is mutable, code execution possible

**Files**:
- `uproc/booter/src/*/ampere/booter_sig_verif_ga100.c` - Signature verification logic
- ROM binary: Not in source archive (immutable, embedded in silicon)

---

## Stage 2: Bootloader (ACR - Application Crypto Processor)

**Purpose**: Authenticate and configure GPU security parameters before Falcon execution

**Responsibilities**:
- Verify ACR (GPU security processor) firmware signature using ROM-established key
- Load ACR microcode into secure memory region (Write-Protected Region / WPR)
- Establish WPR layout and allocate secure data structures
- Verify Falcon microcode signature and decrypt encrypted images
- Configure SMC/MIG instance isolation and security boundaries
- Initialize memory controller with secure parameters

**Components**:
1. **ACR Firmware Image** (signed, verified by ROM)
   - Contains microcode for GPU security processor
   - Performs remaining boot-time verification steps

2. **WPR Initialization** (Write-Protected Region)
   - Allocates secure region in GPU DRAM
   - Stores: Falcon firmware, AES keys, signature keys, runtime state
   - Cannot be modified after verification without detection

3. **Microcode Loading**
   - Falcon (custom 32-bit Harvard-architecture core with Renesas-like ISA) for memory/thermal management
   - GSP (GPU System Processor) - RISC-V based
   - PMU (Power Management Unit) - RISC-V based
   - SEC (Security Processor) - RISC-V based

**Trust Model**:
- ACR firmware must be signed by NVIDIA root key (verified in Stage 1)
- All subsequent firmware images are verified by ACR microcode
- WPR layout is ACR-controlled and immutable post-verification

**Key Files**:
- `uproc/acr/src/acrshared/ampere/acr_wpr_ctrl_ga10x.c` - WPR layout and allocation
- `uproc/acr/src/acrsec2shared/ampere/acr_dma_ga100.c` - DMA and register access
- `uproc/acr/src/acrshared/ampere/acr_sanity_checks_ga100.c` - Post-verification checks
- `uproc/acr/src/ahesasc/ampere/acr_decrypt_ls_ucode_ga100.c` - Microcode decryption

---

## Stage 3: Falcon Microcontroller Firmware

**Purpose**: Execute privileged GPU firmware for memory management, thermal control, and runtime security

**Architecture**:
- **ISA**: Custom 32-bit Harvard-architecture core with Renesas-like ISA (NOT x86 or x86-like; the ISA has superficial register-naming similarities but is a proprietary NVIDIA design)
- **Execution Context**: Privileged mode with direct hardware access
- **Memory Access**: Can read/write entire GPU DRAM including WPR
- **MMIO Access**: Direct control of GPU registers via BAR0
- **Privilege Levels**: HS (High Secure, hardware-authenticated) and LS (Low Secure, software-authenticated) modes

**Firmware Components**:

1. **Memory Training** — GA100 uses HBM2e (not GDDR6). There is no `fbflcn_gddr_boot_time_training_ga100.c`; that file does not exist in the source tree. HBM2e initialization is handled by:
   - **DEVINIT**: VBIOS-embedded PMU scripted sequencer (handles HBM2e training at POST time; not a standalone Falcon ucode)
   - **HULK**: HBM2e row-remap / memory training ucode embedded in VBIOS Image #2 (TargetID=5 = FBFalcon; see `2-6-vbios-ucode-catalog.md`)
   - Training results stored in mutable runtime state (NOT cryptographically verified by ACR)

2. **Memory Controller** (`fbflcn_hbm_mclk_switch.c`)
   - Dynamic HBM2e clock frequency switching (not GDDR6; no `fbflcn_gddr_mclk_switch_ga100.c` exists)
   - Monitors thermal state
   - Implements power management

3. **Core Execution** (`fbfalcon_ga10x.c` / `interrupts_ga100.c` for GA100-specific interrupt handling)
   - Exception handling (interrupt vectors, privileged mode management)
   - IPC (Inter-Process Communication) with host driver
   - Watchdog timers and panic handlers

**Verification Model**:
- Falcon firmware image is LSF-formatted with embedded signature
- ACR verifies Falcon signature during Stage 2
- After verification, Falcon image may be relocated and reinterpreted
- **Critical Gap**: Post-verification mutations not prevented

**Trust Handoff**:
```
Boot ROM
   ↓ (verify ACR signature)
ACR Bootloader (Stage 2)
   ↓ (verify Falcon signature, decrypt if encrypted)
Falcon Microcontroller (Stage 3)
   ↓ (execute privileged operations)
Runtime GPU Control
```

---

## Stage 4: Runtime Execution and Isolation

**Purpose**: Provide multiplexed GPU access while maintaining isolation between clients

**Mechanisms**:

1. **SMC (Simultaneous Multi-Client)** - GA100 exclusive
   - Allows multiple GPU contexts to share resources
   - Instance-based: Each context uses independent registers
   - Register addressing: `base_register + (instance_id * stride)`
   - **Critical**: Instance ID must be validated in privileged operations

2. **MIG (Multi-Instance GPU)** - Hardware partitioning
   - Divides GPU into isolated partitions
   - Each partition has independent resources (cores, memory, bandwidth)
   - Isolation enforced at hardware level

3. **FECS (Front-End Coherence System)** - DMA Arbitration
   - Manages physical memory access from GPU to system RAM
   - Instance-based DMA request routing
   - **Critical**: DMA instance validation required for isolation

---

## Vulnerability Categories by Stage

### Stage 1 (ROM) - Low Risk
- Immutable by design
- Key selection side-channels
- Minimal implementation complexity

### Stage 2 (ACR) - CRITICAL RISK
- **File**: `acr_wpr_ctrl_ga10x.c` - Dependency map bounds violation (GA10X+ path; absent from GA100 prod binary — see Phase-3)
- **File**: `acr_dma_ga100.c` - SMC instance `falconInstance << 21` unchecked (W-level finding; no attacker-reachable path confirmed)
- **AES auth**: GA100 uses AES-DM + SCP slot 43 (NOT AES-CBC; `acr_decrypt_ls_ucode_ga100.c` is for GA10X+ only and absent from GA100 prod AHESASC) — resolved in Phase-3
- WPR lock fires before LS signature verification (timing gap documented; no confirmed exploitable path)
- Pre-verify DMA scribble via driver-controlled `blDataOffset` (W-6; MEDIUM — ring-0 prerequisite)

### Stage 3 (Falcon / DEVINIT) - HIGH RISK
- **Training target**: HULK ucode (FBFalcon, TargetID=5, VBIOS-embedded) + DEVINIT PMU script — not a standalone Falcon ucode file
- HBM2e training results not cryptographically verified
- Fault injection opportunities in HBM2e calibration (DEVINIT/VBIOS path)
- Runtime state corruption possible via HULK or DEVINIT script tampering

### Stage 4 (Runtime) - MEDIUM RISK
- SMC instance validation gaps
- FECS DMA routing vulnerabilities
- Post-verification mutation paths

---

## Critical Trust Assumptions

1. **RSA Signature Integrity**: Assumes RSA-3072 implementation is correct
   - No evidence of cryptographic breaks needed for exploits
   - All identified vulnerabilities bypass this layer

2. **Firmware Metadata Immutability Post-Verification**: Assumes metadata cannot be modified after signature check
   - **Gap Identified**: Multiple post-verification mutation paths exist
   - WPR is write-protected but not read-protected
   - Falcon firmware can be relocated without re-verification

3. **Instance ID Validation**: Assumes firmware validates instance IDs before use
   - **Gap Identified**: Multiple unchecked uses of instance ID in register addressing
   - No visible bounds checking in SMC/MIG instance selection

4. **LSF Parser Correctness**: Assumes firmware descriptor parsing is complete and correct
   - **Gap Identified**: Multiple bounds checking failures
   - Array access without validation
   - Integer overflow in iteration

5. **Memory Training Verification**: Assumes training state cannot be corrupted
   - **Gap Identified**: No cryptographic verification of training results
   - Fault injection possible during calibration phase

---

## Investigation Checklist

- [ ] Confirm RSA-3072 verification implementation in `booter_sig_verif_ga100.c`
- [ ] Map WPR layout and allocation algorithm in `acr_wpr_ctrl_ga10x.c`
- [ ] Verify AES key storage location in `acr_decrypt_ls_ucode_ga100.c`
- [ ] Identify all post-verification firmware mutations in runtime code
- [ ] Extract Falcon ISA from prebuilt firmware binaries
- [ ] Map privilege boundaries in Falcon exception handling
- [ ] Identify all unchecked uses of instance IDs in register addressing
- [ ] Document all workaround paths disabling security checks (WAR functions)

---

## Key Questions

**Q1**: Does the post-verification phase assume all firmware metadata remains immutable and trustworthy?  
**A1**: YES - Evidence from multiple mutation paths in `acr_wpr_ctrl_ga10x.c` and runtime firmware relocation without re-verification

**Q2**: Can the boot ROM validation be bypassed through debug/production key selection?  
**A2**: PARTIALLY - Debug key presence enables signature bypass only if selectable at runtime (depends on strap pin implementation)

**Q3**: Is AES key storage hardcoded across all GA100s?  
**A3**: UNKNOWN - Requires binary analysis of `acr_decrypt_ls_ucode_ga100.c` to determine key derivation method

**Q4**: What privilege modes exist in Falcon execution?  
**A4**: PARTIALLY DOCUMENTED - Exception handling suggests multiple modes, full ISA analysis required

**Q5**: Can WPR layout be manipulated before lock-down?  
**A5**: LIKELY - No visible verification of allocation algorithm in `acr_wpr_ctrl_ga10x.c`

---

## Next Steps

1. **## (Binary Analysis)**:
   - Disassemble bootloader and ACR firmware from prebuilt binaries
   - Extract RSA verification implementation
   - Analyze AES key derivation

2. **## (Vulnerability Confirmation)**:
   - Trace each vulnerability from source code through to exploitability
   - Generate proof-of-concept code for SMC instance bypass
   - Demonstrate dependency map bounds violation

3. **## (Exploitation)**:
   - Chain vulnerabilities for persistent firmware compromise
   - Develop exploit code for each attack surface
   - Test impact on GPU functionality

