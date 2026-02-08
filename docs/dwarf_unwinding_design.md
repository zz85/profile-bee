# DWARF Stack Unwinding Design

## Architecture Overview

Profile-bee uses a **hybrid approach** for stack unwinding:

```
┌─────────────────────────────────────────────────────────┐
│                    Profile-bee Architecture              │
└─────────────────────────────────────────────────────────┘

    ┌──────────────────┐              ┌──────────────────┐
    │   eBPF (Kernel)  │              │  Userland (Rust) │
    └──────────────────┘              └──────────────────┘
            │                                   │
            │  1. Frame Pointer Unwinding       │
            │     (FAST, in kernel)             │
            │                                   │
            │  • Gets RIP, RBP from pt_regs    │
            │  • Walks frame pointers          │
            │  • Stores up to 1024 addresses   │
            │                                   │
            ├──────────────────────────────────▶│
            │   Sends: Instruction Pointers    │
            │                                   │
            │                                   │  2. DWARF Unwinding
            │                                   │     (FALLBACK, userspace)
            │                                   │
            │                                   │  • Triggered when FP < 10 frames
            │                                   │  • Parses .eh_frame sections
            │                                   │  • Evaluates CFI rules
            │                                   │  • Enhances incomplete stacks
            │                                   │
            │                                   │  3. Symbolization
            │                                   │     (Always userspace)
            │                                   │
            │                                   │  • Uses blazesym/gimli
            │                                   │  • Resolves addresses → symbols
```

## Where Does Unwinding Happen?

### eBPF Land (Kernel Space)

**File**: `profile-bee-ebpf/src/lib.rs`

**What it does**:
- Frame pointer (FP) unwinding ONLY
- Reads CPU registers (RIP, RBP) from `pt_regs`
- Walks the frame pointer chain: `[RBP] → next RBP, [RBP+8] → return address`
- Stores instruction pointers in `FramePointers` array (up to 1024 addresses)
- Fast and efficient, but **requires** binaries compiled with `-fno-omit-frame-pointer`

**Why in eBPF?**
- Direct access to CPU registers via `pt_regs`
- Minimal overhead (runs in kernel context)
- No context switches to userspace
- Can sample at high frequency (99Hz-9999Hz)

**Limitation**:
- Only works with frame pointers
- Fails for optimized binaries (`-O2`/`-O3` often omits frame pointers)
- Incomplete stacks for code without FP

### Userland (User Space)

**Module**: `profile-bee/src/unwinder/`

```
profile-bee/src/unwinder/
├── mod.rs       - Main unwinding logic (get_mappings, find_instruction, execute_instruction)
├── ehframe.rs   - DWARF .eh_frame parsing with gimli (UnwindTable, UnwindTableRow, Instruction, Op, Reg)
└── maps.rs      - Process memory map handling (AddressMap, AddressEntry)
```

**What it does** (infrastructure complete, algorithm WIP):
- DWARF CFI (Call Frame Information) unwinding
- Parses `.eh_frame` sections from ELF binaries via gimli
- Builds `UnwindTable` with simplified `Instruction` rules
- Reads `/proc/[pid]/maps` to find process binaries
- Caches parsed unwind tables per binary

**Current status**: Infrastructure exists (parsing, caching, data structures). The core unwinding algorithm (CFI evaluation loop) is NOT yet implemented.

**Why in Userland?**
- Cannot parse complex ELF sections in eBPF (size/complexity limits)
- DWARF expressions require complex evaluation (stack machine)
- Need to read process `/proc/[pid]/maps` to find binaries
- Need to read binary files from filesystem
- Gimli library (DWARF parser) is userspace-only

## Current Implementation Status

### ✅ What Works

1. **eBPF Frame Pointer Unwinding** (COMPLETE)
   - Walks FP chain in kernel
   - Captures up to 1024 instruction pointers
   - Sends to userspace via BPF maps

2. **DWARF Infrastructure** (COMPLETE)
   - `unwinder/maps.rs`: Reads `/proc/[pid]/maps` via `AddressMap::load_pid()`
   - `unwinder/ehframe.rs`: Parses ELF `.eh_frame` sections into `UnwindTable`
   - `unwinder/mod.rs`: `get_unwind_table()` builds per-binary unwind tables
   - Integration hooks in TraceHandler

3. **Symbolization** (COMPLETE)
   - Uses blazesym to resolve addresses
   - Works with both FP and DWARF addresses

### ❌ What's Missing

**DWARF Unwinding Algorithm** (NOT IMPLEMENTED)

The `find_instruction()` and `execute_instruction()` functions in `unwinder/mod.rs` exist but the full unwinding loop that walks the stack using DWARF CFI rules is not complete.

**What needs to be done**:
1. Capture RSP from pt_regs in eBPF (add `sp` to `StackInfo`)
2. Implement process memory reading (`process_vm_readv`)
3. Implement the unwinding loop: for each frame, find the unwind row, compute CFA, read return address
4. Integrate with TraceHandler to enhance short FP stacks

## Simplified DWARF Model

95% of real-world code follows simple patterns:
```
CFA = RSP + offset              // Canonical Frame Address
ReturnAddress = [CFA - 8]       // Return address on stack
```

This is captured in the `Instruction` and `UnwindTableRow` types in `ehframe.rs`:

```rust
pub enum Op {
    Unimplemented,
    Undefined,
    CfaOffset,    // Value at CFA + offset
    Register,     // Register value + offset
}

pub struct UnwindTableRow {
    pub start_address: usize,
    pub end_address: usize,
    pub rip: Instruction,  // How to recover return address
    pub rsp: Instruction,  // How to compute CFA
}
```

## DwarfDelta Innovation

The `DwarfDelta` structure (in `profile-bee-common/src/lib.rs`) compresses unwind rules for potential eBPF-side unwinding:

```rust
struct DwarfDelta {
    addr: u64,      // Instruction pointer to match
    cfa_offset: i8, // RSP + this = CFA
    rip_offset: i8, // CFA + this = return address location
}
```

Benefits:
- Small: 100K entries ≈ 2.4MB (fits in BPF map)
- Fast: Binary searchable
- Simple: No expression evaluation needed

## Flow Diagram

```
User runs: profile-bee --svg output.svg --time 5000

         │
         ▼
    ┌────────┐
    │  eBPF  │  Attaches to perf events
    └────────┘
         │
         │  Timer fires (e.g., 99 Hz)
         ▼
    ┌────────────────────┐
    │  collect_trace()   │
    └────────────────────┘
         │
         ├──▶ copy_stack()  ─────▶  Frame Pointer Unwinding
         │                          │
         │                          ├─▶ RIP = pt_regs.rip
         │                          ├─▶ RBP = pt_regs.rbp
         │                          ├─▶ Walk: [RBP] → next RBP
         │                          │         [RBP+8] → return addr
         │                          │
         │                          ▼
         │                     FramePointers[]
         │
         ▼
    Store in BPF map
         │
         ▼
    ┌─────────────────────┐
    │    Userspace        │
    │  TraceHandler       │
    └─────────────────────┘
         │
         ├──▶ get_instruction_pointers()
         │         │
         │         ▼
         │    Got < 10 frames?
         │         │
         │         ├─ NO ──▶ Use FP addresses as-is
         │         │
         │         ▼ YES
         │    DWARF unwinding (TODO)
         │    using unwinder/ module
         │         │
         │         ▼
         │    Enhanced addresses
         │
         ▼
    symbolize_user_stack()
         │
         ▼
    Generate flamegraph
```

## Configuration

**Disable DWARF** (FP only):
```bash
profile-bee --no-dwarf --svg output.svg --time 5000
```

Note: `--no-dwarf` currently has no effect since the DWARF algorithm isn't implemented yet.

## Future Work

### Phase 1: Userspace DWARF Unwinding
1. Add RSP to StackInfo, capture in eBPF
2. Implement `process_vm_readv` memory reading
3. Implement unwinding loop in `unwinder/mod.rs`
4. Integrate with TraceHandler

### Phase 2: eBPF DWARF Unwinding
1. Pre-compute DwarfDelta tables in userspace
2. Store in BPF maps (per-PID)
3. Implement eBPF-side unwinding using delta lookups
4. Fallback to userspace for complex cases

## References

- [Polar Signals: Profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers)
- [gimli DWARF parser](https://github.com/gimli-rs/gimli)
- [nbdd0121 unwinding library](https://github.com/nbdd0121/unwinding)
- [Parca Agent unwind implementation](https://github.com/parca-dev/parca-agent/blob/main/pkg/stack/unwind/)
