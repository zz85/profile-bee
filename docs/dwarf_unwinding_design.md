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

**Code location**:
```rust
// profile-bee-ebpf/src/lib.rs
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, usize) {
    let regs = ctx.as_ptr() as *const pt_regs;
    let ip = regs.rip;          // Current instruction pointer
    let mut bp = regs.rbp;       // Frame pointer (base pointer)
    
    pointers[0] = ip;
    
    // Walk frame pointer chain
    for i in 1..pointers.len() {
        let Some(ret_addr) = get_frame(&mut bp) else {
            break;
        };
        pointers[i] = ret_addr;
    }
}
```

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

**File**: `profile-bee/src/dwarf_unwind.rs`

**What it does** (or should do):
- DWARF CFI (Call Frame Information) unwinding
- Parses `.eh_frame` or `.debug_frame` sections from ELF binaries
- Uses DWARF expressions to compute Canonical Frame Address (CFA)
- Reconstructs stack frames for code without frame pointers
- **Current status**: Infrastructure exists, algorithm NOT yet implemented

**Code location**:
```rust
// profile-bee/src/dwarf_unwind.rs
impl DwarfUnwinder {
    pub fn unwind_stack(&mut self, pid: u32, initial_addresses: &[Addr]) 
        -> Result<Option<Vec<Addr>>> 
    {
        // Called when FP unwinding produces < 10 frames
        self.try_dwarf_unwind(pid, initial_addresses)
    }
    
    fn try_dwarf_unwind(&mut self, pid: u32, _initial_addresses: &[Addr]) 
        -> Result<Vec<Addr>> 
    {
        // Load .eh_frame sections from process binaries
        let maps = get_process_maps(pid as i32)?;
        for map in &maps {
            if map.is_exec() {
                self.load_unwind_info(path, base_addr)?;
            }
        }
        
        // TODO: Actually unwind using DWARF CFI (line 163)
        // Currently returns empty vec!
        Ok(vec![])
    }
}
```

**Why in Userland?**
- Cannot parse complex ELF sections in eBPF (size/complexity limits)
- DWARF expressions require complex evaluation (stack machine)
- Need to read process `/proc/[pid]/maps` to find binaries
- Need to read binary files from filesystem
- Gimli library (DWARF parser) is userspace-only

**Integration point**:
```rust
// profile-bee/src/trace_handler.rs
fn format_stack_trace(&mut self, ...) -> Vec<StackFrameInfo> {
    let addrs = user_stack.unwrap_or_default();
    
    // Try to enhance with DWARF unwinding if enabled
    let enhanced_addrs = self.enhance_with_dwarf_unwinding(pid, &addrs);
    
    self.symbolize_user_stack(pid, &enhanced_addrs)
}
```

## Current Implementation Status

### ✅ What Works

1. **eBPF Frame Pointer Unwinding** (COMPLETE)
   - Walks FP chain in kernel
   - Captures up to 1024 instruction pointers
   - Sends to userspace via BPF maps

2. **DWARF Infrastructure** (COMPLETE)
   - Can read `/proc/[pid]/maps`
   - Can parse ELF binaries
   - Can extract `.eh_frame` sections
   - Caches parsed data per binary
   - Integration hooks in TraceHandler

3. **Symbolization** (COMPLETE)
   - Uses blazesym to resolve addresses
   - Works with both FP and DWARF addresses

### ❌ What's Missing

**DWARF Unwinding Algorithm** (NOT IMPLEMENTED)

The actual DWARF unwinding is **NOT** implemented. Line 163 in `dwarf_unwind.rs` has a TODO:

```rust
// TODO: Implement the actual DWARF unwinding algorithm
// This would involve:
// 1. Starting from the initial IP (instruction pointer)
// 2. Finding the corresponding .eh_frame FDE (Frame Description Entry)
// 3. Evaluating the DWARF expressions to compute CFA and return address
// 4. Repeating for each frame until we reach the end
```

**What needs to be done**:
1. Parse `.eh_frame` with gimli to find FDE for each IP
2. Evaluate DWARF CFI instructions (DW_CFA_*)
3. Compute CFA (Canonical Frame Address) for each frame
4. Extract return address register from CFA
5. Repeat until stack end

**Why it's hard**:
- DWARF CFI is a stack-based expression language
- Need to track register state across frames
- Different architectures have different register sets
- Need to read process memory for some operations
- Complex error handling for malformed unwind info

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
         │                     [ip0, ip1, ip2, ...]
         │
         ▼
    Store in BPF map
         │
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
         │         ├─ NO ──▶ Use FP addresses
         │         │
         │         ▼ YES
         │    enhance_with_dwarf_unwinding()
         │         │
         │         ▼
         │    ┌──────────────────────┐
         │    │  DwarfUnwinder       │
         │    └──────────────────────┘
         │         │
         │         ├─▶ Read /proc/[pid]/maps
         │         ├─▶ Parse binaries
         │         ├─▶ Load .eh_frame sections
         │         ├─▶ Cache unwind info
         │         │
         │         ▼
         │    TODO: Actual DWARF unwinding
         │    (Currently returns empty vec)
         │         │
         │         ▼
         │    Enhanced addresses
         │         │
         ▼         ▼
    symbolize_user_stack()
         │
         ├──▶ blazesym resolves addresses
         │
         ▼
    StackFrameInfo[] with symbols
         │
         ▼
    Generate flamegraph
```

## Hybrid Strategy Rationale

### Why Not DWARF in eBPF?

**eBPF limitations**:
- Maximum program size (~1 million instructions)
- No dynamic memory allocation
- Cannot read files from filesystem
- Cannot parse complex data structures
- Limited helper functions

**DWARF complexity**:
- `.eh_frame` can be megabytes per binary
- Requires complex parsing (FDE, CIE, expressions)
- Stack-based expression evaluation
- Architecture-specific register sets

### Why Not All Userland?

**Performance**:
- eBPF FP unwinding is 10-100x faster
- Runs in kernel, no context switch
- Can sample at high frequency (9999 Hz)

**When FP works, use it**:
- Most well-behaved code has FP
- Debug builds always have FP
- `-fno-omit-frame-pointer` is becoming common
- Kernel code always has FP

### Hybrid = Best of Both

1. **First**: Try fast eBPF FP unwinding
2. **Then**: If incomplete (<10 frames), enhance with DWARF in userspace
3. **Result**: Fast common case, correct rare case

## Configuration

**Enable DWARF** (default):
```bash
profile-bee --svg output.svg --time 5000
```

**Disable DWARF** (FP only):
```bash
profile-bee --no-dwarf --svg output.svg --time 5000
```

**In code**:
```rust
// DWARF enabled
let profiler = TraceHandler::new();

// DWARF disabled
let profiler = TraceHandler::with_dwarf(false);
```

## References

- [Polar Signals: Profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers)
- [gimli DWARF parser](https://github.com/gimli-rs/gimli)
- [nbdd0121 unwinding library](https://github.com/nbdd0121/unwinding)
- [Parca Agent unwind implementation](https://github.com/parca-dev/parca-agent/blob/main/pkg/stack/unwind/)

## Future Work

To complete DWARF unwinding:

1. **Implement CFI evaluation** in `try_dwarf_unwind()`
2. **Use gimli** to parse `.eh_frame` FDEs
3. **Evaluate DWARF expressions** to compute CFA
4. **Track register state** across frames
5. **Read process memory** for dereferencing
6. **Test with optimized binaries** compiled without FP

The infrastructure is 100% complete. Only the algorithm implementation remains.
