# Key Insights from WIP Branches Analysis

> **Note**: This is historical analysis. The wip2 code is now the active implementation in `profile-bee/src/unwinder/`. References to `dwarf_unwind.rs` below are from the copilot branch and do not exist in the current codebase.

## Summary

Analysis of `dwarf_unwind_wip` and `dwarf_unwind_wip2` branches reveals **working DWARF unwinding implementations** that are far more complete than the current infrastructure-only code. These branches provide a clear roadmap for completing the DWARF unwinding feature.

## Most Important Insights

### 1. **Simplified DWARF Model is Sufficient** 

You don't need to implement full DWARF expression evaluation. Most real-world functions follow simple patterns:

```rust
// 95%+ of cases can be handled with:
CFA = RSP + offset              // Canonical Frame Address
ReturnAddress = [CFA - 8]       // Return address on stack
```

This means we can avoid complex DWARF expression evaluation and use simple arithmetic operations that even eBPF can handle.

### 2. **Three-Component Architecture**

Both WIP branches use a clean three-tier structure:

```
Instruction (atomic operation)
    ↓
UnwindTableRow (per-function range)
    ↓
UnwindTable (per-binary)
```

This matches how DWARF actually works and makes the code maintainable.

### 3. **eBPF-Compatible Data Format (wip2 Innovation)**

wip2 introduces `DwarfDelta` - a brilliant simplification:

```rust
struct DwarfDelta {
    addr: u64,      // Instruction pointer
    cfa_offset: i8, // RSP + this = CFA
    rip_offset: i8, // CFA + this = return address location
}
```

This is:
- Small enough for BPF maps (2.4MB for 100K entries)
- Binary searchable in eBPF
- No complex evaluation needed

### 4. **The Missing Piece: RSP Value**

Current implementation captures IPs but not RSP. DWARF unwinding needs both:

```rust
// Current eBPF captures:
let ip = regs.rip;  // ✅ We have this

// DWARF needs:
let rsp = regs.rsp; // ❌ We're missing this!
```

**Fix**: Add RSP to `StackInfo` structure (wip2 shows how).

### 5. **Actual Unwinding Algorithm**

From wip branches, the unwinding loop is straightforward:

```rust
fn unwind_stack(initial_ip: u64, initial_rsp: u64, unwind_table: &UnwindTable) -> Vec<u64> {
    let mut stack = vec![initial_ip];
    let mut ip = initial_ip;
    let mut rsp = initial_rsp;
    
    while let Some(row) = unwind_table.find_row(ip) {
        // Calculate CFA (Canonical Frame Address)
        let cfa = (rsp as i64 + row.cfa_offset()) as u64;
        
        // Get return address from stack
        let ret_addr_ptr = (cfa as i64 + row.rip_offset()) as u64;
        let ret_addr = read_process_memory(pid, ret_addr_ptr)?;
        
        // Update for next iteration
        ip = ret_addr;
        rsp = cfa; // New stack pointer is the CFA
        
        stack.push(ret_addr);
        
        if stack.len() >= MAX_FRAMES {
            break;
        }
    }
    
    Ok(stack)
}
```

### 6. **gimli Integration Pattern**

Both branches show the correct gimli usage:

```rust
// Parse .eh_frame
let eh_frame = gimli::EhFrame::new(&data, NativeEndian);
let mut ctx = UnwindContext::new();

// Iterate FDEs (Frame Description Entries)
while let Some(entry) = entries.next()? {
    if let gimli::CieOrFde::Fde(partial) = entry {
        let fde = partial.parse(|_, bases, o| 
            eh_frame.cie_from_offset(bases, o)
        )?;
        
        // Get unwind rows for this function
        let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;
        while let Some(row) = table.next_row()? {
            // Extract simplified instructions
            let unwind_row = simplify_row(row)?;
            rows.push(unwind_row);
        }
    }
}
```

### 7. **Memory Reading Challenge**

DWARF unwinding requires reading target process memory. WIP branches show the need but don't fully implement it. Options:

1. **`/proc/[pid]/mem`** - Requires seek + read, complex error handling
2. **`process_vm_readv()`** - Recommended, one syscall
3. **ptrace** - Too slow for profiling

Example needed:
```rust
fn read_u64_from_process(pid: u32, addr: u64) -> Result<u64> {
    use nix::sys::uio::process_vm_readv;
    let mut buf = [0u8; 8];
    let local = [IoSliceMut::new(&mut buf)];
    let remote = [RemoteIoVec { base: addr as _, len: 8 }];
    process_vm_readv(Pid::from_raw(pid as _), &local[..], &remote[..])?;
    Ok(u64::from_ne_bytes(buf))
}
```

### 8. **Performance Optimization**

WIP branches show caching strategies:

```rust
// Parse once per binary
let mut binary_cache = HashMap<PathBuf, UnwindTable>::new();

// Parse once per PID (memory maps can change)
let mut pid_cache = HashMap<u32, Vec<UnwindTable>>::new();
```

Binary search is critical:
```rust
// Sort unwind rows by address
rows.sort_unstable_by_key(|row| row.start_address);

// Fast lookup
let idx = rows.binary_search_by_key(&ip, |row| row.start_address)
    .unwrap_or_else(|i| i.saturating_sub(1));
```

### 9. **Testing Strategy**

wip2 includes sample programs that are valuable:

- **fibonacci.rs**: Deep recursive calls, tests stack depth
- **inefficient.rs**: Complex call patterns, multiple libraries

Test cases should verify:
1. Matches frame pointer results (when FP available)
2. Extends short FP stacks (when FP incomplete)
3. Works with optimized code (compiled with -O2/-O3)

### 10. **Module Organization**

WIP branches suggest clean separation:

```
dwarf_unwind/
├── mod.rs       - Public API, caching, main logic
├── ehframe.rs   - gimli integration, DWARF parsing
└── maps.rs      - Process memory map handling
```

## Implementation Roadmap

Based on WIP branch insights:

### Phase 1: Core Implementation (Immediate)

1. **Add ehframe.rs and maps.rs modules** from wip2
2. **Add RSP to StackInfo** in eBPF
3. **Implement process memory reading** (process_vm_readv)
4. **Implement unwinding algorithm** in `try_dwarf_unwind()`
5. **Add caching** for parsed unwind tables
6. **Test with sample programs**

### Phase 2: Optimization (Future)

7. **Pre-compute DwarfDelta tables** (wip2 approach)
8. **Store in BPF maps** for eBPF-side unwinding
9. **Implement eBPF unwinding** using deltas
10. **Benchmark and tune** performance

## Code to Extract from WIP Branches

### High Priority
- `ehframe.rs` - Complete DWARF parsing (163c972)
- `maps.rs` - Memory map handling (163c972)
- RSP capture in eBPF (163c972:profile-bee-ebpf/src/lib.rs)
- `DwarfDelta` structure (163c972:profile-bee-common/src/lib.rs)

### Medium Priority
- Sample test programs (fibonacci.rs, inefficient.rs)
- pt_regs helper module (163c972)

### Reference Only
- eBPF map integration (complex, phase 2)

## Critical Dependencies

From WIP branch Cargo.toml files:

```toml
# Already have:
gimli = "0.31"
object = "0.36"

# Need to add:
procmaps = "0.7"  # Better than current proc-maps
nix = "0.29"      # For process_vm_readv
```

## Known Limitations from WIP Branches

1. **100K entry limit** for eBPF DwarfDelta approach
2. **Only handles common DWARF patterns** (CfaOffset, Register+offset)
3. **x86_64 only** (could be extended to other architectures)
4. **No expression evaluation** (complex DWARF expressions marked Unimplemented)
5. **Requires process memory read permissions**

## Conclusion

The WIP branches prove that **practical DWARF unwinding is achievable** with a simplified model. The key is to:

1. Focus on common cases (95%+ of real code)
2. Use simple data structures (Instruction, UnwindTableRow)
3. Avoid full expression evaluation
4. Cache aggressively
5. Start with userspace, move to eBPF later

The current infrastructure-only implementation can be upgraded to full functionality by:
- Adding ~300 lines from ehframe.rs
- Adding ~100 lines from maps.rs
- Implementing ~50 lines of unwinding algorithm
- Adding ~50 lines for memory reading

Total: ~500 lines of well-structured, tested code to complete DWARF unwinding.
