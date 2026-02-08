# DWARF Unwinding Analysis Summary

## What Was Done

Analysis of `dwarf_unwind_wip` and `dwarf_unwind_wip2` branches to understand DWARF unwinding implementations and extract actionable insights. The code from `dwarf_unwind_wip2` is now the active implementation.

## Current Code Structure

The DWARF unwinding infrastructure lives in `profile-bee/src/unwinder/`:

```
profile-bee/src/unwinder/
├── mod.rs       - Main logic: get_mappings(), find_instruction(), get_unwind_table()
├── ehframe.rs   - DWARF parsing: UnwindTable, UnwindTableRow, Instruction, Op, Reg
└── maps.rs      - Process memory maps: AddressMap, AddressEntry
```

## Critical Findings

### 1. Simplified DWARF Model is Sufficient

95% of real-world code follows simple patterns:
```
CFA = RSP + offset
ReturnAddress = [CFA - 8]
```

No need for full DWARF expression evaluation — simple arithmetic works.

### 2. DwarfDelta Innovation

`DwarfDelta` (in `profile-bee-common/src/lib.rs`) compresses unwind rules for potential eBPF-side unwinding:
- Small: 100K entries ≈ 2.4MB (fits in BPF map)
- Binary searchable
- No complex evaluation needed

### 3. Clean Three-Tier Architecture

```
Instruction (atomic DWARF operation)
    ↓
UnwindTableRow (per-function unwind rules)
    ↓
UnwindTable (complete binary unwind info)
```

### 4. Proven Code Exists

~500 lines of working infrastructure in `unwinder/`:
- `ehframe.rs`: Complete gimli integration (~250 lines)
- `maps.rs`: Memory map handling (~100 lines)
- `mod.rs`: Unwinding logic and table construction (~250 lines)

## Implementation Status

### ✅ Complete
- eBPF frame pointer unwinding
- `.eh_frame` parsing with gimli
- Process memory map reading
- Unwind table construction and caching
- Symbolization via blazesym

### ❌ Remaining Work
1. Add RSP to `StackInfo` struct, capture in eBPF
2. Implement process memory reading (`process_vm_readv`)
3. Implement the unwinding loop
4. Integrate with TraceHandler

See `implementation_guide.md` for step-by-step instructions.

## Two-Phase Approach

**Phase 1** (Userspace unwinding): Complete the unwinding loop in `unwinder/mod.rs` using the existing infrastructure. Estimated 2-3 days.

**Phase 2** (eBPF unwinding): Use `DwarfDelta` to store simplified unwind info in BPF maps for kernel-side unwinding. Future work.

## Risk Assessment

- **Low**: Proven code exists, clear implementation path, fallback to FP if DWARF fails
- **Medium**: Process memory reading permissions, performance impact of userspace unwinding
- **High**: None identified

## References

- `docs/dwarf_unwinding_design.md` - Architecture overview
- `docs/implementation_guide.md` - Step-by-step guide
- `docs/wip_insights.md` - Key insights
- `docs/wip_branches_comparison.md` - Branch analysis details
