# DWARF Stack Unwinding Design

## Architecture Overview

Profile-bee uses **eBPF-based DWARF unwinding** to profile binaries compiled without frame pointers. Unwind tables are pre-computed in userspace and loaded into BPF maps; the actual stack walking runs entirely in eBPF at sample time.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Startup (Userspace)                         │
│                                                                     │
│  1. Read /proc/[pid]/maps → find executable mappings                │
│  2. Parse .eh_frame from each ELF binary (gimli)                    │
│  3. Pre-evaluate DWARF CFI → flat UnwindEntry table                 │
│  4. Load into BPF maps: UNWIND_TABLE (array), PROC_INFO (hashmap)  │
│  5. Set DWARF_ENABLED=1 in .rodata                                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Sample Time (eBPF, kernel space)                  │
│                                                                     │
│  perf_event fires (e.g., 99 Hz)                                     │
│       │                                                             │
│       ▼                                                             │
│  collect_trace()                                                    │
│       │                                                             │
│       ├─ DWARF_ENABLED? ──YES──▶ dwarf_copy_stack()                 │
│       │                              │                              │
│       │                              ├─ Read RIP, RSP, RBP          │
│       │                              ├─ Lookup PROC_INFO by tgid    │
│       │                              ├─ For each frame (max 32):    │
│       │                              │   ├─ Find mapping for IP     │
│       │                              │   ├─ relative_pc = IP - bias │
│       │                              │   ├─ Binary search table     │
│       │                              │   ├─ Compute CFA (RSP/RBP)   │
│       │                              │   ├─ bpf_probe_read_user(RA) │
│       │                              │   └─ Update SP, BP, IP       │
│       │                              └─ Store pointers[]            │
│       │                                                             │
│       └─ NO ──▶ bpf_get_stackid() (kernel FP unwinding)            │
│                                                                     │
│  Userspace picks the deeper stack (DWARF pointers vs FP stack)      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Symbolization (Userspace)                        │
│                                                                     │
│  Resolve addresses → symbols using blazesym/gimli                   │
│  Generate flamegraph / collapsed output                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Files

| File | Role |
|------|------|
| `profile-bee/src/dwarf_unwind.rs` | Userspace: parse `.eh_frame`, generate `UnwindEntry` table, load into BPF maps |
| `profile-bee-ebpf/src/lib.rs` | eBPF: `dwarf_copy_stack()`, `binary_search_unwind_entry()`, `collect_trace()` |
| `profile-bee-common/src/lib.rs` | Shared types: `UnwindEntry`, `ProcInfo`, `ExecMapping`, constants |
| `profile-bee/src/ebpf.rs` | `EbpfProfiler`: loads eBPF program, sets `DWARF_ENABLED`, loads maps |
| `profile-bee/src/trace_handler.rs` | Picks DWARF stack vs FP stack (whichever is deeper) |

## Data Structures

### UnwindEntry (12 bytes, stored in BPF HashMap map)

```rust
pub struct UnwindEntry {
    pub pc: u32,           // File-relative program counter (u32 sufficient for single-binary offsets)
    pub cfa_offset: i16,   // CFA = register + offset
    pub rbp_offset: i16,   // RBP restore offset from CFA
    pub cfa_type: u8,      // 0=RSP, 1=RBP, 3=PLT, 4=DEREF_RSP
    pub rbp_type: u8,      // How to restore RBP (0=OFFSET, 1=SAME_VALUE, 2=UNDEFINED)
    pub _pad: [u8; 2],
}
```

CFA types:
- `CFA_REG_RSP (0)`: CFA = RSP + offset (most common)
- `CFA_REG_RBP (1)`: CFA = RBP + offset (frame-pointer-based frames)
- `CFA_REG_PLT (3)`: CFA = RSP + offset + ((RIP & 15) >= 11 ? offset : 0) — PLT stubs
- `CFA_REG_DEREF_RSP (4)`: CFA = *(RSP + offset) — signal trampolines

Return address is always at CFA-8 on x86_64, so RA rule/offset are not stored.

### UnwindTableKey (8 bytes, key for sharded tables)

```rust
pub struct UnwindTableKey {
    pub table_id: u32,   // Unique ID for each binary
    pub index: u32,      // Index within that binary's table
}
```

### ProcInfo (per-process, stored in BPF HashMap)

```rust
pub struct ProcInfo {
    pub mapping_count: u32,
    pub mappings: [ExecMapping; 8],  // MAX_PROC_MAPS
}

pub struct ExecMapping {
    pub begin: u64,        // Virtual address range start
    pub end: u64,          // Virtual address range end
    pub load_bias: u64,    // Subtract from IP to get file-relative PC
    pub table_id: u32,     // ID of the unwind table for this mapping
    pub table_count: u32,  // Number of entries for this mapping
}
```

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `unwind_tables` | HashMap | 500K entries × 20B = 10 MB max | Sharded per-binary unwind tables (table_id, index) → UnwindEntry |
| `proc_info` | HashMap | 1024 entries | Per-process mapping info |
| `stacked_pointers` | HashMap | 2048 entries | DWARF-unwound frame pointers per stack |

## How Unwind Tables Are Generated

In `dwarf_unwind.rs::generate_unwind_table_from_bytes()`:

1. Parse ELF to find `.eh_frame` section
2. Use `gimli::UnwindSection::rows()` to iterate all FDE rows
3. For each row, extract:
   - PC range (converted to file-relative by subtracting ELF base vaddr for non-PIE)
   - CFA rule: which register (RSP/RBP) + offset
   - RA rule: offset from CFA, or same-value, or undefined
   - RBP rule: offset from CFA, or same-value, or undefined
4. Flatten into sorted `Vec<UnwindEntry>` (sorted by PC for binary search)

**Non-PIE vs PIE handling**: Non-PIE binaries have absolute virtual addresses in `.eh_frame` (e.g., `0x400527`). The code detects the ELF base vaddr from the first PT_LOAD segment and subtracts it to make entries file-relative. PIE binaries already have file-relative addresses.

## eBPF Unwinding Algorithm

In `dwarf_copy_stack()` (simplified):

```
pointers[0] = RIP
sp = RSP, bp = RBP, current_ip = RIP

for i in 1..32:
    mapping = find_mapping(current_ip)        // linear scan, max 16
    relative_pc = current_ip - mapping.load_bias
    entry = binary_search(mapping.table_id, relative_pc)  // max 19 iterations

    cfa = (entry.cfa_type == RSP) ? sp + entry.cfa_offset
                                  : bp + entry.cfa_offset

    return_addr = bpf_probe_read_user(cfa - 8)  // RA always at CFA-8 on x86_64

    if return_addr == 0: break

    pointers[i] = return_addr
    sp = cfa
    bp = restore_bp(entry, cfa)
    current_ip = return_addr
```

### BPF Verifier Constraints

The eBPF code is structured to pass the BPF verifier:
- All loops use bounded `for _ in 0..CONST` ranges
- Binary search uses `for _ in 0..19` (not `while`)
- Mapping scan uses `for m in 0..16` with early break
- `MAX_DWARF_STACK_DEPTH = 32` keeps the outer loop bounded
- Functions are `#[inline(always)]` to avoid BPF function call overhead
- Sharded tables reduce verifier complexity by keeping per-binary tables smaller

## Performance

### Memory
- Typical process (binary + libc + ld): ~23K entries × 12B = **~270 KB**
- **Sharded design**: Each binary gets its own table (max 500K entries per binary)
- Maximum: 64 binaries × 500K entries × 20B (key + value) = **~600 MB** total capacity
- Build-ID based deduplication: Same binary across multiple processes reuses the same table_id
- ProcInfo per process: ~200 bytes

### CPU (per sample, when DWARF enabled)
- Mapping lookup: O(n) where n ≤ 16
- Binary search: O(log n) where n ≤ 500K per binary, max 19 iterations
- `bpf_probe_read_user`: 1-2 calls per frame (return address + optional RBP restore)
- Compared to FP unwinding (1 `bpf_probe_read` per frame), DWARF is ~10-20x more instructions per frame
- In practice, the overhead is negligible at typical sampling rates (99-999 Hz)

### Startup
- Parsing `.eh_frame` for all mappings: ~10-50ms
- Loading BPF maps: <1ms

## Limitations

- **No hot-reload**: dlopen'd libraries after startup won't have unwind tables (but periodic rescanning is supported)
- **MAX_PROC_MAPS = 16**: processes with very many shared libraries may exceed this
- **MAX_DWARF_STACK_DEPTH = 32**: stacks deeper than 32 frames are truncated
- **MAX_UNWIND_TABLE_SIZE = 500K per binary**: very large binaries (Chrome, Firefox) with >500K unwind entries will be truncated
- **MAX_UNWIND_TABLES = 64**: system-wide profiling limited to 64 unique binaries
- **No signal trampolines**: unwinding through signal handlers may stop early on kernels where the vDSO lacks `.eh_frame` entries for `__restore_rt` (libc's `__restore_rt` is handled)
- **x86_64 only**: register rules are hardcoded for x86_64 (RSP, RBP, RA)

## Testing

13 E2E tests in `tests/run_e2e.sh`:

| Test | What it validates |
|------|-------------------|
| FP callstack | Baseline: FP unwinding produces correct chain |
| FP deep recursion | Baseline: 20 levels of recursion with FP |
| Samples collected | Sanity: profiler collects non-zero samples |
| No-FP without DWARF | Problem statement: no-FP binary produces shallow stacks |
| DWARF callstack | DWARF unwinds no-FP binary: hot→c→b→a→main |
| DWARF callstack O2 | DWARF handles -O2 inlining correctly |
| DWARF deep recursion | 20 levels of recursion without FP |
| DWARF shared library | Cross-.so boundary unwinding |
| DWARF PIE binary | Position-independent executable |
| DWARF ≥ FP depth | DWARF produces at least as many frames as FP |
| DWARF improves no-FP | DWARF produces deeper stacks than no-DWARF |
| Robustness | Non-existent binary doesn't crash |

Test fixtures in `tests/fixtures/src/`, compiled binaries in `tests/fixtures/bin/`.

## References

- [Polar Signals: Profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers)
- [Parca Agent unwind implementation](https://github.com/parca-dev/parca-agent)
- [gimli DWARF parser](https://github.com/gimli-rs/gimli)
- [The `.eh_frame` section](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
