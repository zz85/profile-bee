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
│  4. Load into BPF maps: unwind shards (ArrayOfMaps), EXEC_MAPPINGS (LPM trie)  │
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
│       │                              ├─ LPM trie lookup by (tgid, IP)│
│       │                              ├─ For each frame (flat loop): │
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
| `profile-bee-common/src/lib.rs` | Shared types: `UnwindEntry`, `ExecMappingKey`, `ExecMapping`, constants |
| `profile-bee/src/ebpf.rs` | `EbpfProfiler`: loads eBPF program, sets `DWARF_ENABLED`, loads maps |
| `profile-bee/src/trace_handler.rs` | Picks DWARF stack vs FP stack (whichever is deeper) |

## Data Structures

### UnwindEntry (12 bytes, stored in per-binary Array maps)

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

### ExecMappingKey (16 bytes, LPM trie key data)

```rust
pub struct ExecMappingKey {
    pub tgid: u32,    // big-endian (LPM trie matches MSB-first)
    pub _pad: u32,    // must be 0 (ensures 8-byte alignment for address)
    pub address: u64, // big-endian
}
```

Combined with aya's `Key<T>` which prepends a `u32 prefix_len` field, the full
LPM trie key is 20 bytes. Full-match prefix_len = 128 (32 + 32 + 64 bits).

Userspace decomposes each exec mapping's address range `[begin, end)` into
aligned power-of-2 blocks (the same algorithm as CIDR route summarization) and
inserts each block as a separate LPM trie entry.

### ExecMapping (per-mapping, LPM trie value)

```rust
pub struct ExecMapping {
    pub begin: u64,        // Virtual address range start
    pub end: u64,          // Virtual address range end
    pub load_bias: u64,    // Subtract from IP to get file-relative PC
    pub shard_id: u16,     // Which shard Array to search (0..MAX_UNWIND_SHARDS-1, or SHARD_NONE)
    pub _pad1: [u8; 2],
    pub table_count: u32,  // Number of entries in this shard for this binary
}
```

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `unwind_shards` | ArrayOfMaps\<Array\<UnwindEntry\>\> | 512 outer slots × 131K max entries/shard | Per-binary unwind tables (shard_id → Array, indexed by entry offset) |
| `exec_mappings` | LPM Trie | 200K entries max | Exec mapping lookup by (tgid, address) → ExecMapping via longest-prefix match |
| `dwarf_tgids` | HashMap\<u32, u8\> | 4096 entries max | Tracks which tgids have DWARF data loaded (for process exit cleanup) |
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

// Tail-call chaining: collect_trace inits per-CPU state, then tail-calls
// dwarf_unwind_step via PROG_ARRAY. Each invocation unwinds 5 frames and
// tail-calls itself (up to 33 times, kernel limit) for MAX_DWARF_STACK_DEPTH = 165.
// Legacy fallback (no tail calls): flat loop of LEGACY_MAX_DWARF_STACK_DEPTH = 21.

// Per tail-call invocation (dwarf_unwind_step):
for _ in 0..FRAMES_PER_TAIL_CALL:
    mapping = EXEC_MAPPINGS.get(tgid, current_ip)  // LPM trie O(key_bits)
    relative_pc = current_ip - mapping.load_bias
    entry = binary_search(mapping.shard_id, relative_pc)  // max 17 iterations

    cfa = (entry.cfa_type == RSP) ? sp + entry.cfa_offset
                                  : bp + entry.cfa_offset

    return_addr = bpf_probe_read_user(cfa - 8)  // RA always at CFA-8 on x86_64

    if return_addr == 0: break

    pointers[frame_count++] = return_addr
    sp = cfa
    bp = restore_bp(entry, cfa)
    current_ip = return_addr

// If more frames needed: PROG_ARRAY.tail_call(ctx, 0) — re-enters this step
// If done or limit reached: finalize (copy pointers to STORAGE, submit to ring buffer)
```

### BPF Verifier Constraints

The eBPF code is structured to pass the BPF verifier:
- All loops use bounded `for _ in 0..CONST` ranges
- Binary search uses `for _ in 0..17` (max depth for 131K entries per shard)
- Mapping lookup uses LPM trie (`EXEC_MAPPINGS.get()`) — O(key_bits), no loop
- **Tail-call chaining** via `PROG_ARRAY` achieves `MAX_DWARF_STACK_DEPTH = 165` frames (5 frames × 33 tail calls). Each tail call resets the verifier's instruction budget, so the per-invocation complexity stays low (~5 × (1 LPM lookup + 17 binary search) ≈ 400 instructions). The `dwarf_unwind_step` program unwinds `FRAMES_PER_TAIL_CALL` (5) frames then tail-calls itself.
- **Legacy fallback**: a flat loop of `LEGACY_MAX_DWARF_STACK_DEPTH = 21` frames is used when tail calls are unavailable (kprobe/uprobe contexts, or if `PROG_ARRAY` registration fails)
- Functions are `#[inline(always)]` to avoid BPF function call overhead
- Sharded tables reduce verifier complexity by keeping per-binary tables smaller

## Performance

### Memory
- Typical process (binary + libc + ld): ~23K entries × 12B = **~270 KB**
- **Array-of-maps design**: Each binary gets its own inner Array map (max 131K entries per shard)
- Maximum: 512 shards × 131K entries × 12B = **~770 MB** total capacity (unused slots cost nothing)
- Build-ID based deduplication: Same binary across multiple processes reuses the same shard
- LPM trie entries per mapping: ~10-20 prefix blocks per address range

### CPU (per sample, when DWARF enabled)
- Mapping lookup: O(key_bits) via LPM trie (replaces old O(n) linear scan)
- Binary search: O(log n) where n ≤ 131K per shard, max 17 iterations
- `bpf_probe_read_user`: 1-2 calls per frame (return address + optional RBP restore)
- Compared to FP unwinding (1 `bpf_probe_read` per frame), DWARF is ~10-20x more instructions per frame
- In practice, the overhead is negligible at typical sampling rates (99-999 Hz)

### Startup
- Parsing `.eh_frame` for all mappings: ~10-50ms
- Loading BPF maps: <1ms

## Limitations

- **No hot-reload**: dlopen'd libraries after startup won't have unwind tables (but periodic rescanning is supported)
- **165 frame depth**: achieved via tail-call chaining through `PROG_ARRAY` (5 frames per tail call × 33 tail calls). Legacy flat-loop fallback limited to ~21 frames when tail calls are unavailable (kprobe/uprobe contexts, older kernels).
- **MAX_SHARD_ENTRIES = 131K per binary**: very large binaries (Chrome, Firefox) with >131K unwind entries will be truncated
- **MAX_UNWIND_SHARDS = 512**: system-wide profiling limited to 512 unique binaries
- **MAX_EXEC_MAPPING_ENTRIES = 200K**: LPM trie entries across all processes; typically ~10-20 entries per mapping
- **No signal trampolines**: unwinding through signal handlers may stop early on kernels where the vDSO lacks `.eh_frame` entries for `__restore_rt` (libc's `__restore_rt` is handled)
- **x86_64 only**: register rules are hardcoded for x86_64 (RSP, RBP, RA)

## Testing

14 E2E tests in `tests/run_e2e.sh`:

| Test | What it validates |
|------|-------------------|
| FP callstack | Baseline: FP unwinding produces correct chain |
| FP deep recursion | Baseline: 20 levels of recursion with FP |
| Samples collected | Sanity: profiler collects non-zero samples |
| No-FP without DWARF | Problem statement: no-FP binary produces shallow stacks |
| DWARF callstack | DWARF unwinds no-FP binary: hot→c→b→a→main |
| DWARF callstack O2 | DWARF handles -O2 inlining correctly |
| DWARF deep recursion | 20 levels of recursion without FP |
| DWARF deep stack | 50 levels of recursion without FP (verifies ≥20 frames captured) |
| DWARF shared library | Cross-.so boundary unwinding |
| DWARF PIE binary | Position-independent executable |
| DWARF Rust binary | Rust binary compiled at O2 without frame pointers |
| DWARF ≥ FP depth | DWARF produces at least as many frames as FP |
| DWARF improves no-FP | DWARF produces deeper stacks than no-DWARF |
| Robustness | Non-existent binary doesn't crash |

Test fixtures in `tests/fixtures/src/`, compiled binaries in `tests/fixtures/bin/`.

## References

- [Polar Signals: Profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers)
- [Parca Agent unwind implementation](https://github.com/parca-dev/parca-agent)
- [gimli DWARF parser](https://github.com/gimli-rs/gimli)
- [The `.eh_frame` section](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
