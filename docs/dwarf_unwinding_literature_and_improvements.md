# DWARF Stack Unwinding: Literature Review & Improvement Plan

## Background

Most Linux binaries are compiled without frame pointers (`-fomit-frame-pointer` is the default at `-O2`+). This breaks the simple linked-list stack walk that `bpf_get_stackid()` relies on. The `.eh_frame` ELF section — originally for C++ exception handling — contains DWARF Call Frame Information (CFI) that describes how to restore registers at every program counter. It's present in virtually all ELF binaries, even pure C ones.

## Literature & Prior Art

### Elastic / Prodfiler (now OTel eBPF Profiler)

- **Source**: [Elastic blog post](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf), [GitHub](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
- **Patented**: [US11604718B1](https://patents.google.com/patent/US11604718B1/en)

Pioneered `.eh_frame`-based unwinding from eBPF in 2019 (launched as Prodfiler in 2021). The eBPF code detects executables compiled without frame pointers and notifies userspace. Userspace parses `.eh_frame`, converts DWARF CFI into a compact lookup structure, and loads it back into BPF maps. Key characteristics:

- System-wide profiling with dynamic process discovery
- Full DWARF expression VM support
- Multi-runtime: native + JVM + Python + Ruby + PHP + Node.js + .NET + Perl + Erlang
- ARM64 support
- Native inline frame resolution
- Production-proven at 10K+ core scale since 2021

### Parca Agent

- **Source**: [Polar Signals blog post](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf), [GitHub](https://github.com/parca-dev/parca-agent)

Open-source DWARF-based eBPF unwinder (Go). Architecture:

1. Userspace parses `.eh_frame`, evaluates DWARF CFI state machine, produces a flat sorted table
2. Table loaded into BPF array map; per-process mapping info into hash map
3. eBPF binary-searches the table, computes CFA, reads return address via `bpf_probe_read_user`

Notable design choices:

- **Compact 8-byte row**: `u64 pc, u16 reserved, u8 cfa_type, u8 rbp_type, i16 cfa_offset, i16 rbp_offset` — uses `i16` offsets since most real-world offsets fit in 16 bits
- **Hardcodes 2 most common DWARF expressions** (covering >50% of expression-based entries) rather than skipping all expressions
- System-wide profiling with dynamic process discovery
- Snapshot testing of unwind tables against known-good outputs for correctness

### INRIA Paper: "Reliable and Fast DWARF-Based Stack Unwinding" (OOPSLA'19)

- **Source**: [ACM DL](https://dl.acm.org/doi/10.1145/3360572), Bastian et al.

Key contributions:

- **Validation**: Fixed-point control flow analysis to verify that compiler-generated `.eh_frame` tables are correct. Found real bugs in GCC and LLVM unwind table generation.
- **Synthesis**: Generate unwind tables from object code when `.eh_frame` is missing or broken — useful as a fallback for stripped binaries.
- Comprehensive description of the DWARF CFI format and its interaction with x86_64 ABI.
- Demonstrated that unwind table correctness is not guaranteed — compilers do produce incorrect entries.

### Converged Architecture

All three production systems converge on the same high-level design:

```
Userspace:  parse .eh_frame → evaluate DWARF CFI → flat table (PC → CFA/RA/RBP rules)
                                    ↓
BPF maps:   Array<UnwindEntry> + HashMap<pid, ProcInfo>
                                    ↓
eBPF:       binary search table → compute CFA → bpf_probe_read_user(RA) → loop
```

## Profile-Bee's Current Implementation

### Active Path (`dwarf_unwind.rs` + eBPF `lib.rs`)

Follows the Parca architecture:

- `DwarfUnwindManager` parses `/proc/[pid]/maps`, reads `.eh_frame` via `gimli`, generates `Vec<UnwindEntry>` sorted by PC
- `UnwindEntry` is **32 bytes**: `u64 pc` + `u8 cfa_type` + 3 pad + `i32 cfa_offset` + `u8 ra_type` + 3 pad + `i32 ra_offset` + `u8 rbp_type` + 3 pad + `i32 rbp_offset`
- Loaded into BPF `Array<UnwindEntry>` (max 250K entries) + `HashMap<ProcInfoKey, ProcInfo>`
- eBPF: `dwarf_copy_stack()` does linear mapping scan (max 8), binary search (max 16 iterations), CFA computation, `bpf_probe_read_user` for RA/RBP, up to 32 frames
- Falls back to FP-based `copy_stack()` if no proc_info found for the tgid

### Dead Code: `unwinder/` Module

An earlier, incomplete iteration that should be removed:

- `unwinder/ehframe.rs`: Parses `.eh_frame` into `UnwindTableRow` with `Instruction` types
- `unwinder/maps.rs`: Reads `/proc/[pid]/maps` via `procmaps` crate
- `unwinder/mod.rs`: Flattens into `DwarfUnwindInfo` with `DwarfDelta` (`i8` offsets — far too small for real use)
- Has commented-out BPF walk code; `find_instruction()` is incomplete
- Uses different common types (`DwarfDelta`, `DwarfUnwindInfo`) from the active path

## Comparison with Production Systems

| Aspect | Profile-Bee | Parca Agent | OTel eBPF Profiler |
|--------|------------|-------------|-------------------|
| Row size | 12 bytes (u32 PC, i16 offsets) | 8 bytes (i16, packed) | ~similar to Parca |
| DWARF expressions | 2 most common (PLT + signal) | 2 most common hardcoded | Full support |
| Scope | Single process only | System-wide, dynamic | System-wide, dynamic |
| Max mappings/process | 16 | Dynamic | Dynamic |
| Max table entries | 250K global | Dynamic (sharded) | Dynamic |
| Signal trampolines | Handled (libc) | Handled | Handled |
| FP fallback | Yes (when no DWARF entry) | No | No |
| Entry deduplication | Yes (consecutive identical) | No | No |
| Architecture | x86_64 only | x86_64 + arm64 | x86_64 + arm64 |
| dlopen support | None | Dynamic reload | Dynamic reload |
| Inline frames | No | No | Yes |
| Runtime support | Native only | Native only | Native + 8 HLL runtimes |
| Binary cache key | File path | Build ID | File ID |

## Improvement Plan

### High Impact, Lower Effort

#### 1. Compact UnwindEntry to ~12 bytes

Parca uses `i16` offsets and packs to 8 bytes. Profile-bee's 32-byte entries waste 4x BPF map memory. Most real-world CFA/RA/RBP offsets fit in `i16`. Proposed layout:

```rust
#[repr(C, packed)]
pub struct UnwindEntry {
    pub pc: u64,        // 8 bytes
    pub cfa_offset: i16, // 2 bytes
    pub rbp_offset: i16, // 2 bytes
    pub cfa_type: u8,    // 1 byte
    pub rbp_type: u8,    // 1 byte
}                        // 14 bytes (RA is always CFA-8 on x86_64)
```

This would fit 4x more entries in the same budget, or reduce memory from 7.6MB to ~2MB.

#### 2. Handle the 2 Most Common DWARF Expressions

Currently all `CFA_REG_EXPRESSION` entries are skipped. Parca found two specific expressions cover >50% of expression-based rows (typically in glibc). Implementing these would improve coverage for system libraries.

#### 3. Remove Dead `unwinder/` Module

Remove `unwinder/ehframe.rs`, `unwinder/maps.rs`, `unwinder/mod.rs`, and the `DwarfDelta`/`DwarfUnwindInfo` types from `profile-bee-common`. They're unused dead code from an earlier iteration with `i8` offsets that can't represent real-world values.

#### 4. Handle Signal Trampolines (vDSO `__restore_rt`)

When a signal interrupts execution, the kernel pushes a signal frame. Without special handling, unwinding stops at the signal trampoline. Both Parca and OTel handle this by detecting the vDSO sigreturn address and manually stepping over the signal frame.

#### 5. Fix `copy_stack()` Early Return Bug

The FP-based `copy_stack()` in `profile-bee-ebpf/src/lib.rs` has a `return (ip, bp, 1, sp);` before the actual frame-walking loop (line ~186), making FP unwinding always return depth 1. This means non-DWARF mode is effectively broken.

### Medium Impact, Medium Effort

#### 6. System-Wide DWARF Profiling

Currently limited to `--pid`/`--cmd`. The eBPF program could notify userspace of newly-seen tgids via ring buffer, triggering on-demand unwind table loading (the Elastic/Prodfiler approach).

#### 7. Dynamic Library Hot-Loading (dlopen)

Monitor `/proc/[pid]/maps` periodically or use `mmap`/`munmap` tracepoints to detect new mappings. Reload unwind tables for newly loaded shared libraries.

#### 8. Build-ID Based Caching

Use ELF build IDs instead of file paths as cache keys. Handles container environments where the same binary appears at different paths, and avoids re-parsing when the same library is loaded by multiple processes.

#### 9. Increase MAX_PROC_MAPS

8 mappings is tight. A typical process has main binary + libc + ld-linux + libpthread + libm + libgcc_s + libstdc++ + more, easily exceeding 8. Bumping to 16-32 would cover most real-world cases.

#### 10. Unwind Table Validation

Per the INRIA paper, compiler-generated `.eh_frame` tables can have bugs. A validation pass (checking CFA offset monotonicity within functions, RA always at CFA-8 for x86_64, etc.) would catch corrupt entries before loading them into eBPF.

### Lower Priority, Higher Effort

#### 11. ARM64 Support

Different register constants and CFA rules, but the same overall architecture.

#### 12. Inline Frame Resolution

Use `.debug_info` to resolve inline function boundaries for more accurate flamegraphs of optimized code.

#### 13. Sharded Unwind Tables

Replace the single global 250K-entry array with per-binary or per-mapping tables. Removes the global limit and enables profiling very large binaries (Chrome, Firefox).

## Recommended Priority

All high-impact quick wins are now complete:

1. ~~**Remove dead code** (#3)~~ ✅ Done
2. ~~**Fix FP unwinding bug** (#5)~~ ✅ Done
3. ~~**Compact UnwindEntry** (#1)~~ ✅ Done (12 bytes: u32 PC, i16 offsets)
4. ~~**Expression support** (#2)~~ ✅ Done (PLT + signal frame)
5. ~~**Signal trampolines** (#4)~~ ✅ Done (CFA_REG_DEREF_RSP + vDSO parsing)

Additional improvements completed (from async-profiler analysis):
- ✅ Entry deduplication (7-63% reduction depending on binary)
- ✅ u32 PC (file-relative addresses fit in 32 bits)
- ✅ FP-based fallback when no DWARF entry found
- ✅ MAX_PROC_MAPS increased to 16
- ✅ vDSO .eh_frame parsing from /proc/[pid]/mem

Remaining medium-effort items: #6 (system-wide), #7 (dlopen), #8 (build-ID cache), #10 (validation).

## References

1. [Polar Signals: DWARF-based Stack Walking Using eBPF](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf)
2. [Elastic: How Universal Profiling unwinds stacks without frame pointers](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf)
3. [Bastian et al.: Reliable and Fast DWARF-Based Stack Unwinding (OOPSLA'19)](https://dl.acm.org/doi/10.1145/3360572)
4. [OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
5. [Parca Agent](https://github.com/parca-dev/parca-agent)
6. [Ian Lance Taylor: .eh_frame](https://www.airs.com/blog/archives/460)
7. [MaskRay: Stack unwinding](https://maskray.me/blog/2020-11-08-stack-unwinding)
8. [corsix.org: ELF .eh_frame](https://www.corsix.org/content/elf-eh-frame)

## Appendix: async-profiler Analysis

### Overview

[async-profiler](https://github.com/async-profiler/async-profiler) (8.8K stars) is a userspace sampling profiler for Java (C++, ~55% of codebase). Unlike profile-bee's eBPF approach, it runs inside the target process via a JVMTI agent and uses `SIGPROF` signal handlers to sample. This gives it direct memory access to the stack — no `bpf_probe_read_user` needed.

It offers three stack walking modes:
- **Frame Pointer (FP)**: traditional linked-list walk
- **DWARF**: `.eh_frame`-based unwinding (enabled with `--cstack dwarf`)
- **VM Structs**: JVM-internal structure walking (default since v4.2)

Despite the different execution model, several design choices are directly applicable.

### FrameDesc: 16-byte Compact Entry

```c
struct FrameDesc {
    u32 loc;       // 4B — file-relative PC (32-bit, not 64!)
    int cfa;       // 4B — packed: low byte = register, upper 24 bits = offset
    int fp_off;    // 4B — FP restore offset (or DW_SAME_FP sentinel)
    int pc_off;    // 4B — PC/RA offset from CFA
};
```

Key differences from profile-bee's `UnwindEntry`:
- **32-bit PC**: file-relative offsets within a single binary never exceed 4GB, so `u64` is wasteful. Profile-bee could save 4 bytes per entry by switching to `u32`.
- **Packed CFA field**: register number in the low byte, offset in the upper 24 bits of a single `int`. Eliminates the need for separate `cfa_type` and `cfa_offset` fields.

### PLT Stub Handling (`DW_REG_PLT`)

PLT stubs have a peculiar stack layout where the CFA offset depends on the instruction's position within the PLT entry. DWARF encodes this as a `DW_CFA_def_cfa_expression`, which profile-bee currently skips entirely.

async-profiler introduces a pseudo-register `DW_REG_PLT` and computes the actual offset at walk time:

```c
} else if (cfa_reg == DW_REG_PLT) {
    sp += ((uintptr_t)pc & 15) >= 11 ? cfa_off * 2 : cfa_off;
}
```

This is one of the "2 most common DWARF expressions" referenced in the Parca literature. Implementing it would improve unwinding through dynamically-linked function calls (e.g., calls into libc).

### Deduplication of Consecutive Identical Entries

In `addRecord()`, async-profiler skips adding a new entry if the CFA/FP/PC rules haven't changed from the previous entry:

```c
void DwarfParser::addRecord(...) {
    int cfa = cfa_reg | cfa_off << 8;
    if (_prev == NULL || (_prev->loc == loc && --_count >= 0) ||
            _prev->cfa != cfa || _prev->fp_off != fp_off || _prev->pc_off != pc_off) {
        _prev = addRecordRaw(loc, cfa, fp_off, pc_off);
    }
}
```

Profile-bee doesn't deduplicate — gimli's `rows()` iterator emits one entry per PC change, even if the rules are identical. Adding dedup could reduce table size by 20-40%.

### Default Frame Fallback

When no DWARF info is found for a PC, async-profiler falls back to `FrameDesc::default_frame` which assumes a standard frame-pointer-based layout (CFA = FP + 16, FP at CFA-16, RA at CFA-8 on x86_64). Profile-bee currently just stops unwinding when no entry is found. A FP-based fallback would recover additional frames in binaries with partial frame pointer coverage.

### SafeAccess and Crash Protection

async-profiler uses inline assembly for memory loads with a SIGSEGV handler that detects faults and returns a default value. The entire `walkVM` function is wrapped in `setjmp`/`longjmp` for crash recovery. Not directly applicable to eBPF (where `bpf_probe_read_user` handles faults), but the userspace symbolization path could benefit from similar protection.

### DW_CFA_val_expression for PC-Relative Unwinding

async-profiler parses a limited subset of DWARF expressions — specifically `DW_CFA_val_expression` for the PC register, encoding "previous PC = current PC + offset". This handles tail-call-optimized code where the return address isn't on the stack but can be computed from the current PC.

### Custom DWARF Parser

async-profiler implements its own DWARF CFI parser in ~300 lines of C++, directly consuming the `.eh_frame_hdr` binary search table for O(1) FDE lookup. This is faster than iterating all FDEs. They parse DWARF opcodes directly, only extracting the 3 registers they care about (SP, FP, PC).

### Actionable Takeaways for Profile-Bee

| # | Improvement | Estimated Impact |
|---|------------|-----------------|
| 1 | Deduplicate consecutive identical unwind entries | 20-40% table size reduction |
| 2 | Use `u32` for PC in UnwindEntry (12 bytes total) | 25% memory reduction |
| 3 | PLT stub handling (DW_REG_PLT trick) | Better unwinding through dynamic calls |
| 4 | Default FP-based fallback when no entry found | Recover frames in partial-FP binaries |
| 5 | Pack CFA register + offset into single field | Minor space optimization |
| 6 | Parse `.eh_frame_hdr` for faster FDE lookup | Faster startup for large binaries |

## Appendix: async-profiler — Off-CPU, Memory & Lock Profiling

Beyond DWARF unwinding, async-profiler implements several profiling modes that are relevant to profile-bee's roadmap (which lists "Off CPU profiling" as a TODO). Here's how they work and what's applicable.

### Wall-Clock / Off-CPU Profiling

async-profiler's `-e wall` mode samples all threads equally regardless of whether they're running, sleeping, or blocked. This is the key to off-CPU profiling — it reveals where threads spend time waiting.

**How it works:**
1. A dedicated timer thread iterates over all threads every `interval` (default ~5ms)
2. Sends `SIGPROF` (or configurable signal) to each thread
3. The signal handler inspects the interrupted context to classify thread state:
   - If PC points to a `syscall` instruction → `THREAD_SLEEPING`
   - If the previous instruction was `syscall` and the return value is `EINTR` → `THREAD_SLEEPING`
   - Otherwise → `THREAD_RUNNING`
4. Stack trace is captured with the thread state annotation

**Batch mode optimization (v4.2+):** Instead of recording every idle sample individually, consecutive idle samples for the same thread are batched into a single `WallClockEvent` with a `_time_span` and `_samples` count. This dramatically reduces overhead for mostly-idle threads. A lock-free MPSC ring buffer tracks per-thread CPU time to detect when a sleeping thread becomes runnable.

**Throttling:** At most `THREADS_PER_TICK = 8` threads are signaled per timer tick, preventing overhead explosion with many threads.

**Applicability to profile-bee:** An eBPF-based off-CPU profiler would use a different mechanism — typically attaching to `sched_switch` tracepoints to capture the moment a thread goes off-CPU and when it comes back. The stack is captured at the off-CPU transition. The key insight from async-profiler is the batching optimization: consecutive off-CPU periods for the same stack should be coalesced to reduce map pressure.

### Native Memory Profiling (`nativemem`)

async-profiler intercepts `malloc`, `calloc`, `realloc`, `free`, `posix_memalign`, and `aligned_alloc` via GOT/PLT patching (import table hooking). This is a non-intrusive approach that doesn't require recompilation.

**How it works:**
1. At startup, saves original function pointers from the GOT
2. Patches the GOT entries in all loaded libraries to point to hook functions
3. Hook functions call the original allocator, then record the allocation
4. `dlopen` is also hooked to patch newly loaded libraries
5. Sampling: not every allocation is recorded — a counter tracks total allocated bytes, and a sample is taken every `_interval` bytes (e.g., every 1MB)
6. For leak detection: `free` calls are also recorded, and `jfrconv --leak` matches allocations with frees to show only unfreed memory

**Key details:**
- Detects nested malloc (e.g., musl's `calloc` calls `malloc` internally) to prevent double-counting
- Uses dummy hooks for nested cases to preserve frame pointer chain
- Hooks are compiled with `-fno-omit-frame-pointer` and `-fno-optimize-sibling-calls` to ensure stack traces are correct through the hook functions
- Sampling interval is configurable: `--nativemem 1m` limits to one sample per MB allocated

**Applicability to profile-bee:** eBPF can attach uprobes to `malloc`/`free` or use `tracepoint:kmem:kmalloc` for kernel allocations. The sampling approach (record every Nth byte of allocation) is directly applicable to avoid overwhelming the perf buffer. The leak detection pattern (matching alloc/free by address) could be implemented with a BPF hashmap keyed by address.

### Native Lock Profiling (`--nativelock`)

Intercepts `pthread_mutex_lock`, `pthread_rwlock_rdlock`, and `pthread_rwlock_wrlock` via the same GOT patching mechanism.

**How it works:**
1. Hook first tries `pthread_mutex_trylock` — if it succeeds, no contention, no recording
2. If trylock fails, records `start_time` (via TSC), calls the real `pthread_mutex_lock`, records `end_time`
3. The duration `end_time - start_time` is the contention time in nanoseconds
4. Stack trace is captured at the lock acquisition point
5. Sampling: uses interval-based sampling on total contention duration

**Key insight:** Only contended locks are recorded (trylock succeeds = no contention = no overhead). This makes the profiler nearly zero-overhead for uncontended locks.

**Applicability to profile-bee:** eBPF can attach uprobes to `pthread_mutex_lock` entry/return to measure contention time. The trylock-first optimization isn't possible from eBPF (we can't modify the program's behavior), but we can filter by duration — only record lock acquisitions that took longer than a threshold.

### Architecture Comparison: Userspace Hooking vs eBPF

| Aspect | async-profiler (userspace) | profile-bee (eBPF) |
|--------|---------------------------|-------------------|
| Mechanism | GOT/PLT patching, signal handlers | eBPF programs on tracepoints/uprobes |
| Memory access | Direct pointer dereference | `bpf_probe_read_user` |
| Crash safety | `setjmp`/`longjmp`, `SafeAccess` SIGSEGV handler | BPF verifier prevents crashes |
| Scope | Single process (injected agent) | System-wide or per-process |
| Overhead control | Sampling interval, thread throttling | Sampling frequency, map size limits |
| dlopen handling | Hooks `dlopen` to patch new libraries | Would need `/proc/pid/maps` polling or mmap tracepoint |
| Off-CPU | Signal all threads + classify state | `sched_switch` tracepoint |
| Memory | GOT patching of malloc/free | uprobes on malloc/free or kmem tracepoints |
| Locks | GOT patching of pthread_mutex_lock | uprobes on pthread_mutex_lock entry/return |

### Concrete Ideas for profile-bee

1. **Off-CPU profiling via `sched_switch`**: Attach eBPF to `sched:sched_switch` tracepoint. On switch-out, record the stack + timestamp in a BPF hashmap keyed by `(tgid, tid)`. On switch-in, compute the off-CPU duration and emit the event. Batch consecutive off-CPU periods for the same stack (async-profiler's insight).

2. **Native memory profiling via uprobes**: Attach uprobes to `malloc`/`free` in libc. Use a BPF hashmap to track `address → (size, stack_id)`. Sample every Nth byte allocated (not every call). For leak detection, remove entries on `free` and periodically dump remaining entries.

3. **Lock contention via uprobes**: Attach uprobes to `pthread_mutex_lock` entry and uretprobes to its return. Measure wall-clock duration between entry and return. Only emit events above a configurable threshold (e.g., >1ms). The stack at entry shows who's waiting; the lock address identifies which lock.

4. **Hardware performance counters**: profile-bee already uses `perf_events` for CPU sampling. The same infrastructure supports `cache-misses`, `branch-misses`, `page-faults`, `context-switches`, etc. — just change the `perf_type_id` and `config` in the perf_event_open call. async-profiler supports all of these via `-e <event>`.
