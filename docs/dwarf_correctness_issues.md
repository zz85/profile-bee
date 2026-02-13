# DWARF Unwinding Correctness Issues

Findings from comparing profile-bee DWARF unwinding against `perf --call-graph dwarf` on the same binaries.

**Test environment:** Linux 5.10, x86_64, gcc 7.x, profile-bee at commit 7554585 (origin/main)

## Issue 1: MAX_DWARF_STACK_DEPTH was too low (12 frames) — FIXED

**Severity:** High  
**File:** `profile-bee-common/src/lib.rs`  
**Status:** Fixed — increased to 21 (was 22 before signal frame support; see Issue 2)

The constant `MAX_DWARF_STACK_DEPTH` was set to 12, truncating stacks for any moderately deep call chain. The design doc and README both claimed 32 frames, but the BPF verifier rejects values above 22 on kernel 5.10 (the nested loops in `dwarf_copy_stack` — 8 mapping iterations × N depth iterations × 16 binary search iterations — exceed the verifier's instruction limit).

**Before (depth=12):**
```
recurse ×11 → leaf                    (12 frames, missing main/__libc_start_main/_start)
```

**After (depth=22):**
```
recurse ×21 → leaf                    (22 frames)
```

**perf reference (depth=24):**
```
leaf → recurse ×20 → main → __libc_start_main → _start
```

The fix captures the full 20-level recursion. The remaining 2-frame gap vs perf is because perf unwinds in userspace with no depth limit.

**Tail-call chaining to reach 165 frames — IN PROGRESS**

**Status:** Infrastructure added, implementation in progress. See [docs/tail_call_unwinding.md](tail_call_unwinding.md) for complete design and implementation details.

To reach 32+ frames, the eBPF unwind loop is being split into a tail-call chain. This is the approach used by production profilers like [opentelemetry-ebpf-profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) and parca-agent.

**Current progress:**

✅ Phase 1: Infrastructure (Completed)
- `DwarfUnwindState` structure for per-CPU state storage
- `UNWIND_STATE` and `PROG_ARRAY` maps added to eBPF code
- Constants updated: `MAX_DWARF_STACK_DEPTH = 165` (5 frames/call × 33 tail calls)
- Legacy implementation preserved at `LEGACY_MAX_DWARF_STACK_DEPTH = 21`

🚧 Phase 2: Implementation (In Progress)
- Splitting `dwarf_copy_stack()` into init and step functions
- Making step function tail-callable
- Registering programs in `PROG_ARRAY` from userspace

📋 Phase 3: Testing (Pending)
- Tests for 50+, 100+ frame depths
- Performance validation
- Kernel compatibility testing (5.4, 5.10, 5.15, 6.x)

**Design highlights:**
- **5 frames per tail call** keeps verifier happy (~600-800 instructions/call vs 4K limit)
- **165 max frames** (5 × 33 tail calls, kernel limit)
- **Per-CPU state map** stores unwinding state across calls (8.2 KB per CPU)
- **Automatic fallback** to 21-frame legacy mode on older kernels

For complete implementation details, architecture diagrams, and code examples, see [docs/tail_call_unwinding.md](tail_call_unwinding.md).

References:
- [opentelemetry-ebpf-profiler native_stack_trace.ebpf.c](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/support/ebpf/native_stack_trace.ebpf.c)
- [Elastic blog: profiling without frame pointers](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf)
- [Polar Signals: DWARF-based stack walking using eBPF](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf/)

## Issue 2: Signal trampoline unwinding stops at `__restore_rt` — FIXED

**Severity:** Medium  
**File:** `profile-bee-ebpf/src/lib.rs` (dwarf_copy_stack), `profile-bee/src/dwarf_unwind.rs`

When a signal handler is active, profile-bee now unwinds through the signal trampoline into the interrupted frame.

**Before:**
```
[unknown] → __restore_rt → handler → signal_work     (stopped here)
```

**After:**
```
[unknown] → _start → __libc_start_main → main → compute → __restore_rt → handler → signal_work
```

**perf reference:**
```
signal_work → handler → __restore_rt → compute → main → __libc_start_main → _start
```

**Root cause:** The `__restore_rt` FDE uses `DW_CFA_expression` rules for all registers (not the standard `Offset(-8)` for RA). The userspace DWARF parser was skipping entries where RA wasn't `Offset(-8)`, so the signal frame entry never made it into the unwind table.

**Fix:** Two changes:
1. **Userspace** (`dwarf_unwind.rs`): Allow signal frame entries through even when RA is an expression rule, since the eBPF code handles them specially.
2. **eBPF** (`lib.rs`): When `CFA_REG_DEREF_RSP` is detected, read RIP/RSP/RBP directly from the `ucontext_t` at fixed x86_64 Linux offsets (`RSP+168`, `RSP+160`, `RSP+120`) instead of using the standard `CFA-8` return address convention.

**Tradeoff:** The extra `bpf_probe_read_user` calls for signal frame handling consume verifier budget, reducing `MAX_DWARF_STACK_DEPTH` from 22 to 21 (one fewer frame in the deepest stacks).

## Issue 3: Partial shared library unwinding failures (~51% of samples) — FIXED

**Severity:** Medium  
**File:** `profile-bee/src/dwarf_unwind.rs`

For the shared library test, previously only ~49% of samples got the full call chain. The rest showed only `[unknown];lib_hot`.

**Before:**
```
sharedlib-no-fp;[unknown];_start;__libc_start_main;main;caller_a;caller_b;lib_entry;lib_inner;lib_hot  47
sharedlib-no-fp;[unknown];lib_hot                                                                     101
```

**After:**
```
sharedlib-no-fp;[unknown];_start;__libc_start_main;main;caller_a;caller_b;lib_entry;lib_inner;lib_hot  298
```

**Root cause:** Race condition between process spawn and initial DWARF table load. When using `--cmd`, the process is spawned and `load_process` reads `/proc/PID/maps` immediately. But the dynamic linker hasn't finished mapping shared libraries yet, so the initial load captures only the main binary's unwind table (~1412 entries). The shared library and libc tables (~19000 entries) are only picked up by the background refresh thread 1 second later.

**Fix:** Poll `/proc/PID/maps` until the executable mapping count stabilizes before loading unwind tables. This waits for the dynamic linker to finish (typically <50ms) without using a fragile fixed delay.

## Issue 4: Persistent `[unknown]` frame at stack bottom

**Severity:** Low  
**File:** `profile-bee/src/trace_handler.rs`

Every stack has an `[unknown]` frame between the process name and `_start`. This is the initial RIP value (frame 0) which blazesym can't symbolize — likely the ELF entry stub or a kernel-to-userspace transition address.

Cosmetic issue but adds noise to flamegraphs.

## Issue 5: Design doc vs implementation mismatch — FIXED

**Severity:** Low

| Constant | Design doc | Code (before) | Code (after fix) |
|----------|-----------|---------------|-------------------|
| MAX_DWARF_STACK_DEPTH | 32 | 12 | 21 |
| MAX_PROC_MAPS | 16 | 8 | 8 (can't increase — BPF verifier) |

The design doc has been updated to reflect the actual BPF verifier limits.

## Test Results Summary

### Before fixes

| Test | pb depth | perf depth | Match? |
|------|----------|------------|--------|
| Basic callstack | 9 | 8 | ✅ |
| Deep recursion (20 levels) | 13 | 24 | ❌ Truncated at 12 |
| Shared library | 10 | 8 | ⚠️ 51% fail |
| PIE binary | 9 | 8 | ✅ |
| Indirect calls | 11 | 10 | ✅ |
| Multi-threaded | 8 | 8 | ✅ |
| Signal handler | 6 | 7 | ❌ Stops at trampoline |
| Rust binary (O2) | 8 | 9 | ✅ |

### After all fixes (depth=21, signal trampoline, shared lib race)

| Test | pb depth | perf depth | Match? |
|------|----------|------------|--------|
| Basic callstack | 9 | 8 | ✅ |
| Deep recursion (20 levels) | 22 | 24 | ✅ (within 2 frames) |
| Shared library | 10 | 8 | ✅ 100% success |
| Signal handler | 9 | 7 | ✅ Crosses trampoline |
| PIE binary | 9 | 8 | ✅ |
| Indirect calls | 11 | 10 | ✅ |
| Multi-threaded | 8 | 8 | ✅ |
| Rust binary (O2) | 8 | 9 | ✅ |
