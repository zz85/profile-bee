# DWARF Unwinding Correctness Issues

Findings from comparing profile-bee DWARF unwinding against `perf --call-graph dwarf` on the same binaries.

**Test environment:** Linux 5.10, x86_64, gcc 7.x, profile-bee at commit 7554585 (origin/main)

## Issue 1: MAX_DWARF_STACK_DEPTH was too low (12 frames) — FIXED

**Severity:** High  
**File:** `profile-bee-common/src/lib.rs`  
**Status:** Fixed — increased to 22

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

**Future improvement:** To reach 32 frames, the eBPF code would need restructuring to reduce verifier complexity — e.g., splitting the unwind loop into a tail-call chain across multiple eBPF programs.

## Issue 2: Signal trampoline unwinding stops at `__restore_rt`

**Severity:** Medium  
**File:** `profile-bee-ebpf/src/lib.rs` (dwarf_copy_stack)

When a signal handler is active, profile-bee unwinds through the handler but stops at `__restore_rt`. It does not continue into the interrupted frame.

**profile-bee:**
```
[unknown] → __restore_rt → handler → signal_work     (stops here)
```

**perf:**
```
signal_work → handler → __restore_rt → compute → main → __libc_start_main → _start
```

**Root cause:** After the `CFA_REG_DEREF_RSP` entry (signal frame), the unwinder needs to extract the saved registers (RIP, RSP, RBP) from the `ucontext_t` structure on the stack. Currently it treats the signal trampoline like a normal frame, which doesn't work because `__restore_rt` uses a DWARF expression to locate the saved context.

**Potential fix:** After detecting a signal frame (CFA_REG_DEREF_RSP), read the saved RIP/RSP/RBP from the `ucontext_t` at known offsets from the signal frame's stack pointer. On x86_64 Linux, the `mcontext_t` within `ucontext_t` has RIP at offset 168, RSP at offset 160, and RBP at offset 120 from the `ucontext_t` base.

## Issue 3: Partial shared library unwinding failures (~51% of samples)

**Severity:** Medium  
**File:** `profile-bee/src/dwarf_unwind.rs`, `profile-bee-ebpf/src/lib.rs`

For the shared library test, only ~49% of samples get the full call chain. The rest show only `[unknown];lib_hot`.

**profile-bee:**
```
sharedlib-no-fp;[unknown];_start;__libc_start_main;main;caller_a;caller_b;lib_entry;lib_inner;lib_hot  47
sharedlib-no-fp;[unknown];lib_hot                                                                     101
```

**perf:** 100% of samples get the full stack.

**Possible causes:**
1. The FP-based fallback (`try_fp_step`) in the eBPF code may be kicking in when the DWARF lookup fails at a library boundary, and the FP step produces a bad frame that terminates unwinding
2. The mapping lookup may not find the correct mapping when the return address crosses from `libhotlib.so` back to the main binary, if the main binary's mapping range doesn't cover the PLT/GOT region
3. Race between process startup and mapping scan — some samples may be collected before all mappings are loaded

**Investigation needed:** Add per-sample debug counters in eBPF to track where unwinding stops.

## Issue 4: Persistent `[unknown]` frame at stack bottom

**Severity:** Low  
**File:** `profile-bee/src/trace_handler.rs`

Every stack has an `[unknown]` frame between the process name and `_start`. This is the initial RIP value (frame 0) which blazesym can't symbolize — likely the ELF entry stub or a kernel-to-userspace transition address.

Cosmetic issue but adds noise to flamegraphs.

## Issue 5: Design doc vs implementation mismatch

**Severity:** Low

| Constant | Design doc | Code (before) | Code (after fix) |
|----------|-----------|---------------|-------------------|
| MAX_DWARF_STACK_DEPTH | 32 | 12 | 22 |
| MAX_PROC_MAPS | 16 | 8 | 8 (can't increase — BPF verifier) |

The design doc should be updated to reflect the actual BPF verifier limits.

## Test Results Summary

### Before fix (MAX_DWARF_STACK_DEPTH=12)

| Test | pb depth | perf depth | Match? |
|------|----------|------------|--------|
| Basic callstack | 9 | 8 | ✅ |
| Deep recursion (20 levels) | 13 | 24 | ❌ Truncated |
| Shared library | 10 | 8 | ⚠️ 51% fail |
| PIE binary | 9 | 8 | ✅ |
| Indirect calls | 11 | 10 | ✅ |
| Multi-threaded | 8 | 8 | ✅ |
| Signal handler | 6 | 7 | ❌ Stops at trampoline |
| Rust binary (O2) | 8 | 9 | ✅ |

### After fix (MAX_DWARF_STACK_DEPTH=22)

| Test | pb depth | perf depth | Match? |
|------|----------|------------|--------|
| Deep recursion (20 levels) | 23 | 24 | ✅ (within 1 frame) |
