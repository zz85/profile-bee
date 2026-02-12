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

**Future improvement: tail-call chaining to reach 128+ frames**

To reach 32+ frames, the eBPF unwind loop needs to be split into a tail-call chain. This is the approach used by production profilers like [opentelemetry-ebpf-profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) (formerly Elastic/Prodfiler) and parca-agent.

The idea: instead of one big loop that the BPF verifier rejects, unwind a small fixed number of frames per eBPF program invocation, then `bpf_tail_call()` back into the same program. Each tail call resets the verifier's instruction budget, so the total depth is limited only by the tail-call limit (33 on most kernels).

**How opentelemetry-ebpf-profiler does it:**

```
// Only unwind 5 frames per program invocation
#define NATIVE_FRAMES_PER_PROGRAM  5

static int unwind_native(struct pt_regs *ctx) {
    PerCPURecord *record = get_per_cpu_record();  // state persisted in per-CPU map
    Trace *trace = &record->trace;

    for (int i = 0; i < NATIVE_FRAMES_PER_PROGRAM; i++) {
        push_native(&record->state, trace, ...);
        error = unwind_one_frame(&record->state, &stop);
        if (error || stop) break;
        error = get_next_unwinder(&record, &unwinder);
        if (error || unwinder != PROG_UNWIND_NATIVE) break;
    }

    // Tail-call back into ourselves (or into interpreter unwinder, or stop)
    // This resets the BPF verifier instruction count
    tail_call(ctx, unwinder);
}
```

Key design points:
- **Per-CPU state map:** Unwind state (SP, BP, IP, frame array, frame count) is stored in a `BPF_MAP_TYPE_PERCPU_ARRAY`, not on the eBPF stack. This persists across tail calls.
- **Small inner loop:** 4-5 frames per invocation keeps the verifier happy even with complex per-frame logic (mapping lookup + binary search + CFA computation).
- **Tail-call limit = depth limit:** With 5 frames/call × 33 tail calls = 165 max frames. More than enough.
- **Program array map:** Uses `BPF_MAP_TYPE_PROG_ARRAY` to dispatch tail calls. The same program index can tail-call to itself.

**What this would look like for profile-bee (aya-rs):**

```rust
// In eBPF code:
#[map]
static PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

#[map]
static UNWIND_STATE: PerCpuArray<DwarfUnwindState> = PerCpuArray::with_max_entries(1, 0);

const FRAMES_PER_CALL: usize = 5;

fn dwarf_unwind_step(ctx: &PerfEventContext) {
    let state = UNWIND_STATE.get_ptr_mut(0).unwrap();
    for _ in 0..FRAMES_PER_CALL {
        // ... unwind one frame, store in state.pointers[state.len] ...
        if done { break; }
    }
    if !done {
        // Tail-call back into ourselves
        unsafe { PROG_ARRAY.tail_call(ctx, 0); }
    }
}
```

This would require:
1. Moving the `FramePointers` and unwind registers (SP, BP, IP) into a per-CPU map
2. Splitting `dwarf_copy_stack()` into an init function (called from `collect_trace`) and a step function (the tail-call target)
3. Registering the step function in a `ProgramArray` map from userspace

References:
- [opentelemetry-ebpf-profiler native_stack_trace.ebpf.c](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/support/ebpf/native_stack_trace.ebpf.c) — `NATIVE_FRAMES_PER_PROGRAM = 5`, `tail_call()` pattern
- [Elastic blog: profiling without frame pointers](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf) — architecture overview
- [Polar Signals: DWARF-based stack walking using eBPF](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf/) — parca-agent's approach

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
