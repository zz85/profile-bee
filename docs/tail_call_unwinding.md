# Tail-Call Unwinding for Deeper Stack Traces

## Overview

This document describes the tail-call unwinding implementation that enables profile-bee to capture stack traces deeper than the BPF verifier's instruction limit allows in a single program invocation.

## Background

### The Problem

The BPF verifier limits the complexity of eBPF programs to prevent infinite loops and ensure termination. This limit is approximately 4,096 instructions per program. The DWARF unwinding loop in `dwarf_copy_stack()` has nested loops:

- Outer loop: `MAX_DWARF_STACK_DEPTH` iterations (~21)
- Mapping lookup loop: `MAX_PROC_MAPS` iterations (~8)
- Binary search loop: `MAX_BIN_SEARCH_DEPTH` iterations (~16)

Total worst-case complexity: ~21 × 8 × 16 = 2,688 instructions, which approaches the verifier limit. Increasing `MAX_DWARF_STACK_DEPTH` beyond 21-22 causes the verifier to reject the program on kernel 5.10.

### The Solution

Use `bpf_tail_call()` to split the unwinding loop across multiple program invocations. Each tail call resets the verifier's instruction budget, allowing us to:

- Unwind 5 frames per invocation (keeping verifier happy)
- Support up to 33 tail calls (kernel limit)
- Achieve total depth of **5 × 33 = 165 frames**

This is the approach used by production profilers like [opentelemetry-ebpf-profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) and parca-agent.

##Implementation

### Data Structures

#### DwarfUnwindState (profile-bee-common/src/lib.rs)

Per-CPU state that persists across tail calls:

```rust
pub struct DwarfUnwindState {
    pub pointers: [u64; 1024],   // Frame array (RIP values)
    pub frame_count: usize,       // Current depth
    pub current_ip: u64,          // RIP for next frame
    pub sp: u64,                  // Stack pointer
    pub bp: u64,                  // Base pointer
    pub tgid: u32,                // Process ID
    pub mapping_count: u32,       // Number of mappings
}
```

### eBPF Maps

#### UNWIND_STATE (profile-bee-ebpf/src/lib.rs)

```rust
#[map(name = "unwind_state")]
pub static UNWIND_STATE: PerCpuArray<DwarfUnwindState> = PerCpuArray::with_max_entries(1, 0);
```

Stores the unwinding state in a per-CPU map, accessible across tail calls.

#### PROG_ARRAY (profile-bee-ebpf/src/lib.rs)

```rust
#[map(name = "prog_array")]
pub static PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);
```

Holds file descriptors of eBPF programs for tail-call dispatch.

### Constants

```rust
pub const FRAMES_PER_TAIL_CALL: usize = 5;
pub const MAX_TAIL_CALLS: usize = 33;
pub const MAX_DWARF_STACK_DEPTH: usize = FRAMES_PER_TAIL_CALL * MAX_TAIL_CALLS; // 165
pub const LEGACY_MAX_DWARF_STACK_DEPTH: usize = 21;
```

### Program Flow

#### 1. Initialization (collect_trace)

```rust
fn collect_trace(ctx: &PerfEventContext) {
    // ... existing code ...

    if dwarf_enabled() {
        dwarf_copy_stack_init(ctx, tgid);
        // Tail call handles the rest
    }
}
```

#### 2. Init Function (dwarf_copy_stack_init)

```rust
fn dwarf_copy_stack_init(ctx: &PerfEventContext, tgid: u32) {
    let regs = ctx.as_ptr() as *const pt_regs;
    let state = UNWIND_STATE.get_ptr_mut(0).unwrap();

    // Initialize state
    state.pointers[0] = regs.rip;
    state.current_ip = regs.rip;
    state.sp = regs.rsp;
    state.bp = regs.rbp;
    state.tgid = tgid;
    state.frame_count = 1;

    // Tail-call into step function
    unsafe { PROG_ARRAY.tail_call(ctx, 0); }
}
```

#### 3. Step Function (dwarf_unwind_step - tail-callable)

```rust
#[perf_event]
fn dwarf_unwind_step(ctx: PerfEventContext) {
    let state = UNWIND_STATE.get_ptr_mut(0).unwrap();
    let proc_info = PROC_INFO.get(&ProcInfoKey { tgid: state.tgid, _pad: 0 }).unwrap();

    // Unwind up to FRAMES_PER_TAIL_CALL frames
    for _ in 0..FRAMES_PER_TAIL_CALL {
        if !dwarf_unwind_one_frame(state, proc_info) {
            // Done unwinding
            return;
        }
    }

    // More frames to unwind - tail-call back into ourselves
    unsafe { PROG_ARRAY.tail_call(&ctx, 0); }
}
```

#### 4. Single Frame Unwind

```rust
fn dwarf_unwind_one_frame(state: &mut DwarfUnwindState, proc_info: &ProcInfo) -> bool {
    // Find mapping containing current_ip
    // Binary search unwind table
    // Compute CFA
    // Read return address
    // Update state (sp, bp, ip, frame_count)
    // Return true if more frames, false if done
}
```

### Userspace Registration

The userspace code must register the step program in the `PROG_ARRAY` after loading:

```rust
pub fn setup_tail_call_unwinding(bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    let step_prog: &Program = bpf.program("dwarf_unwind_step")?;
    let step_fd = step_prog.fd()?;

    let mut prog_array: ProgramArray = bpf.map_mut("prog_array")?.try_into()?;
    prog_array.set(0, step_fd, 0)?;

    Ok(())
}
```

## Current Status

### Phase 1: Infrastructure ✅ (Completed)

- `DwarfUnwindState` structure added
- `UNWIND_STATE` and `PROG_ARRAY` maps added
- Constants updated (`MAX_DWARF_STACK_DEPTH = 165`)
- Legacy implementation preserved (`LEGACY_MAX_DWARF_STACK_DEPTH = 21`)

### Phase 2: Implementation (Pending)

- [ ] Implement `dwarf_copy_stack_init()`
- [ ] Implement `dwarf_unwind_step()` as tail-callable program
- [ ] Uncomment and use `dwarf_unwind_one_frame()`
- [ ] Add `#[perf_event]` attribute to step function
- [ ] Update `collect_trace()` to use init function

### Phase 3: Userspace Integration (Pending)

- [ ] Add `setup_tail_call_unwinding()` to `ebpf.rs`
- [ ] Call registration after eBPF load
- [ ] Add runtime detection of tail-call support
- [ ] Fallback to legacy mode on older kernels

### Phase 4: Testing (Pending)

- [ ] Add test for 50+ frame depth
- [ ] Add test for 100+ frame depth
- [ ] Verify performance (should be similar to legacy)
- [ ] Test on kernels 5.4, 5.10, 5.15, 6.x

## Design Decisions

### Why 5 Frames Per Call?

5 frames keeps each invocation well under the verifier limit while maximizing total depth:
- Each frame requires: mapping lookup (8 iterations) + binary search (16 iterations) + CFA computation
- 5 frames ≈ 5 × (8 + 16 + overhead) ≈ 600-800 instructions
- Well under 4,096 limit with safety margin

### Why Store State in Per-CPU Map?

- eBPF stack is limited (~512 bytes)
- `DwarfUnwindState` is ~8.2 KB (1024 frames × 8 bytes + metadata)
- Per-CPU maps are fast (no locking) and persist across tail calls
- Each CPU gets its own state, no contention

### Signal Frame Handling

Signal frames (`CFA_REG_DEREF_RSP`) work the same in tail-call mode:
- Read RIP/RSP/RBP from `ucontext_t` at fixed offsets
- Continue unwinding from interrupted frame
- No special tail-call handling needed

## Performance Considerations

### Overhead of Tail Calls

- Tail call adds ~20-50 CPU cycles vs direct function call
- For 21-frame stack: 21/5 = 4 tail calls ≈ 80-200 cycles
- Negligible compared to `bpf_probe_read_user` cost (~500 cycles each)

### Memory Usage

- `UNWIND_STATE`: 1 entry × 8.2 KB = 8.2 KB per CPU
- For 128 CPUs: ~1 MB total
- Acceptable for production use

## Compatibility

### Kernel Requirements

- Tail calls: Linux 4.2+ (introduced in commit 04fd61ab36ec)
- Program arrays: Linux 4.2+
- Per-CPU arrays: Linux 3.19+

### Fallback Strategy

```rust
fn dwarf_copy_stack(...) -> ... {
    if tail_call_supported() {
        dwarf_copy_stack_with_tail_calls(...)
    } else {
        dwarf_copy_stack_legacy(...)  // 21-frame limit
    }
}
```

Runtime detection:
```rust
fn tail_call_supported() -> bool {
    // Check kernel version or try to load a test tail-call program
    kernel_version() >= Version::new(4, 2, 0)
}
```

## References

- [opentelemetry-ebpf-profiler native_stack_trace.ebpf.c](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/support/ebpf/native_stack_trace.ebpf.c)
- [eBPF tail calls documentation](https://docs.kernel.org/bpf/prog_cgroup_sockopt.html#tail-calls)
- [BPF verifier documentation](https://docs.kernel.org/bpf/verifier.html)
- [Parca Agent DWARF unwinding](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf/)
- [Elastic blog on profiling without frame pointers](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf)

## Future Enhancements

1. **Adaptive frame count**: Adjust `FRAMES_PER_TAIL_CALL` based on program complexity
2. **Stack truncation marker**: Add sentinel value when hitting 165-frame limit
3. **Metrics**: Track actual tail-call depth distribution
4. **Hybrid mode**: Use FP unwinding for known-FP binaries, DWARF for others
