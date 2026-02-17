# Off-CPU Profiling

Off-CPU profiling measures time threads spend **blocked** — waiting on I/O, locks, timers, futexes, etc. It complements on-CPU sampling by showing *why* a process isn't making progress rather than *what* it's doing when it runs.

Reference: [Brendan Gregg's Off-CPU Analysis](https://www.brendangregg.com/offcpuanalysis.html)

## Current Implementation

### How It Works

A single `kprobe` on the kernel's `finish_task_switch` function fires every time a context switch completes (i.e., when a task is placed back onto a CPU). The probe:

1. Looks up the **previous PID** on this CPU via a `LAST_PID_ON_CPU` per-CPU Array map.
2. Records the **current PID** as the new occupant of the CPU.
3. Looks up the previous PID's **off-CPU start time** from an `OFF_CPU_START` HashMap.
4. Computes the **blocked duration** in microseconds.
5. If the duration passes the min/max block-time filter, captures the stack via `bpf_get_stackid` and frame pointer walking, then writes it to the existing `COUNTS` map and `RING_BUF_STACKS`.

The kprobe tries `finish_task_switch` first, falling back to `finish_task_switch.isra.0` for kernels where GCC renames the symbol.

### CLI Usage

```bash
# Basic off-CPU profiling (5 seconds, SVG output)
sudo probee --off-cpu --time 5000 --svg offcpu.svg

# Filter: only blocks longer than 1ms
sudo probee --off-cpu --min-block-time 1000 --time 5000 --tui

# Filter: only blocks between 1ms and 1s
sudo probee --off-cpu --min-block-time 1000 --max-block-time 1000000 --time 5000

# Profile a specific command
sudo probee --off-cpu -- sleep 5
```

`--off-cpu` is currently **mutually exclusive** with `--kprobe`, `--uprobe`, and `--tracepoint`.

### eBPF Maps (off-CPU specific)

| Map | Type | Purpose |
|-----|------|---------|
| `OFF_CPU_START` | HashMap<u32, u64> | PID → timestamp (ns) when task left CPU |
| `LAST_PID_ON_CPU` | Array<u32> | Per-CPU slot tracking which PID was last running |

### Output Semantics

In off-CPU mode the values in `COUNTS` represent **microseconds of blocked time**, not sample counts. The SVG/HTML flamegraph title is set to "Off-CPU Time Flamegraph" and the unit label is "us" (microseconds). Flamegraph tools (inferno, d3-flamegraph) are unit-agnostic so this works without modification.

## Comparison with Polar Signals / OTel eBPF Profiler

The [OTel eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) (maintained by Polar Signals) implemented off-CPU profiling via [design doc 00001](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/design-docs/00001-off-cpu-profiling) and [PR #196](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/196). Their approach differs in several key areas:

### Hook Strategy

| | OTel Profiler | profile-bee |
|---|---|---|
| Entry hook (task leaves CPU) | `tracepoint:sched:sched_switch` | None (inferred via per-CPU array) |
| Exit hook (task returns to CPU) | `kprobe:finish_task_switch.isra.0` | `kprobe:finish_task_switch` (+ `.isra.0` fallback) |
| # of attach points | 2 | 1 |

They use `sched_switch` (a stable kernel tracepoint) to record the previous task's PID and timestamp, then `finish_task_switch` (kprobe) to compute duration and unwind the stack. We use a single kprobe and infer the previous task from a per-CPU array.

**Their tracepoint approach is more robust**: `sched_switch` is a stable ABI that also exposes `prev_state`, enabling filtering by task state (e.g., `TASK_UNINTERRUPTIBLE` only for involuntary waits). Our per-CPU inference avoids the two-hook complexity but cannot inspect task state.

### Overhead Control

| | OTel Profiler | profile-bee |
|---|---|---|
| Strategy | Probabilistic sampling (N/1000 events) | Capture all events, filter by duration |
| Config | `--off-cpu-threshold N` | `--min-block-time` / `--max-block-time` (microseconds) |

They randomly drop most context-switch events at the BPF level (e.g., keep 3%), capping overhead regardless of scheduling frequency. We process every event but discard those outside the block-time window.

**Their sampling approach is safer for production** — on a system doing 100K context switches/second, our kprobe fires on every single one. Time-based filtering still does all the map lookups before deciding to discard.

### Stack Unwinding

| | OTel Profiler | profile-bee |
|---|---|---|
| Method | Full DWARF unwinding via tail calls | `bpf_get_stackid` + frame pointer walking |
| Language support | Polyglot (Go, Python, Java, etc.) | Native code with frame pointers |

They reuse their existing DWARF-based tail-call unwinding infrastructure for off-CPU stacks, giving the same stack quality as on-CPU profiles. We use the simpler `bpf_get_stackid` path — this works but produces lower-quality stacks for code compiled without frame pointers.

### Simultaneous On+Off CPU

They run both modes concurrently: `perf_event` samples on-CPU while `tracepoint+kprobe` captures off-CPU. Our `--off-cpu` is mutually exclusive with the default profiler.

### Analysis / Filtering

Polar Signals added **stack content filters** ("not contains") and **language-specific presets** (Go runtime, Tokio) in their UI to suppress expected off-CPU noise like `runtime.usleep`, `runtime.futex`, etc. We have no stack-content filtering beyond the block-time thresholds.

## Comparison with BCC offcputime

[BCC's `offcputime`](https://github.com/iovisor/bcc/blob/master/tools/offcputime.py) by Brendan Gregg is the classic reference implementation. It uses a single BPF C function attached to `kprobe:finish_task_switch` (with regex fallback for `.isra.N` variants), same as us. The key differences are in how it accesses kernel data and how it aggregates results.

### Kernel Struct Access vs. Per-CPU Inference

BCC's BPF program receives `struct task_struct *prev` as the kprobe argument and dereferences it directly:

```c
// BCC — reads prev->pid, prev->tgid, prev->state from the kprobe arg
int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    // also: prev->__state for filtering
}
```

This is possible because BCC compiles C against kernel headers at runtime. We avoid kernel struct access entirely (no header dependency, no version-specific field offsets) by using a `LAST_PID_ON_CPU` per-CPU Array to infer the previous task. The tradeoff is that we **cannot read `prev->state`**, which blocks task-state filtering.

### Single-Function Design

BCC does both phases (record sleep time for `prev`, compute wake duration for current) in a single BPF function. The function:

1. Records `bpf_ktime_get_ns()` for `prev->pid` (the task leaving the CPU).
2. Looks up the current task's previously recorded start time.
3. Computes the delta, applies min/max filters, captures stacks, increments the count.

Our implementation splits this across two conceptual phases using two maps (`LAST_PID_ON_CPU` + `OFF_CPU_START`), achieving the same result without reading the kprobe argument.

### Pure Kernel-Side Aggregation

| | BCC offcputime | profile-bee |
|---|---|---|
| Aggregation location | Entirely in-kernel (`BPF_HASH`) | In-kernel `COUNTS` + per-event ring buffer to userspace |
| When data reaches userspace | Once, at exit (batch read) | Streaming via `RING_BUF_STACKS` |
| Per-event userspace cost | Zero | Ring buffer submit + poll |

BCC never sends per-event data to userspace. The `counts` hash map accumulates microseconds per unique `{pid, tgid, user_stack_id, kernel_stack_id, comm}` key entirely in-kernel. Userspace reads the map once at program exit. This is **very low overhead**, especially on high-frequency scheduling workloads.

We submit every qualifying event through the ring buffer for real-time processing. This enables streaming/TUI/web-server modes but has higher per-event cost. A future **batch mode** that skips the ring buffer and reads `COUNTS` at the end (like BCC) would be a good addition for non-interactive use cases.

### Filtering and Targeting

| Feature | BCC offcputime | profile-bee |
|---|---|---|
| Min block time | `-m` (default 1 us) | `--min-block-time` (default 0) |
| Max block time | `-M` (default U64_MAX) | `--max-block-time` (default 0 = unlimited) |
| PID filter | `-p` (comma-separated list) | `--pid` (single PID) |
| TID filter | `-t` (comma-separated list) | No |
| Task state | `--state` bitmask (e.g., 2 = `TASK_UNINTERRUPTIBLE`) | No |
| User/kernel threads | `-u` / `-k` (via `prev->flags & PF_KTHREAD`) | No |
| User/kernel stacks | `-U` / `-K` (skip capturing one side) | No (always captures both) |
| Stack storage size | `--stack-storage-size` (default 16384) | Fixed |

BCC has significantly more filtering options. The `--state` filter is particularly valuable: `--state 2` captures only `TASK_UNINTERRUPTIBLE` waits (disk I/O, locks, page faults), ignoring voluntary sleeps — this is the most useful filter for latency debugging.

### Output

| | BCC offcputime | profile-bee |
|---|---|---|
| Formats | Multi-line stack dump (default), folded (`-f`) | Collapse, SVG, HTML, JSON, TUI, web server |
| Symbolization | BCC built-in (per-tgid user, ksym kernel) | blazesym |
| Symbol offsets | `-s` flag | No |
| Real-time display | No (batch at end) | Yes (TUI, web server) |
| Direct flamegraph | No (pipe to `flamegraph.pl`) | Yes (built-in SVG/HTML) |

We have much richer output. BCC's folded output is typically piped to `flamegraph.pl` as a separate step; we generate flamegraphs directly.

### Summary

BCC offcputime is more mature in **data collection** (direct kernel struct access, task-state filtering, pure kernel aggregation, multi-PID/TID targeting). profile-bee is stronger in **output and usability** (single binary, no dependencies, built-in flamegraphs, real-time TUI, web server). The main gaps to close on the collection side are task-state filtering, kernel-only aggregation batch mode, and multi-PID targeting.

## Future Improvements

Roughly ordered by impact. These bring our implementation closer to the OTel/Polar Signals and BCC approaches and address known limitations.

### 1. Add `sched_switch` Tracepoint as Entry Hook

Replace the per-CPU array inference with a proper `tracepoint:sched:sched_switch` handler that reads `prev->pid` and `prev->state` directly from the tracepoint args. Benefits:

- **Task state filtering**: e.g., `--state 2` (like BCC) to only capture `TASK_UNINTERRUPTIBLE` waits (I/O, locks) and ignore voluntary sleeps. This is the single most impactful filtering improvement — both BCC and OTel support this.
- **Stability**: tracepoints are stable kernel ABI; `finish_task_switch` symbol names vary across kernels.
- **Thread type filtering**: tracepoint args also expose task flags, enabling `--user-threads-only` / `--kernel-threads-only` (like BCC's `-u` / `-k`).
- Note: requires coordinating two BPF programs via a shared map (same pattern OTel uses).

### 2. Add Probabilistic Sampling

Add `--off-cpu-threshold N` (sample N out of every 1000 context switches). Implement as a simple `bpf_get_prandom_u32() % 1000 < threshold` check at the top of the sched_switch handler. Critical for production safety on high-frequency scheduling workloads (OTel uses this approach).

### 3. Add Kernel-Only Aggregation Batch Mode

BCC offcputime achieves very low overhead by aggregating entirely in-kernel and only reading the `counts` map once at exit. Add a `--batch` mode (or make it the default for non-interactive outputs like `--collapse`, `--svg`) that skips the ring buffer and reads `COUNTS` at the end of the profiling duration. The ring buffer path would remain for real-time modes (`--tui`, `--serve`).

### 4. Wire Up DWARF Unwinding for Off-CPU Stacks

The off-CPU kprobe currently uses `bpf_get_stackid` for user stacks (same as BCC). To get the same quality as on-CPU profiles, we need to call into the existing DWARF tail-call unwinding path. Challenge: tail calls require matching BPF program types, so the kprobe can't directly tail-call into `perf_event` programs. Options:

- Use a `raw_tracepoint` on `sched_switch` instead (raw tracepoints may allow tail calls within the same type).
- Duplicate the DWARF unwinding programs as kprobe-type variants.
- Use the legacy inline DWARF path (21 frames max) as a pragmatic middle ground.

### 5. Enable Simultaneous On+Off CPU Mode

Allow `--off-cpu` alongside the default perf_event profiler. Both write to the same `COUNTS` map but with different semantics (samples vs. microseconds). Userspace would need to distinguish the two streams — options include a flag bit in `StackInfo` or separate maps.

### 6. Stack Content Filters and Language Presets

Add `--off-cpu-filter "not contains runtime.usleep"` style filtering, either in BPF (by symbol name matching on known addresses) or more practically in userspace post-processing. Ship presets for common runtimes:

- **Go**: filter `runtime.usleep`, `runtime.futex`, `runtime.notesleep`
- **Rust/Tokio**: filter `tokio::park`, `std::thread::park`
- **Java**: filter JVM internal parking

### 7. Multi-PID and TID Targeting

Support comma-separated PID lists (`--pid 185,175,165`) and TID-level filtering (`--tid`), matching BCC's `-p` and `-t` flags. Also add `--user-stacks-only` / `--kernel-stacks-only` to skip capturing one side of the stack (reduces overhead and noise).

### 8. Hot/Cold Flame Graphs (Combined Visualization)

Generate a single flame graph that shows both on-CPU (hot) and off-CPU (cold) time together, using color to distinguish. Brendan Gregg describes this as ["hot/cold flame graphs"](https://www.brendangregg.com/FlameGraphs/hotcoldflamegraphs.html). Requires simultaneous on+off CPU mode (#5 above).

## References

- [Brendan Gregg — Off-CPU Analysis](https://www.brendangregg.com/offcpuanalysis.html)
- [BCC offcputime](https://github.com/iovisor/bcc/blob/master/tools/offcputime.py) — the classic reference implementation
- [OTel eBPF Profiler — Off-CPU Design Doc](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/design-docs/00001-off-cpu-profiling)
- [OTel eBPF Profiler — Off-CPU Implementation PR](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/196)
- [Polar Signals Blog — Introducing Off-CPU Profiling](https://www.polarsignals.com/blog/posts/2025/07/30/introducing-off-cpu-profiling)
- [Brendan Gregg — Hot/Cold Flame Graphs](https://www.brendangregg.com/FlameGraphs/hotcoldflamegraphs.html)
