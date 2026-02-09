# Next Steps

Prioritized roadmap for profile-bee, roughly ordered by impact.

## 1. Off-CPU Profiling

On-CPU profiling only tells half the story. Off-CPU profiling (via `sched_switch` tracepoints or `finish_task_switch` kprobes) would show where time is spent blocked on I/O, locks, or sleep — making profile-bee a much more complete tool.

## ~~2. System-wide DWARF Unwinding~~ ✅ Done

DWARF unwinding now works system-wide. A background thread loads unwind tables for all profiled processes, with Build-ID caching to avoid redundant parsing of shared libraries.

## ~~3. Dynamic Library Hot-loading (`dlopen` support)~~ ✅ Done

A background thread polls `/proc/[pid]/maps` (~1s interval) to detect newly loaded libraries and incrementally updates the eBPF unwind tables at runtime.

## 4. uprobe / USDT Support

The vendored `cargo-trace` already has uprobe/USDT attachment code in `bpf-probes`. Wiring this into the main binary would enable function-level latency profiling and user-defined static tracepoints.

## 5. ~~Signal Trampoline / VDSO Unwinding~~ ✅ Done

Implemented: vDSO `.eh_frame` parsing from `/proc/[pid]/mem`, `CFA_REG_DEREF_RSP` for signal frames, `CFA_REG_PLT` for PLT stubs. Remaining gap: kernels where the vDSO lacks `.eh_frame` entries for `__restore_rt` may still stop unwinding at signal boundaries.

## 6. PID Nesting / cgroup-based Profiling

Support container-aware profiling — profile all processes in a cgroup or namespace. Important for containerized environments.

## 7. Publish to crates.io

Clean up the public API surface, add documentation, and consider splitting or removing the vendored `cargo-trace` dependency.

## 8. CPU Usage Optimization

`process_profiling_data` blocks the collection loop during symbolization. Moving to an async pipeline where collection and symbolization happen concurrently would reduce overhead at high sampling frequencies.

## 9. Interpreted / JIT Stack Support

Support perf map files (`/tmp/perf-<pid>.map`) that runtimes like Java, Node.js, and Python emit. Well-established convention that would broaden the user base significantly.
