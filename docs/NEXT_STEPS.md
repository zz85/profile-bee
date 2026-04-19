# Next Steps

Prioritized roadmap for profile-bee, roughly ordered by impact.

## ~~1. Off-CPU Profiling~~ ✅ Done (basic)

Basic off-CPU profiling implemented via `kprobe:finish_task_switch` with per-CPU tracking, min/max block-time filtering, and all output formats. See [docs/off_cpu_profiling.md](off_cpu_profiling.md) for the full design, comparison with the OTel/Polar Signals approach, and planned improvements (sched_switch tracepoint, probabilistic sampling, DWARF unwinding for off-CPU stacks, simultaneous on+off CPU mode).

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

Self-profiling shows the DWARF subsystem accounts for ~70% of probee's active CPU time. The top bottlenecks are per-entry BPF map syscalls (24%), ELF read page fault storms (25%), and `/proc/kallsyms` iteration on BPF-heavy systems (10%). See [docs/dwarf_performance.md](dwarf_performance.md) for the full analysis and improvement plan.

## 9. Interpreted / JIT Stack Support

Support perf map files (`/tmp/perf-<pid>.map`) that runtimes like Java, Node.js, and Python emit. Well-established convention that would broaden the user base significantly.

## 10. Output Format Expansion

### 10a. Pprof Output ✅ Done

Google's pprof protobuf format — the standard interchange format for profiling data. Gzip-compressed `.pb.gz` files compatible with `go tool pprof`, Grafana/Pyroscope, Speedscope, Datadog, and Polar Signals/Parca. Implemented via `--pprof <path>` flag.

### 10b. AWS CodeGuru Profiler JSON Format ✅ Done

CodeGuru's `PostAgentProfile` API accepts `application/json` with a recursive call-tree structure. Schema referenced from the open-source [Python agent](https://github.com/aws/amazon-codeguru-profiler-python-agent) and [AWS thread-state docs](https://docs.aws.amazon.com/codeguru/latest/profiler-ug/working-with-visualizations-thread-states.html). Key design points:

- Call tree stored as nested JSON objects (`children` is a map, not array)
- Only **self-time counts at leaf nodes** with proper thread-state counter types (`RUNNABLE` for on-CPU, `WAITING` for off-CPU)
- Agent metadata: sample weights, duration, fleet info (`fleetInstanceId`, `hostType`), agent version
- No Ion dependency needed — plain `serde_json`
- See `docs/codeguru_format.md` for full schema reference

Implemented via:
- `--codeguru <path>` flag for local file output (`src/codeguru.rs`)
- `--codeguru-upload --profiling-group <name>` for direct upload to CodeGuru via `PostAgentProfile` API (`src/codeguru_upload.rs`). Uses the AWS SDK credential chain; requires `sudo -E` to preserve credentials.

### 10c. OTLP Profiles Export ✅ Done

Export profiles in OpenTelemetry Profiles v1development format via gRPC to OTLP-compatible backends. See [docs/otlp_export.md](otlp_export.md) for the full guide.

**Implemented:**
- Pre-symbolized mode (function names in proto, `"go"` frame type) — works with Pyroscope, OTel Collector
- Native address mode (real ELF VAs, `"native"` frame type, htlhash build IDs) — works with devfiler via symbol server
- `--flush-interval` for headless continuous profiling
- `--symbol-server` for automatic binary upload to external symbol server
- `--symbol-server-listen` for embedded symbol server (single-process mode)
- Standalone `symbol-server` crate and shared `profile-bee-symbols` library
- Mode auto-selected: native when symbol server is configured + collect_raw() available, pre-symbolized otherwise

**Future enhancements:**
- **Pre-extracted symbol upload:** When profile-bee is already doing symbolization (blazesym), it could extract symbols and POST them in symbfile format directly to the symbol server. This avoids the server re-parsing the binary — useful for local-testing workflows where profile-bee already has the binary in memory.
- **DWARF enrichment in symbol-server:** Add addr2line/gimli-based source file + line number extraction to the symbfile writer for richer devfiler display.
- **Parca/debuginfod compatibility:** Support the debuginfod protocol for Parca-based backends.
- **GNU Build ID fallback:** The pre-symbolized path currently uses a synthetic FNV hash as the build ID. Could use GNU Build ID (from `.note.gnu.build-id`) instead when available, which is cheaper to read and more standard for non-devfiler receivers.

### 10d. JFR (Java Flight Recorder) Format — Planned

Binary format used by JDK Mission Control, IntelliJ, Grafana/Pyroscope, and Datadog Continuous Profiling. Despite the Java name, async-profiler proves it works for native C/C++/kernel stacks (library name as "Class", symbol as "Method", FrameType=C++/Kernel).

**Effort estimate:** ~1000-1200 lines of Rust, 1-2 weeks. No formal spec document exists — implementation references async-profiler's `flightRecorder.cpp` (~1500 lines C++) and OpenJDK's `ChunkHeader.java` as the primary sources. No Rust JFR writer exists; `jfrs` crate is reader-only.

**Key components needed:**
1. LEB128/varint encoding (~50 lines)
2. Chunk header (68-byte big-endian fixed header, patched at end) (~80 lines)
3. Metadata event writer — self-describing type schema tree (~300 lines, hardest part)
4. Constant pool writer — threads, stack traces, methods, classes, symbols (~200 lines)
5. ExecutionSample event writer (~50 lines)
6. Orchestration — collect data, assign IDs, write chunk (~100 lines)

**Native frame representation (from async-profiler):**
- `Class.name` = shared library name (e.g., `libc.so.6`)
- `Method.name` = symbol name (e.g., `__GI___libc_read`)
- `FrameType` = `"C++"`, `"Native"`, or `"Kernel"`

**Testing:** Must validate against `jfr print` (JDK CLI tool) and JDK Mission Control.

## 11. S3 / Remote Upload — Planned

Upload profiling data (pprof, CodeGuru JSON, or JFR) to S3 or HTTP endpoints for continuous profiling pipelines.

Note: Direct CodeGuru upload is already implemented via `--codeguru-upload`. S3 upload would be for custom pipelines or non-CodeGuru consumers (e.g., Pyroscope, Grafana Cloud Profiles).

## 12. TUI: PTY/VTE Terminal Emulation for Process Output — Planned

The current TUI process output capture (Issue #57) uses piped stdio, which means the
child process detects it's not connected to a terminal (`isatty()` returns false). Programs
may disable colors, switch to full buffering, or hide interactive features.

A future enhancement would embed a terminal emulator inside the TUI output panel:

- Allocate a PTY pair (`openpty`); child gets the slave end and thinks it has a real terminal
- Parse the master end through a VTE state machine (`vte` crate) into a virtual cell grid
- Render the virtual screen into the ratatui frame (preserving colors, cursor position, etc.)
- Forward mouse events from the output area back to the PTY master
- Forward SIGWINCH so the child knows the "terminal" size

This would enable full-fidelity output rendering (progress bars, colors, interactive prompts)
similar to what zellij/tmux provide. Dependencies: `vte`, `pty-process` or raw `openpty`/`forkpty`.
Complexity is significantly higher than the pipe-based approach (terminal lifecycle, signal
forwarding, input multiplexing, job control edge cases).
