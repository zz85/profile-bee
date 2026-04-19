# Changelog

## v0.3.13

### New Features

- **OTLP Profiles export** (`--otlp-endpoint`) — stream profiling data via gRPC in OpenTelemetry Profiles v1development format to Pyroscope, devfiler, OTel Collector, or any OTLP-compatible backend. Proto compilation uses `protox` (pure-Rust, no `protoc` binary needed) with `tonic` for gRPC transport.
- **Two export modes, auto-selected** — pre-symbolized mode sends function names directly (works with Pyroscope out of the box); native-address mode sends real ELF virtual addresses with `/proc/pid/maps` mappings and htlhash build IDs (for devfiler's server-side symbolization). Mode is chosen automatically based on whether a symbol server is configured.
- **Symbol server** (`symbol-server` crate) — standalone daemon that accepts ELF binary uploads from profile-bee, extracts symbols from `.symtab`/`.dynsym` with Rust/C++ demangling, and serves devfiler-compatible symbfiles (zstd-compressed protobuf with delta-encoded address ranges). Devfiler auto-fetches symbols via `--symb-endpoint`.
- **Embedded symbol server** (`--symbol-server-listen <port>`) — runs the symbol server inside the profile-bee process for single-binary workflows. No separate daemon needed. Feature-gated behind `symbol-server` (default on).
- **Automatic binary upload** (`--symbol-server <url>`) — discovers ELF binaries from `/proc/*/maps` for all running processes and uploads them to the symbol server in the background. Deduplicates by path, verifies ELF magic, with connect/request timeouts.
- **Continuous profiling mode** (`--flush-interval <ms>`) — run indefinitely (or until `--time` expires), uploading a batch of samples every N milliseconds. Headless alternative to `--serve` without HTTP server overhead.
- **Shared `profile-bee-symbols` crate** — htlhash FileId computation (SHA-256 of head+tail+length, compatible with devfiler/Elastic) and ELF symbol extraction, shared between profile-bee and symbol-server.

### Improvements

- **OTLP works in all modes** — `--tui`, `--serve`, `--tui --serve` (combined), batch, and `--flush-interval` all support OTLP export via `--otlp-endpoint`.
- **Real instruction pointer addresses** — `StackFrameInfo.address` is now populated with raw IPs after blazesym symbolization, enabling the native-address OTLP path.
- **ELF VA normalization** — runtime virtual addresses are normalized to ELF VA space (`runtime_addr - mapping_start + file_offset`) so devfiler's SymTree interval lookups resolve correctly.
- **Non-fatal OTLP errors** — transport failures log a warning and reset the gRPC client for automatic reconnection on the next flush cycle. Profiling and local output sinks continue uninterrupted.
- **10-second timeouts** on all OTLP `connect()` and `export()` calls via `tokio::time::timeout` to prevent indefinite blocking.
- **Atomic symbfile writes** — symbol-server uses temp+rename for ranges and metadata.json to prevent partial entries.
- **Blocking work off async workers** — both symbol-server and embedded server use `tokio::task::spawn_blocking` for ELF parsing and symbfile generation.
- **Readiness signal for embedded server** — `spawn_embedded_server` returns a `oneshot::Receiver<()>` that fires after `TcpListener::bind` succeeds, eliminating the startup race.
- **C++ demangling priority** — C++ Itanium demangling is attempted before Rust to prevent `_ZN...` names from being mis-parsed by `rustc_demangle`.
- **Feature independence** — `opt.tui` is cfg-gated in the OTLP block so `otlp` compiles without `tui` feature.

### New CLI Flags

| Flag | Description |
|------|-------------|
| `--otlp-endpoint <host:port>` | OTLP gRPC endpoint for profile export |
| `--otlp-insecure` | Use plaintext gRPC (default: true) |
| `--otlp-service-name <name>` | Service name for resource attributes |
| `--symbol-server <url>` | External symbol server URL for binary upload |
| `--symbol-server-listen <port>` | Embedded symbol server port |
| `--flush-interval <ms>` | Continuous profiling flush interval |

### Documentation

- New `docs/otlp_export.md` — full guide covering architecture, CLI flags, Pyroscope/devfiler setup, symbol server endpoints, and symbolization approaches across the ecosystem (devfiler, Pyroscope, Parca, OTel Collector, Grafana Alloy).
- Updated `docs/NEXT_STEPS.md` with OTLP export status and future enhancement roadmap.
- Updated README with OTLP and symbol-server feature descriptions and quick-start examples.

## v0.3.12

### New Features

- **Node.js profiling support** — profile Node.js applications with JavaScript function names resolved via V8's perf-map files. When spawning via `probee -- node app.js`, automatically injects `NODE_OPTIONS` with `--perf-basic-prof` (writes `/tmp/perf-<pid>.map`) and `--interpreted-frames-native-stack` (enables frame pointers in interpreter frames). blazesym's built-in perf-map support reads these files during symbolization.
- **V8 symbol formatting** — V8 perf-map symbols like `LazyCompile:*processData /app/server.js:42:5` are formatted into clean display names (`processData (server.js:42)`) for readable flamegraphs. Handles all V8 symbol types: optimized (`*`), interpreted (`~`), builtins, stubs, regex, and eval.
- **FP-only zones for JIT code** — anonymous executable memory mappings (V8 JIT, JVM HotSpot, etc.) are registered in the eBPF LPM trie with `shard_id=SHARD_NONE` so the unwinder uses frame-pointer walking through JIT regions while preserving DWARF unwinding for surrounding native frames. Enables correct mixed native/JIT stack traces with `--dwarf`.
- **Node.js missing perf-map warning** — when profiling an existing Node.js process via `--pid` without a perf-map file, prints a warning with instructions to restart with `--perf-basic-prof` or use `probee -- node <script>` for automatic injection.

### Improvements

- **E2E test infrastructure** — `run_test` now recognizes exit code 77 as SKIP (autotools convention) with distinct yellow status output, so missing optional dependencies (e.g. `node`) are reported accurately instead of silently passing.
- **Node.js E2E tests** — three new test cases: sample collection, JS function name resolution, and DWARF mode with FP-only JIT zones. Tests skip gracefully when `node` is not installed.

## v0.3.11

### New Features

- **Unified output flag** (`-o` / `--output`) — replace per-format flags (`--svg`, `--html`, `--json`, `--collapse`, `--pprof`, `--codeguru`) with a single repeatable `-o <file>` flag. Format is inferred from file extension: `.svg`, `.html`, `.json`, `.folded`, `.pb.gz`, `.pprof`, `.codeguru.json`. Multiple outputs at once: `-o flame.svg -o profile.pb.gz`. (#88)
- **Unified event/probe flag** (`-e` / `--event`) — replace `--kprobe`, `--uprobe`, `--tracepoint` with a single `-e <spec>` flag using prefix syntax: `kprobe:fn`, `uprobe:spec`, `uretprobe:spec`, `tracepoint:cat:name` (short forms: `k:`, `u:`, `ur:`, `t:`, `tp:`). Bare names default to uprobe. (#25)
- **Output format inference** — `infer_output_format()` maps file extensions to output sinks. Compound extensions like `.codeguru.json` and `.cg.json` are supported. Unknown extensions produce a clear error message listing valid options.
- **Event prefix parsing** — `parse_event_prefix()` in `probe_spec.rs` with doc-tests covering all 9 prefix variants. `EventKind` enum exported from the library for programmatic use.

### Improvements

- **Legacy flags preserved** — `--svg`, `--html`, `--json`, `--collapse`, `--pprof`, `--codeguru`, `--kprobe`, `--uprobe`, `--tracepoint` continue to work (hidden from `--help` but documented in the examples section). 100% backward compatible.
- **Simplified help output** — `--help` now shows `-o` and `-e` as the primary interface, with legacy flags mentioned in the examples footer. Usage line updated to `(sudo) probee [OPTIONS] [-o <FILE>...] [-e <EVENT>...] [-- <COMMAND>...]`.
- **`--list-probes` accepts unified prefix** — `--list-probes 'uprobe:pthread_*'` works alongside bare specs.
- **TUI `build_profiler_config` uses event parsing** — both batch and TUI paths share the same `parse_event_specs()` code path.
- **README and docs updated** — all ~37 example commands converted to new syntax.

## v0.3.10

### New Features

- **eBPF process lifecycle tracking** — new `sched_process_exec` and broadened `sched_process_exit` tracepoints detect process exec and exit events in the kernel. Events are delivered to userspace via a dedicated ring buffer. Enabled automatically when DWARF unwinding is active; agents can enable it explicitly via `SessionConfig::track_process_lifecycle`. (#89)
- **`ProcessMetadataCache`** (`process_metadata` module) — lazy, capacity-bounded cache of per-process metadata read from `/proc/[pid]/`. Provides `cmdline`, `cwd`, `environ`, `exe`, and mount namespace inode for any PID seen during profiling. Integrates with lifecycle events for automatic cache invalidation (exec) and eviction (exit). Agents can enrich stack traces with `cache.get_or_load(pid)` and `cache.environ_var(pid, "MY_VAR")`.
- **`ProcessEvent` shared type** — unified 16-byte `#[repr(C)]` struct in `profile-bee-common` carrying event type, PID, and timestamp for both exec and exit events.

### Improvements

- **Thread exit filtering in eBPF** — `handle_process_exit()` and `handle_process_exec()` return early when `tid != tgid`, avoiding thousands of spurious ring buffer events on thread-heavy workloads (Java, Go runtime threads).
- **Deferred metadata eviction** — exit events are queued in `pending_exit_pids` and evicted at the start of the next `drain_events()` cycle, covering the async delivery race where StackInfo and exit event for the same PID arrive in different drain windows.
- **Trace count flushed on exec** — when a PID execs, its accumulated `trace_count` entries are flushed before cache invalidation, so the old binary's samples are not lost.
- **PID reuse detection** — `ProcessMetadataCache::get_or_load()` validates cached entries against `/proc/[pid]/stat` starttime; mismatches trigger automatic reload.
- **DWARF table reload on exec** — exec events are forwarded to the DWARF thread, which reloads unwind tables for the new binary.
- **Debug impl redacts secrets** — `ProcessMetadata`'s `Debug` output shows entry counts instead of raw `environ`/`cmdline` values, preventing accidental secret leakage in logs.
- **Robust `/proc` stat handling** — `ProcessMetadata::load()` returns `None` when `/proc/[pid]/stat` is unreadable (process already exited), preventing `start_time = 0` entries from bypassing PID-reuse detection. `get_or_load()` removes stale entries when the process disappears between cache hit and validation.

## v0.3.9

### New Features

- **Group by process** (`--group-by-process`) — prefix each stack with `process_name (pid)` to split flamegraphs into per-process sub-trees. Works with all output formats. (#86)
- **TUI process list view** — new Processes tab (via Tab key) showing all processes sorted by sample count with CPU% bar visualization. Enter to zoom into a process.
- **TUI expandable call tree** — press `t` to toggle tree mode in Top or Processes views. Shows a perf report-style expandable call tree with overhead% and self%, expand/collapse with Enter/h. Expanded state persists across live data refreshes.
- **TUI PID mode toggle** — press `p` to toggle PID mode on the fly, splitting the flamegraph by process without restarting.
- **CodeGuru idle stack classification** — idle/swapper stacks (pid == 0) now use the `IDLE` counter type, which CodeGuru excludes from CPU and Latency views.

## v0.3.8

### New Features

- **Library API** (`ProfilingSession`) — profile-bee can now be used as a Rust library, not just a CLI binary. `ProfilingSession::new(config)` consolidates the entire eBPF + DWARF setup sequence into a single call. Supports batch and streaming modes via `OutputSink` trait. (#48)
- **pprof output** (`--pprof`) — gzip-compressed protobuf format compatible with `go tool pprof`, Grafana/Pyroscope, Speedscope, Datadog, and Polar Signals/Parca.
- **AWS CodeGuru Profiler JSON** (`--codeguru`) — recursive call-tree format with proper thread-state counter types (`RUNNABLE` for on-CPU, `WAITING` for off-CPU). Uploadable via AWS CLI.
- **Direct CodeGuru upload** (`--codeguru-upload`) — uploads profiles directly to CodeGuru's `PostAgentProfile` API using the AWS SDK. Uses the standard credential chain. Included by default (behind `aws` feature flag).
- **CodeGuru format documentation** — `docs/codeguru_format.md` with full schema reference covering all 7 counter types, metadata fields, and CodeGuru console visualization views.

### Improvements

- **Library refactor** — moved ~660 lines of orchestration from the binary into reusable library modules: `session.rs`, `event_loop.rs`, `pipeline.rs`. Binary reduced from 1753 to ~1100 lines.
- **println/eprintln replaced with tracing** in all library code (spawn.rs, ebpf.rs, html.rs, trace_handler.rs).
- **Parameterized web server port** — `html::start_server_on_port(port)` for library consumers.
- **Process-exit monitoring added to TUI modes** — `--pid` auto-stop and DWARF cleanup now work in `--tui` and `--tui --serve` modes (was missing).
- **Ring buffer tasks exit on receiver drop** — prevents background tasks from running indefinitely after profiling completes.
- **Ctrl-C handler logs errors** instead of treating signal setup failure as Ctrl-C received.
- **Size checks on ring buffer reads** — defensive guard before unsafe pointer casts.
- **`syscall_name_to_nr` gated to x86_64** — `#[cfg(target_arch = "x86_64")]` with stubs for other architectures.
- **Sink duration accuracy** — pprof and CodeGuru sinks now receive actual profiling duration via `set_actual_duration_ms` instead of the requested timeout.
- **TUI warns about ignored output flags** — `--tui --pprof` etc. now prints a warning instead of silently dropping the output.

### Bug Fixes

- Fix misleading "DWARF-unwound stack" log message appearing without `--dwarf` (the stacked_pointers map is shared by FP and DWARF paths).
- Fix `CodeGuruUploadSink` panic: "Cannot start a runtime from within a runtime" — replaced `block_on()` with `spawn()` + channel bridge.
- Fix `event_loop.rs` batch-mode channel disconnect not setting `stopped = true`.
- Fix `session.rs` `group_by_cpu` hardcoded to `false` — now wired through `SessionConfig`.

## v0.3.5

### Improvements

- **Replace PROC_INFO HashMap with EXEC_MAPPINGS LPM trie** — O(log n) address-to-mapping lookups replace O(n) linear scan, removing the per-process 8-mapping limit. Supports up to 200K total LPM entries across all processes.
- **Correct ExecMappingKey alignment** — changed from `#[repr(C, packed)]` to `#[repr(C)]` with explicit padding to avoid unaligned 64-bit access in eBPF and userspace.
- **Prevent overflow in `summarize_address_range`** — use u128 arithmetic so range-length computation cannot wrap when address ranges approach `u64::MAX`.
- **DWARF mapping refresh rebuilds from scratch** — process mappings are recomputed each scan instead of cloning and skipping existing ranges, preventing stale shard/load_bias data when memory ranges are reused.
- **Always propagate exec mapping updates to eBPF** — `send_refresh` is now called after every successful `refresh_process`, not only when new shards are created, ensuring dlopen'd libraries with cached binaries get LPM trie entries (matches lightswitch's approach of unconditionally writing mappings to BPF).
- **Reduce refresh channel overhead** — `send_refresh` now only clones the changed process's mappings instead of all tracked processes.
- **Surface LPM trie insert failures** — replaced silent `let _ = trie.insert(...)` with explicit error logging including tgid, mapping range, and block details.
- **Guard against invalid mapping ranges** — added `debug_assert` to catch corrupted begin/end values before LPM trie population.
- **Derive LPM key bit-width from struct size** — replaced magic `128` in `LpmKey::new` calls with `EXEC_MAPPING_KEY_BITS` constant derived from `size_of::<ExecMappingKey>()`.

### Tests

- Added 7 unit tests for `summarize_address_range` edge cases (empty range, single address, power-of-two boundaries, near `u64::MAX`, full address space).

### Documentation

- Updated DWARF design docs to reflect LPM trie architecture (replaces old PROC_INFO references).

## v0.3.2

### New Features

- **Off-CPU profiling** (`--off-cpu`) — trace context switches via `kprobe:finish_task_switch` to find where threads block on I/O, locks, or sleep. Per-CPU tracking with configurable block-time filters (`--min-block-time`, `--max-block-time`). All output formats supported (TUI, SVG, HTML, JSON, collapse, web).
- **TUI mouse support** — click to select frames, double-click to zoom, scroll wheel navigation. Enabled by default (`--no-tui-mouse` to disable).
- **Web UI improvements** — rewritten flamegraph viewer with viewport-sized canvas, live controls, client-side accumulate mode, sort-by-name, bottom-up toggle, pause/refresh, green live indicator. Fixed zoom, Y layout, and ancestor frame visibility.

### Improvements

- **ArrayOfMaps for DWARF shards** — replaced 8 individual `shard_0..shard_7` eBPF Array maps with a single `BPF_MAP_TYPE_ARRAY_OF_MAPS`. Supports up to 64 binaries (was 8) with up to 131K unwind entries each (was 65K). Inner maps created on-demand to reduce idle memory usage.
- **Oversized unwind tables truncated instead of skipped** — large binaries (e.g. glibc) now get partial DWARF coverage instead of none.
- **DWARF refresh and truncation logs moved to debug level** — no longer interfere with TUI mode. Use `RUST_LOG=debug` to see them.
- **Test fixture binaries removed from git** — rebuilt from source via `tests/build_fixtures.sh`. E2E test runner auto-detects missing or stale fixtures.

### Bug Fixes

- Fix HTML output script injection vulnerability — escape user-controlled strings in generated HTML
- Fix HTML file write ordering — defer writes to avoid partial output on error
- Fix HTML replacement order for correct template substitution
- Fix eBPF `get_stackid` type inference with updated aya API (turbofish annotations)
- Fix kernel <5.14 compatibility for ArrayOfMaps — use fixed `max_entries` matching the eBPF template

### Dependencies

- `aya` / `aya-ebpf`: switched to `github.com/zz85/aya` branch `array-of-maps` (adds `BPF_MAP_TYPE_ARRAY_OF_MAPS` support)

### Infrastructure

- E2E test suite expanded to 16 tests (added off-CPU profiling tests)
- Prebuilt eBPF binary updated for `cargo install` compatibility

## v0.3.0 — Initial Public Release

The first release published to crates.io. Install with `cargo install profile-bee` — no nightly Rust required.

### Highlights

- **Interactive TUI flamegraph viewer** — live, real-time flamegraphs directly in your terminal with vim-style navigation, search, zoom, and freeze/unfreeze. Forked and adapted from [flamelens](https://github.com/YS-L/flamelens). Three update modes: reset, accumulate, and decay.
- **DWARF-based stack unwinding in eBPF** — profiles binaries compiled without frame pointers (`-O2`/`-O3`). Parses `.eh_frame` sections into flat unwind tables loaded into eBPF maps for in-kernel stack walking. Supports PIE, shared libraries, vDSO, PLT stubs, and signal trampolines.
- **Smart uprobe/uretprobe targeting** — GDB-style symbol resolution with auto-discovery across loaded ELF binaries. Supports glob (`pthread_*`), regex (`/pattern/`), demangled C++/Rust names, source file:line (DWARF), explicit library prefixes, and multi-attach. Discovery mode (`--list-probes`) to inspect matches without attaching.
- **Raw tracepoint support** — bypasses BPF LSM restrictions on `PERF_EVENT_IOC_SET_BPF`. Multi-tier fallback: syscall-specific raw_tp → task_pt_regs raw_tp → generic raw_tp → perf tracepoint.

### New Features

- **TUI mode** (`--tui`) with real-time flamegraph updates, configurable refresh interval (`--tui-refresh-ms`), and update modes (`--update-mode reset|accumulate|decay`)
- **Combined TUI + web server mode** (`--tui --serve`) for simultaneous terminal and browser access
- **DWARF unwinding** (`--dwarf`) with background thread for detecting `dlopen`-loaded libraries within ~1 second
- **Smart uprobes** (`--uprobe`) with glob, regex, demangled name, and source:line matching
- **Uprobe discovery mode** (`--list-probes`) to search symbols without attaching
- **Raw tracepoint attachment** for kprobe, tracepoint, and syscall events
- **Frame pointer unwinding in eBPF** — custom stack walker using `pt_regs` for deeper stacks than `bpf_get_stackid`
- **Process spawning** (`--cmd`, `-- <command>`) — spawn a process and profile it, auto-terminates when it exits
- **PID exit detection** — profiler automatically stops when `--pid` target process exits
- **Prebuilt eBPF binary** — bundled for `cargo install` without nightly Rust; `build.rs` auto-detects fresh builds for development
- **blazesym integration** — symbol resolution via blazesym library with Rust and C++ demangling
- **Multi-process DWARF** — system-wide profiling with per-process unwind tables and sharded eBPF array maps

### Bug Fixes

- Fix TUI/serve modes stopping after 10s due to `--time` defaulting to 10000ms unconditionally
- Fix `TracePointContext` incorrectly cast to `pt_regs` (tracepoint data struct != registers)
- Fix `sys_exit` tracepoint filtering reading return value instead of syscall NR from `args[1]`
- Fix syscall tracepoint fallback using per-syscall names (`sys_enter_write`) that don't exist as raw tracepoints
- Fix double-counting in headless `process_profiling_data`
- Fix combined mode missing stopping mechanisms (timer, Ctrl-C, child/PID exit)
- Fix shared library unwinding race condition
- Fix signal trampoline unwinding (`__restore_rt`)
- Fix PID filtering and empty stacks with `--cmd`/`--`
- Fix spawned processes not terminated on profiler exit
- Fix timing issue: load DWARF tables before setting `TARGET_PID`
- Fix BPF verifier rejection with DWARF unwinding constants

### Breaking Changes

- **Binary names changed**: `profile-bee` → `probee` (primary) and `pbee` (short alias)
- **`--dwarf` now defaults to `false`** (frame pointer unwinding is the default for stability/performance)
- **`--time` behavior changed in TUI/serve modes**: defaults to 0 (unlimited) instead of 10000ms. CLI mode retains the 10s default.

### Performance

- Compact `UnwindEntry` from 32 → 12 bytes (u32 PC, deduplicated consecutive entries)
- Sharded array maps for unwind tables (replaced single HashMap)
- Build-ID based caching for unwind table lookups
- Inode/metadata-based cache keys instead of reading full binaries
- BPF-based stack aggregation to reduce kernel ↔ userspace transfers

### Infrastructure

- `cargo install profile-bee` works on stable Rust (prebuilt eBPF binary bundled)
- TUI feature enabled by default (`--no-default-features` to exclude)
- Crate metadata added for crates.io publishing (license, description, repository)
- GitHub Actions CI workflow for Rust packages and E2E tests
- E2E test framework (`tests/run_e2e.sh`) with 14 test cases covering FP, DWARF, deep stacks, shared libraries, PIE, and Rust binaries
- Test fixtures: C binaries in 6 variants (FP/no-FP × O0/O2), Rust binary, shared library, PIE, signal handler

### Platform Support

- Linux x86_64
- DWARF unwinding: x86_64 only (ARM support planned)
- Kernel >= 4.15 for basic profiling, >= 5.15 for raw tracepoint with task_pt_regs
