# Changelog

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
