# Profile-Bee Developer Guide

> For AI coding assistants. Read this before making changes.

## What Is This?

An eBPF-based CPU profiler for Linux, written in Rust. Single binary (`probee`), no BCC/libbpf dependencies. Walks stacks in-kernel via frame pointers or DWARF unwind tables, outputs flamegraphs (TUI, SVG, HTML, JSON, web server).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  profile-bee-ebpf (kernel)     profile-bee (userspace)          │
│  ─────────────────────────     ───────────────────────          │
│  perf_event fires              tokio async runtime              │
│    → collect_trace()             ← RingBuf polling              │
│    → FP or DWARF unwinding       → read COUNTS, STACK_TRACES,  │
│    → write to eBPF maps            STACKED_POINTERS maps        │
│    → submit StackInfo via        → symbolize (blazesym/gimli)   │
│      RING_BUF_STACKS            → output flamegraph             │
│                                                                 │
│  profile-bee-common (#![no_std])                                │
│  ────────────────────────────────                               │
│  Shared #[repr(C)] types: StackInfo, FramePointers,             │
│  UnwindEntry, ProcInfo, DwarfUnwindState, constants             │
└─────────────────────────────────────────────────────────────────┘
```

## Crate Layout

| Crate | What | Notes |
|-------|------|-------|
| `profile-bee/` | Userspace binary (`probee`, `pbee`) | CLI, eBPF loader, symbolization, output generation |
| `profile-bee-ebpf/` | eBPF kernel programs | **Separate workspace** — built with `cargo +nightly` for `bpfel-unknown-none` |
| `profile-bee-common/` | Shared `#![no_std]` types | `#[repr(C)]` structs used by both eBPF and userspace |
| `profile-bee-tui/` | Terminal UI (forked from flamelens) | Behind `tui` feature flag (default on) |
| `xtask/` | Build automation | `cargo xtask build-ebpf`, `cargo xtask run` |

## Key Files — Read Order

| # | File | Lines | What |
|---|------|-------|------|
| 1 | `profile-bee-common/src/lib.rs` | ~190 | All shared types and constants (`StackInfo`, `UnwindEntry`, `FramePointers`, `ProcInfo`, `DwarfUnwindState`) |
| 2 | `profile-bee-ebpf/src/main.rs` | ~110 | All eBPF program entry points — thin wrappers calling into `lib.rs` |
| 3 | `profile-bee-ebpf/src/lib.rs` | ~1200 | eBPF core: `collect_trace`, DWARF unwinding, all map definitions |
| 4 | `profile-bee/src/ebpf.rs` | ~500 | `EbpfProfiler` — eBPF loading, program attachment, map setup, DWARF table loading |
| 5 | `profile-bee/src/dwarf_unwind.rs` | ~880 | `DwarfUnwindManager` — `.eh_frame` parsing, unwind table generation, shard management |
| 6 | `profile-bee/src/trace_handler.rs` | ~290 | `TraceHandler` — symbolization (blazesym), stack frame formatting |
| 7 | `profile-bee/bin/profile-bee.rs` | ~1750 | CLI (`Opt` struct via clap), orchestration, all output modes, main loop |
| 8 | `profile-bee/src/probe_spec.rs` | ~780 | `ProbeSpec` / `SymbolPattern` — uprobe spec parsing (glob, regex, demangled, source loc) |
| 9 | `profile-bee/src/probe_resolver.rs` | ~670 | `ProbeResolver` — resolves `ProbeSpec` to concrete `ResolvedProbe` targets via ELF scanning |

## Module Map — Userspace (`profile-bee/`)

```
bin/profile-bee.rs          CLI entry point, Opt (clap), main loop, output writers
src/
  lib.rs                    Re-exports; declares modules
  ebpf.rs                   EbpfProfiler: load/attach eBPF, map I/O, DWARF table loading
  dwarf_unwind.rs           DwarfUnwindManager: .eh_frame → UnwindEntry tables → eBPF shards
  trace_handler.rs          TraceHandler: address → symbol resolution (blazesym), caching
  types.rs                  StackFrameInfo, FrameCount, StackInfoExt trait
  cache.rs                  ProcessCache, AddrCache, PointerStackFramesCache (LRU-style)
  html.rs                   HTML flamegraph output (Stack tree builder)
  spawn.rs                  SpawnProcess: child process lifecycle for --cmd
  probe_spec.rs             ProbeSpec enum: parse uprobe specs (exact/glob/regex/source/demangled)
  probe_resolver.rs         ProbeResolver: spec → ResolvedProbe via ELF .symtab/.dynsym scanning
  legacy/                   Legacy symbol resolution code (addr2line-based, being replaced by blazesym)
```

## Module Map — eBPF (`profile-bee-ebpf/`)

```
src/main.rs                 Entry points: #[perf_event], #[kprobe], #[uprobe], etc.
src/lib.rs                  All implementation + map definitions:
                              collect_trace()              — main sampling path (FP + optional DWARF)
                              collect_trace_stackid_only() — tracepoint path (bpf_get_stackid only)
                              collect_trace_raw_syscall()  — raw_tracepoint sys_enter
                              collect_trace_raw_tp_with_task_regs() — raw TP with bpf_task_pt_regs
                              dwarf_unwind_one_frame()     — single DWARF frame step
                              dwarf_copy_stack_regs()      — legacy inline path (21 frames max)
                              dwarf_try_tail_call()        — tail-call path entry (165 frames max)
                              dwarf_unwind_step_impl()     — tail-call target (5 frames per call)
                              dwarf_finalize_stack()       — write completed stack to maps
                              handle_process_exit()        — PID exit detection
src/pt_regs.rs              pt_regs struct definition for x86_64
```

## Data Flow — One Sample

```
1. Kernel perf_event fires → profile_cpu() [main.rs]
2. → collect_trace() [lib.rs]
   a. Read target_pid, skip_idle filters
   b. Get kernel stack via bpf_get_stackid → stack_traces map
   c. Get user stack:
      - FP mode: walk frame pointer chain via get_frame()
      - DWARF mode: dwarf_try_tail_call() → dwarf_unwind_step_impl() (×33 tail calls)
   d. Build StackInfo { tgid, pid, cpu, kstack_id, ustack_id, ... }
   e. Increment counts map (kernel-side aggregation)
   f. Submit StackInfo to RING_BUF_STACKS
3. Userspace tokio task polls RingBuf
4. → TraceHandler.format_stack_trace()
   a. Read kernel frames from stack_traces map
   b. Read user frames from stacked_pointers map (FP/DWARF) or stack_traces map
   c. Symbolize via blazesym (with AddrCache)
   d. Produce Vec<StackFrameInfo> + count
5. → Output: collapse format → inferno (SVG), or HTML, JSON, TUI, web server
```

## CLI Structure (`Opt` in `bin/profile-bee.rs`)

Key flags — all optional, sensible defaults:

| Flag | Type | Default | What |
|------|------|---------|------|
| `--tui` | bool | false | Interactive terminal flamegraph |
| `--svg <path>` | Option | None | SVG flamegraph output |
| `--html <path>` | Option | None | HTML flamegraph |
| `--json <path>` | Option | None | JSON flamegraph format |
| `--collapse <path>` | Option | None | Stackcollapse format |
| `--serve` | bool | false | Real-time web server (port 8000) |
| `--pid <pid>` | Option | None | Target specific PID |
| `--cmd <cmd>` | Option | None | Profile a command |
| `-- <args>` | Vec | [] | Command with args (alternative to --cmd) |
| `--time <ms>` | Option | None | Profile duration in ms |
| `--frequency <hz>` | u64 | 99 | Sampling frequency |
| `--cpu <id>` | Option | None | Target specific CPU core |
| `--dwarf` | bool | false | Enable DWARF unwinding |
| `--kprobe <fn>` | Option | None | Kernel function probe |
| `--uprobe <spec>` | Vec | [] | Uprobe spec(s) — can repeat |
| `--tracepoint <tp>` | Option | None | Tracepoint (category:name) |
| `--skip-idle` | bool | false | Filter idle stacks |
| `--group-by-cpu` | bool | false | Per-core breakdown |
| `--stream-mode <n>` | u8 | 2 | 0=batch, 1=stream, 2=hybrid |
| `--list-probes <spec>` | Option | None | Discovery mode — list matching symbols |

## eBPF Programs

All in `profile-bee-ebpf/src/main.rs`, implementations in `lib.rs`:

| Program | Macro | Attach Point | Unwinding |
|---------|-------|-------------|-----------|
| `profile_cpu` | `#[perf_event]` | CPU sampling (default) | FP + DWARF tail-call |
| `kprobe_profile` | `#[kprobe]` | Kernel function entry | FP + DWARF legacy (21 frames) |
| `uprobe_profile` | `#[uprobe]` | Userspace function entry | FP + DWARF legacy |
| `uretprobe_profile` | `#[uretprobe]` | Userspace function return | FP + DWARF legacy |
| `tracepoint_profile` | `#[tracepoint]` | Perf tracepoints | `bpf_get_stackid` only |
| `raw_tp_sys_enter` | `#[raw_tracepoint]` | `sys_enter` | FP + DWARF legacy |
| `raw_tp_sys_exit` | `#[raw_tracepoint]` | `sys_exit` | FP + DWARF legacy |
| `raw_tp_generic` | `#[raw_tracepoint]` | Any (userspace picks) | `bpf_get_stackid` only |
| `raw_tp_with_regs` | `#[raw_tracepoint]` | Any (kernel ≥5.15) | FP + DWARF legacy |
| `dwarf_unwind_step` | `#[perf_event]` | Tail-call target only | DWARF (5 frames/call) |
| `tracepoint_process_exit` | `#[tracepoint]` | `sched:sched_process_exit` | N/A |

**Why tail-call only works for `perf_event`:** eBPF tail calls require matching program types. Only `profile_cpu` and `dwarf_unwind_step` are both `perf_event`, so kprobe/uprobe/tracepoint programs fall back to the 21-frame inline DWARF path.

## Shared eBPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `counts` | HashMap | Kernel-side stack sample counting |
| `stacked_pointers` | HashMap | Custom FP/DWARF unwound frame IPs |
| `stack_traces` | StackTrace | Kernel `bpf_get_stackid` stacks |
| `RING_BUF_STACKS` | RingBuf | Notification to userspace |
| `STORAGE` | PerCpuArray | Per-CPU scratch for unwinding |
| `shard_0`..`shard_7` | Array | DWARF unwind tables (per-binary) |
| `proc_info` | HashMap | Per-process exec mappings for DWARF |
| `unwind_state` | PerCpuArray | Per-CPU state for tail-call unwinding |
| `prog_array` | ProgramArray | Tail-call target for `dwarf_unwind_step` |
| `target_pid_map` | Array | PID filter (0 = all) |

## DWARF Unwinding

Two paths:

**Tail-call path (primary, up to 165 frames, `perf_event` only):**
```
collect_trace → dwarf_try_tail_call → PROG_ARRAY.tail_call(0)
  → dwarf_unwind_step_impl (5 frames) → tail_call(0) → ... (up to 33×)
  → dwarf_finalize_stack → writes to STORAGE + COUNTS + RING_BUF
```

**Legacy inline path (fallback, up to 21 frames):**
```
collect_trace → dwarf_copy_stack_regs (flat loop of 21)
```

**Unwind table generation (userspace, `DwarfUnwindManager`):**
1. Read `/proc/[pid]/maps` → find executable mappings
2. Parse `.eh_frame` from each ELF (via `gimli`)
3. Classify CFA rules into compact `UnwindEntry` (12 bytes each)
4. Load into sharded eBPF Array maps (`shard_0`..`shard_7`)
5. Background thread polls for `dlopen`-loaded libraries (~1s)

## Build Commands

```bash
# Build eBPF (requires nightly Rust + bpf-linker)
cargo xtask build-ebpf --release

# Build userspace (uses fresh eBPF build if available, otherwise prebuilt in ebpf-bin/)
cargo build --release

# Build both and run with sudo
cargo xtask run -- --tui

# Build without TUI
cargo build --release --no-default-features
```

The eBPF binary is embedded at compile time via `build.rs`. A prebuilt copy at `profile-bee/ebpf-bin/profile-bee.bpf.o` is used when no fresh build exists (enables `cargo install` on stable Rust).

## Testing

```bash
# Unit/integration tests (no sudo needed)
cargo test --workspace

# E2E tests (requires sudo — eBPF needs CAP_SYS_ADMIN)
bash tests/build_fixtures.sh          # compile C/Rust test binaries
sudo tests/run_e2e.sh --verbose       # ~14 tests: FP, DWARF, deep stacks, shared libs, PIE, Rust

# Run specific e2e tests
sudo tests/run_e2e.sh --filter dwarf
```

**E2E test structure:** `tests/run_e2e.sh` runs `probee --collapse` against fixture binaries in `tests/fixtures/bin/`, then validates output against expected patterns in `tests/output/*.collapse`. Each test checks that expected function names appear in the stack traces.

**CI:** GitHub Actions (`.github/workflows/rust.yml`) runs fmt, clippy, build+test, and e2e tests. The eBPF crate is built separately with `cargo +nightly build -Z build-std=core --target bpfel-unknown-none`.

## How To: Common Tasks

### Add a new CLI flag
1. Add field to `Opt` struct in `bin/profile-bee.rs` (uses `clap` derive)
2. Wire it through in the main function body (same file)

### Add a new output format
1. Add the writer function (see `html.rs` for pattern)
2. Add CLI flag to `Opt` in `bin/profile-bee.rs`
3. Call writer from the output section of `main()`

### Add a new eBPF program type
1. Define entry point in `profile-bee-ebpf/src/main.rs` with appropriate macro
2. Implement (or call shared impl) in `profile-bee-ebpf/src/lib.rs`
3. Load and attach from `setup_ebpf_profiler()` in `profile-bee/src/ebpf.rs`
4. Rebuild eBPF: `cargo xtask build-ebpf --release`

### Add a new shared type between eBPF and userspace
1. Define in `profile-bee-common/src/lib.rs`
2. Must be `#[repr(C)]`, `Copy`, `Clone` with explicit padding
3. No `String`, `Vec`, `HashMap` — it's `#![no_std]`

### Add a new uprobe spec syntax
1. Extend `ProbeSpec` enum in `probe_spec.rs`
2. Update `ProbeSpec::parse()` in the same file
3. Handle the new variant in `ProbeResolver` methods in `probe_resolver.rs`

### Modify DWARF unwinding
- **Userspace table generation:** `DwarfUnwindManager::scan_and_update()` in `dwarf_unwind.rs`
- **eBPF-side unwinding:** `dwarf_unwind_one_frame()` in `profile-bee-ebpf/src/lib.rs`
- **Shared data structures:** `UnwindEntry`, `ProcInfo`, `DwarfUnwindState` in `profile-bee-common/src/lib.rs`
- After eBPF changes: `cargo xtask build-ebpf --release && cargo build --release`

## Critical Pitfalls

### BPF Verifier
- All loops MUST be bounded (`for _ in 0..CONST`). No `while`, no dynamic bounds.
- Map accesses must be bounds-checked. The verifier tracks these statically.
- `shard_lookup()` uses an 8-way static `match` — dynamic array indexing fails verification.
- The eBPF crate uses extreme optimization (`opt-level=3, lto, codegen-units=1`) even in debug — required for verifier to accept the code.
- Adding code to `collect_trace` can push it over the verifier instruction limit. The DWARF inline path (21 iterations × 8 mappings × 16 binary search steps) is near the edge.

### Two Separate Workspaces
- `profile-bee-ebpf/` is NOT in the root workspace. `cargo build` at root only builds userspace.
- Always run `cargo xtask build-ebpf` before `cargo build` when changing eBPF code.
- The eBPF crate requires nightly Rust and `bpf-linker`: `cargo install bpf-linker`.

### `#![no_std]` in Common Crate
- `profile-bee-common` is `#![no_std]`. No `String`, `Vec`, `HashMap`, `println!`.
- All structs must be `#[repr(C)]`, `Copy`, `Clone` with deterministic layout.
- Explicit padding fields (`_pad`, `_pad2`) ensure layout matches across eBPF and userspace.

### Binary Names
- `probee` and `pbee` are the same binary (both `[[bin]]` entries in `profile-bee/Cargo.toml`, same source `bin/profile-bee.rs`).

### `--pid` vs `--cmd`
- `--pid` with `stream_mode 2` (default) can miss samples for already-running processes.
- `--cmd` (or `-- <command>`) handles the process lifecycle and works reliably.
- E2E tests use `--cmd`.

### Frame Pointers Everywhere
- `.cargo/config.toml` sets `force-frame-pointers=yes` globally. All workspace crates are built with frame pointers for self-profiling support.

### Three Proc-Maps Libraries
- The codebase uses `procfs`, `procmaps`, and `proc-maps` for `/proc/pid/maps` parsing — legacy debt, not intentional.

## Known Limitations (DWARF)

| Constraint | Value | Why |
|---|---|---|
| Max frame depth | 165 (tail-call) / 21 (legacy) | Kernel 33 tail-call limit; legacy for kprobe/uprobe |
| Mappings per process | 8 (`MAX_PROC_MAPS`) | eBPF array size limit |
| Unwind shards | 8 (`MAX_UNWIND_SHARDS`) | Max 8 unique binaries with tables loaded |
| Entries per shard | 65,536 (`MAX_SHARD_ENTRIES`) | Very large binaries truncated |
| CFA registers | RSP, RBP only | Other registers skipped |
| DWARF expressions | Unsupported | Except PLT-stub and signal-frame patterns |
| Architecture | x86_64 only | Hardcoded register rules |

## Key Dependencies

| Crate | Used For |
|-------|----------|
| `aya` / `aya-ebpf` | eBPF loading, map access, program attachment |
| `blazesym` | Symbol resolution (replacing legacy addr2line) |
| `gimli` | DWARF `.eh_frame` parsing for unwind tables |
| `object` | ELF binary parsing |
| `inferno` | SVG flamegraph generation from collapse format |
| `clap` | CLI argument parsing (derive mode) |
| `tokio` | Async runtime for RingBuf polling, timers, signals |
| `warp` | HTTP server for `--serve` mode |
| `ratatui` (via profile-bee-tui) | Terminal UI rendering |

## Docs Reference

| Document | What |
|----------|------|
| `docs/dwarf_unwinding_design.md` | Full DWARF architecture, data structures, algorithm, limitations |
| `docs/tail_call_unwinding.md` | Tail-call chaining design and implementation |
| `docs/dwarf_correctness_issues.md` | Fixed and open DWARF correctness issues |
| `docs/dwarf_unwinding_literature_and_improvements.md` | Comparison with parca-agent, OTel profiler, async-profiler |
| `docs/kprobe_tracepoint_examples.md` | Example kprobe and tracepoint commands |
| `docs/NEXT_STEPS.md` | Feature roadmap |
| `CHANGELOG.md` | Release notes |
