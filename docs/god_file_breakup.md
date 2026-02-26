# Breaking Up `bin/profile-bee.rs`

Incremental plan to refactor the 2,250-line main binary into focused modules,
introducing a `Collector`/`OutputSink` trait pattern that decouples profiling from output.

## Current Structure

```
bin/profile-bee.rs (2,252 lines)
├── Types: PerfWork, DwarfThreadMsg, DwarfRefreshUpdate, Opt       (32-238)
├── Helpers: parse syscalls, uprobe resolution, process setup      (280-954)
├── main() — 311 lines of orchestration                            (525-835)
├── Stopping mechanisms + ring buffer tasks                        (957-1065)
├── DWARF refresh loop + eBPF map updates                          (1068-1333)
├── Profiling loop A: batch                                        (1337-1476)
├── Profiling loop B: streaming                                    (1482-1617)
├── Helpers: process_local_counting, process_kernel_counting       (1620-1665)
├── Output dispatch: output_results, output_svg                    (1680-1760)
├── Profiling loop C: TUI thread                                   (1866-2056)
└── TUI orchestration: run_tui_event_loop, run_combined, run_tui   (2060-2252)
```

The profiling data processing logic is duplicated three times:
- `process_profiling_data()` — batch mode
- `process_profiling_data_streaming()` — streaming/web mode
- `spawn_profiling_thread()` — TUI mode

All three share ~80% of their logic (eBPF counts clearing, PerfWork dispatch, DWARF refresh, stack symbolization, collapse formatting). The differences are blocking strategy, state ownership, and output target.

## Goal

After all phases, `bin/profile-bee.rs` shrinks to ~500-600 lines: a thin CLI wrapper that parses options, builds a pipeline, and calls `pipeline.run()`. Adding a new output format or trace collector requires implementing one trait — no changes to the profiling loop.

## Phases

Each phase is a standalone commit. Code compiles and tests pass after every phase.

### Phase 1: Move `apply_dwarf_refresh` into `ebpf.rs`

**~130 lines moved, ~0 lines added**

`apply_dwarf_refresh()` (lines 1203-1333) is pure eBPF map manipulation:
- Creates inner shard arrays, inserts into `unwind_shards` ArrayOfMaps
- Updates `exec_mappings` LPM trie (add/remove entries)
- Updates `dwarf_tgids` HashMap

Also move `send_refresh()` (lines 1167-1200), which builds `DwarfRefreshUpdate` structs from `DwarfUnwindManager` state.

Both belong in `ebpf.rs` next to other map operations. The main binary calls them via the `EbpfProfiler` API.

### Phase 2: Extract coordination types into `src/pipeline.rs`

**~100 lines moved, ~20 lines added**

Move from `bin/profile-bee.rs`:
- `PerfWork` enum — central message type for the profiler's mpsc channel
- `DwarfThreadMsg` enum — messages for the DWARF background thread
- `DwarfRefreshUpdate` struct — incremental DWARF data from background thread
- `dwarf_refresh_loop()` — background thread that polls `/proc/[pid]/maps` and refreshes unwind tables

These types define the profiling pipeline's coordination interfaces.

### Phase 3: Define `OutputSink` trait + sink implementations

**~200 lines moved, ~100 lines added. Creates `src/output.rs`.**

```rust
pub trait OutputSink: Send {
    /// Called with each batch of processed stack frames + counts.
    fn on_frames(&mut self, frames: &[FrameCount]) -> Result<()>;
    /// Called when profiling is complete. Flush/finalize output.
    fn finish(&mut self) -> Result<()>;
}
```

Sink implementations, extracted from `output_results()` and `spawn_profiling_thread()`:

| Sink | Extracted from | What it does |
|------|---------------|--------------|
| `CollapseSink` | `output_results()` | Writes stackcollapse format to file |
| `SvgSink` | `output_svg()` | Accumulates collapse lines, writes SVG on `finish()` |
| `HtmlSink` | `output_results()` | Generates HTML flamegraph on `finish()` |
| `JsonSink` | `output_results()` | Writes JSON to file on `finish()` |
| `WebBroadcastSink` | `output_results()` | Sends JSON to `broadcast::Sender` each cycle |
| `TuiSink` | `spawn_profiling_thread()` | Parses into `ParsedFlameGraph`, writes to `Arc<Mutex>` |
| `MultiplexSink` | New | Wraps `Vec<Box<dyn OutputSink>>`, fans out to all |

After this phase, adding a new output format (pprof, OpenTelemetry, remote HTTP) is a single `OutputSink` implementation — no changes to any profiling loop.

### Phase 4: Unify profiling loops into `ProfilingPipeline`

**~400 lines collapsed to ~200, net reduction ~200 lines**

Replace all three loops with a single `ProfilingPipeline::run()`:

```rust
pub struct ProfilingPipeline {
    perf_rx: mpsc::Receiver<PerfWork>,
    profiler: TraceHandler,
    bpf: Ebpf,
    sink: Box<dyn OutputSink>,
    dwarf_tx: Option<mpsc::Sender<DwarfThreadMsg>>,
    config: PipelineConfig,
}

pub struct PipelineConfig {
    pub stream_mode: u8,
    pub flush_interval: Duration,  // Duration::MAX for batch (one shot)
    pub group_by_cpu: bool,
}
```

The mode differences reduce to `PipelineConfig`:
- **Batch**: `flush_interval = Duration::MAX`, sink = `MultiplexSink(svg + html + json + collapse)`
- **Streaming**: `flush_interval = 2s`, sink = `MultiplexSink(web + svg + ...)`
- **TUI**: `flush_interval = tui_refresh_ms`, sink = `MultiplexSink(tui + optional web)`

### Phase 5: Slim down `main()` to thin CLI wrapper

**Net: `bin/profile-bee.rs` drops to ~500-600 lines**

`main()` becomes:
1. Parse CLI options
2. Build `ProfilerConfig` + set up eBPF
3. Build `OutputSink` from CLI options
4. Build `PipelineConfig` from CLI options
5. Create `ProfilingPipeline`
6. Call `pipeline.run()`
7. Call `sink.finish()`

## Summary

| Phase | Lines moved | Enables |
|-------|------------|---------|
| 1. Move DWARF refresh to ebpf.rs | ~130 | Cleaner module boundaries |
| 2. Extract coordination types | ~100 | Shared pipeline interfaces |
| 3. OutputSink trait | ~300 | Adding new trace collectors without touching loops |
| 4. Unify profiling loops | ~200 net reduction | Single bug-fix point |
| 5. Slim main() | ~100 | Thin CLI wrapper, everything unit-testable |
