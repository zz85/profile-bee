# Ideas

## Distribution Approaches

### 1. CLI-first (bcc `profile` model)

Follow the ergonomics of bcc's `profile` tool — a single binary that just works with sensible defaults:

```bash
# bcc profile style: just run it, get folded stacks on stdout
sudo profile-bee                          # system-wide, 10s, stdout
sudo profile-bee -p 1234                  # target pid
sudo profile-bee -p 1234 -F 999 -d 5     # 999hz for 5s
sudo profile-bee -p 1234 -f               # folded output (pipe to flamegraph)
```

Key ergonomic lessons from bcc `profile`:
- Default to stdout in folded format — pipeable to other tools
- Short flags for common options (`-p`, `-F`, `-d`)
- No mandatory output file — works in a pipeline
- Kernel-side aggregation by default for efficiency (profile-bee already does this)

This positions profile-bee as a **drop-in replacement for `profile-bpfcc`** that doesn't need Python or bcc installed.

### 2. Embeddable Agent (async-profiler-agent model)

A library crate (`profile-bee-agent`) that applications embed for always-on continuous profiling in production:

```rust
let profiler = profile_bee_agent::ProfilerBuilder::default()
    .frequency(99)
    .duration(Duration::from_secs(60))
    .interval(Duration::from_secs(300))  // profile 60s every 5min
    .with_reporter(S3Reporter::new(config))
    .build();

profiler.spawn()?;  // background, non-blocking
```

Key ideas from async-profiler-agent:
- `Reporter` trait — abstract destination (S3, local, HTTP, Pyroscope)
- Host metadata auto-detection (EC2 instance ID, ECS task, K8s pod)
- `spawn()` fire-and-forget pattern
- Periodic profiling (profile N seconds, sleep, repeat)

Profile-bee's advantage: no external `.so` needed, DWARF unwinding built in, native Rust/C++ support, kernel stacks included.

### 3. Cargo Subcommand (cargo-flamegraph model)

A `cargo-profile-bee` binary that integrates with the cargo build workflow:

```bash
# Build in release, run, profile, and generate flamegraph — one command
cargo profile-bee --svg out.svg -- --release --bin my-server

# Profile tests
cargo profile-bee --svg test.svg -- test -- my_heavy_test

# Profile benchmarks
cargo profile-bee --svg bench.svg -- bench

# With DWARF unwinding (for optimized builds without frame pointers)
cargo profile-bee --dwarf --svg out.svg -- --release --bin my-server
```

Key ergonomics from cargo-flamegraph:
- Handles build → spawn → profile → output in one step
- Passes cargo args after `--` naturally
- Auto-opens SVG in browser on completion
- No need to manually find the binary path

The vendored `cargo-trace` already has some of this plumbing. The main work is wiring it into profile-bee's profiler and output pipeline.

## Integrations

### flamelens ✅ IMPLEMENTED

[flamelens](https://github.com/YS-L/flamelens) is an interactive TUI flamegraph viewer. Profile-bee now includes an embedded TUI viewer forked from flamelens.

**Implementation:**
- Created `profile-bee-tui` workspace crate containing the forked flamelens code
- Adapted to work with profile-bee's collapsed stack format
- Removed Python-specific features, added support for live profiling updates
- Integrated with `--tui` flag (requires `tui` feature)
- Supports real-time flamegraph updates during profiling
- Freeze/unfreeze capability with 'z' key

**Usage:**
```bash
# Build with TUI support
cargo build --release --features tui

# Use the TUI viewer
sudo ./target/release/profile-bee --tui --cmd "your-command"
sudo ./target/release/profile-bee --tui --pid <pid> --time 30000
```

**Original ideas (archived):**
- ~~Pipe directly: `sudo profile-bee -p 1234 | flamelens`~~
- ~~Add a `--flamelens` flag that pipes output to flamelens automatically (if installed)~~
- ~~Explore embedding flamelens as an optional feature for an integrated TUI experience~~
