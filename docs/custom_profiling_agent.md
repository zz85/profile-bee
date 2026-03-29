# Building a Custom Profiling Agent

This guide shows how to build a continuous profiling agent as a **separate crate**
that depends on `profile-bee` as a library.  The agent profiles your system,
enriches the stack data with custom metadata, and uploads results to a backend
— all without modifying the profile-bee repository.

## Architecture

```
your-profiling-agent/           (your crate)
├── Cargo.toml                  (depends on profile-bee)
└── src/
    ├── main.rs                 (CLI, scheduling loop)
    ├── enrichment.rs           (stack post-processing)
    └── upload.rs               (backend upload logic)
```

Your agent uses profile-bee's library API to handle the hard parts (eBPF loading,
stack unwinding, symbolization) and focuses on the domain-specific logic:
stack enrichment, environment detection, upload formatting.

## Core API: `collect_raw()`

The key extension point is `ProfilingEventLoop::collect_raw()`, which returns
structured `Vec<FrameCount>` instead of pre-formatted collapse strings.

```rust
use profile_bee::event_loop::{RawCollectResult, collapse_raw};
use profile_bee::types::FrameCount;

// collect_raw() returns symbolized frames you can inspect and modify
let result: RawCollectResult = session.event_loop.collect_raw(&rx, Some(duration));

for fc in &result.stacks {
    // fc.count  — number of times this stack was sampled
    // fc.frames — Vec<StackFrameInfo>, bottom-to-top
    for frame in &fc.frames {
        // frame.pid          — process ID
        // frame.cmd          — process name (16-byte kernel comm)
        // frame.symbol       — resolved symbol name
        // frame.object_path  — path to the ELF binary/library
        // frame.source       — source file + line (if available)
        // frame.cpu_id       — CPU core that was sampled
    }
}

// If you need collapse-format strings after enrichment:
let collapse_strings: Vec<String> = collapse_raw(&result.stacks);
```

## Comparison: `collect()` vs `collect_raw()`

| | `collect()` | `collect_raw()` |
|---|---|---|
| Returns | `Vec<String>` (collapse format) | `Vec<FrameCount>` (structured) |
| Use case | Standard output (SVG, TUI, pprof) | Custom agents that enrich stacks |
| Can modify stacks? | No (already formatted) | Yes (full access to frame data) |
| Can add/remove frames? | No | Yes |
| Can look up process metadata? | No | Yes (between collect and format) |

## Example: Continuous Profiling Agent

```rust
use std::time::Duration;
use profile_bee::session::{ProfilingSession, SessionConfig};
use profile_bee::ebpf::ProfilerConfig;
use profile_bee::event_loop::collapse_raw;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Configure the profiler
    let config = SessionConfig {
        profiler: ProfilerConfig {
            frequency: 99,          // 99 Hz sampling
            dwarf: true,            // DWARF unwinding for accurate stacks
            ..ProfilerConfig::default()
        },
        duration_ms: 0,             // Run indefinitely (we control the loop)
        ..SessionConfig::default()
    };

    // 2. Initialize the profiling session
    //    This loads eBPF programs, sets up DWARF tables, starts ring buffers.
    let (mut session, rx) = ProfilingSession::new(config).await?;

    // 3. Continuous profiling loop
    let interval = Duration::from_secs(10);  // collect 10s of samples per cycle

    loop {
        // Collect raw structured stacks for this interval
        let result = session.event_loop.collect_raw(&rx, Some(interval));

        if !result.stacks.is_empty() {
            // 4. Enrich stacks with your domain-specific metadata
            let enriched = enrich_stacks(result.stacks);

            // 5. Upload to your backend
            if let Err(e) = upload_profile(&enriched).await {
                eprintln!("Upload failed: {e:#}");
                // Continue profiling even if upload fails
            }
        }

        if result.stopped {
            break;
        }
    }

    Ok(())
}
```

## Stack Enrichment Pattern

A common pattern is to look up per-process metadata and annotate stacks.
Since `StackFrameInfo` contains the `pid`, you can read `/proc/[pid]/*`
to get process context:

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use profile_bee::types::{FrameCount, StackFrameInfo};

/// Cached process metadata read from /proc.
struct ProcessMetadata {
    cwd: Option<PathBuf>,
    cmdline: Option<Vec<String>>,
    environment: String,  // your domain-specific field
}

/// Cache to avoid re-reading /proc for every sample.
struct MetadataCache {
    cache: HashMap<usize, ProcessMetadata>,
}

impl MetadataCache {
    fn get(&mut self, pid: usize) -> &ProcessMetadata {
        self.cache.entry(pid).or_insert_with(|| {
            // Read from /proc/[pid]/{cwd,cmdline,environ}
            // using the `procfs` crate (already a transitive dependency)
            let process = procfs::process::Process::new(pid as i32).ok();
            let cwd = process.as_ref().and_then(|p| p.cwd().ok());
            let cmdline = process.as_ref().and_then(|p| p.cmdline().ok());

            // Your domain logic: detect deployment environment from cwd, etc.
            let environment = detect_environment(&cwd, &cmdline);

            ProcessMetadata { cwd, cmdline, environment }
        })
    }
}

fn detect_environment(cwd: &Option<PathBuf>, cmdline: &Option<Vec<String>>) -> String {
    // Example: extract environment name from process working directory
    // e.g., /opt/services/my-service/... -> "my-service"
    if let Some(cwd) = cwd {
        if let Some(name) = cwd.components().nth(3) {
            return name.as_os_str().to_string_lossy().to_string();
        }
    }
    "unknown".to_string()
}
```

### Applying Enrichment

```rust
fn enrich_stacks(stacks: Vec<FrameCount>) -> Vec<FrameCount> {
    let mut cache = MetadataCache { cache: HashMap::new() };

    stacks.into_iter().map(|mut fc| {
        if let Some(first_frame) = fc.frames.first() {
            let meta = cache.get(first_frame.pid);

            // Prepend an environment frame as the stack root.
            // This groups stacks by service in flamegraph visualizations.
            let env_frame = StackFrameInfo {
                pid: first_frame.pid,
                cmd: first_frame.cmd.clone(),
                symbol: Some(meta.environment.clone()),
                ..Default::default()
            };
            fc.frames.insert(0, env_frame);

            // Optionally reformat the process name frame
            if let Some(cmdline) = &meta.cmdline {
                if let Some(frame) = fc.frames.get_mut(1) {
                    frame.cmd = format_process_name(&frame.cmd, cmdline);
                }
            }
        }
        fc
    }).collect()
}

fn format_process_name(comm: &str, cmdline: &[String]) -> String {
    // Example: for interpreters, show the script name instead of "python3"
    let interpreters = ["python", "python3", "node", "ruby", "perl", "java"];
    if interpreters.iter().any(|i| comm.contains(i)) {
        // Find the script argument
        if let Some(script) = cmdline.iter().find(|arg| !arg.starts_with('-')) {
            if let Some(name) = PathBuf::from(script).file_name() {
                return format!("{} {}", comm, name.to_string_lossy());
            }
        }
    }
    comm.to_string()
}
```

## Using OutputSink for Standard Formats

If you also want standard output formats alongside your custom upload,
use `collapse_raw()` to convert enriched stacks to collapse strings,
then feed them to any existing `OutputSink`:

```rust
use profile_bee::event_loop::collapse_raw;
use profile_bee::output::{SvgSink, PprofSink, OutputSink};

let enriched: Vec<FrameCount> = enrich_stacks(raw_stacks);
let collapse_strings = collapse_raw(&enriched);

// Write an SVG flamegraph with enriched stacks
let mut svg = SvgSink::new("profile.svg".into(), "My Service".into(), false);
svg.finish(&collapse_strings)?;

// Write a pprof file with enriched stacks
let mut pprof = PprofSink::new("profile.pb.gz".into(), 99, 10000, false);
pprof.finish(&collapse_strings)?;
```

## Cargo.toml

```toml
[package]
name = "my-profiling-agent"
version = "0.1.0"
edition = "2021"

[dependencies]
profile-bee = { git = "https://github.com/zz85/profile-bee", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal", "time"] }
anyhow = "1"
procfs = "0.17"       # for /proc/[pid] metadata reads
reqwest = "0.12"      # for HTTP upload (if needed)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

Note: `default-features = false` disables the TUI dependency. Add `features = ["tui"]`
if you want TUI support in your agent.

## API Reference

### `ProfilingEventLoop::collect_raw()`

```rust
pub fn collect_raw(
    &mut self,
    rx: &mpsc::Receiver<PerfWork>,
    timeout: Option<Duration>,
) -> RawCollectResult
```

- `timeout = None` — blocks until a `Stop` signal (batch mode)
- `timeout = Some(d)` — collects for up to `d`, then returns (streaming/agent mode)
- Returns `RawCollectResult { stacks: Vec<FrameCount>, stopped: bool }`

### `collapse_raw()`

```rust
pub fn collapse_raw(stacks: &[FrameCount]) -> Vec<String>
```

Converts structured `FrameCount` data into sorted collapse-format strings.
Same format as `collect()` produces. Compatible with inferno, flamegraph.pl,
and all profile-bee output sinks. Uses the default `fmt_symbol()` formatter.

### `collapse_raw_with()`

```rust
pub fn collapse_raw_with<F>(stacks: &[FrameCount], fmt: F) -> Vec<String>
where F: Fn(&StackFrameInfo) -> String
```

Same as `collapse_raw()` but with a custom frame formatter. Controls how
each `StackFrameInfo` becomes a string in the collapse output.

```rust
use profile_bee::event_loop::collapse_raw_with;

// Example: perf-style "object`symbol" format
let stacks = collapse_raw_with(&raw.stacks, |frame| {
    let obj = frame.fmt_object();
    let sym = frame.symbol.as_deref().unwrap_or("[unknown]");
    format!("{}`{}", obj, sym)
});

// Example: include full source paths
let stacks = collapse_raw_with(&raw.stacks, |frame| {
    let sym = frame.symbol.as_deref().unwrap_or("[unknown]");
    match &frame.source {
        Some(src) => format!("{} ({})", sym, src),
        None => sym.to_string(),
    }
});
```

### `FrameCount`

```rust
pub struct FrameCount {
    pub frames: Vec<StackFrameInfo>,  // bottom-to-top stack frames
    pub count: u64,                    // number of samples
}
```

### `StackFrameInfo`

```rust
pub struct StackFrameInfo {
    pub pid: usize,
    pub cmd: String,                    // kernel comm (16 bytes)
    pub address: u64,
    pub object_path: Option<PathBuf>,   // ELF binary/library path
    pub symbol: Option<String>,         // resolved symbol name
    pub source: Option<String>,         // source file:line
    pub cpu_id: Option<u32>,
    pub ns: Option<u64>,                // mount namespace inode
}
```
