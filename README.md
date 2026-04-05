## About

Profile Bee is an eBPF-based CPU profiler that ships as a single binary — no BCC, libbpf, or perf tooling needed on the target host. Built with Rust and [aya](https://aya-rs.dev/).

![Architecture](https://raw.githubusercontent.com/zz85/profile-bee/main/docs/architecture-sketch.png)

- Just `cargo install`, `sudo probee --tui`, and you're looking at a live flamegraph — no package manager dance, no Python dependencies, no separate visualization step
- Walks stacks directly in the kernel via frame pointers (fast, the default) or DWARF unwind tables (for those `-O2` binaries everyone ships without frame pointers)
- Attaches to perf events, kprobes, uprobes, or tracepoints — auto-discovers uprobe targets with glob and regex matching
- Demangles Rust and C++ symbols out of the box
- Outputs to interactive TUI, SVG, HTML, JSON, stackcollapse, pprof, or a real-time web server — whatever fits your workflow
- Uploads profiles directly to AWS CodeGuru Profiler for continuous profiling in the cloud

## Screenshots

Real-time TUI flamegraphs
![TUI Screenshot](https://raw.githubusercontent.com/zz85/profile-bee/main/docs/tui-self-profile-screenshot.png)

Real-time Web-based flamegraphs
![Web interface](https://raw.githubusercontent.com/zz85/profile-bee/main/docs/probee-web.png)


## Install

### Option 1: Shell Installer (Recommended)

Download and install the latest release with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/zz85/profile-bee/main/install.sh | bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/zz85/profile-bee/main/install.sh | bash
```

This installs pre-built binaries to `~/.local/bin`. No Rust toolchain required.

### Option 2: Cargo Install

```bash
cargo install profile-bee
```

Installs `probee` and `pbee` (short alias). No nightly Rust required — a prebuilt eBPF binary is bundled. Requires root to run (eBPF).

## Quick Start

```bash
# Interactive TUI flamegraph (live, system-wide)
sudo probee --tui

# Profile a specific command
sudo probee --tui -- my-application

# Generate an SVG flamegraph
sudo probee -o flamegraph.svg -t 5000

# Profile a command with args
sudo probee -o output.svg -- ./my-binary arg1 arg2

# Real-time flamegraphs via web server
sudo probee --serve --skip-idle

# Trace function calls with uprobe
sudo probee -e uprobe:malloc -t 1000 -o malloc.svg

# Off-CPU profiling — find where threads block
sudo probee --off-cpu --tui -- ./my-server
```

Run `probee` with no arguments or `probee --help` for the full list of options and examples.

## Features

- **Interactive TUI** — real-time flamegraph viewer with vim-style navigation, search, zoom, and mouse support (click, scroll, double-click to zoom)
- **Off-CPU profiling** (`--off-cpu`) — trace context switches via `finish_task_switch` kprobe to find where threads block on I/O, locks, or sleep. Configurable block-time filters.
- **Multiple output formats** — SVG, HTML, JSON (d3), [stackcollapse](https://www.speedscope.app/), and [pprof](https://github.com/google/pprof) protobuf (`.pb.gz`)
- **AWS CodeGuru integration** (`--codeguru-upload`) — upload profiles directly to AWS CodeGuru Profiler with proper thread-state counter types (RUNNABLE/WAITING)
- **Frame pointer unwinding** (default) — fast eBPF-based stack walking via `bpf_get_stackid`
- **DWARF unwinding** (`--dwarf`) — profiles `-O2`/`-O3` binaries without frame pointers using `.eh_frame` tables loaded into eBPF maps
- **Smart uprobes** — GDB-style symbol resolution with glob, regex, demangled name matching, and multi-attach
- **kprobe & tracepoint** support — profile kernel functions and tracepoint events
- **Real-time web server** (`--serve`) — live flamegraph updates over HTTP with interactive controls
- **Automatic termination** — stops when `-p` target or child process exits
- **Rust & C++ demangling** — via gimli/blazesym
- **BPF-based aggregation** — stack counting in kernel to reduce userspace data transfer
- **Group by CPU / process** — per-core or per-PID flamegraph breakdown (`--group-by-cpu`, `--group-by-process`)
- **Process lifecycle tracking** — eBPF-driven exec and exit detection via `sched_process_exec` / `sched_process_exit` tracepoints. Auto-enabled with DWARF unwinding; available to library consumers via `SessionConfig::track_process_lifecycle`
- **Process metadata cache** — lazy per-PID cache of `cmdline`, `cwd`, `environ`, `exe`, and mount namespace. Library API for agents that need to enrich profiling data with process context

---

## Detailed Usage

### Output Formats

Use `-o <file>` to specify output — the format is inferred from the file extension:

```bash
# SVG flamegraph
sudo probee -o profile.svg -f 999 -t 5000

# HTML flamegraph
sudo probee -o flamegraphs.html -t 5000

# Stackcollapse format (compatible with speedscope, flamegraph.pl)
sudo probee -o profile.folded -f 999 -t 10000

# pprof protobuf (compatible with go tool pprof, Grafana/Pyroscope, Speedscope)
sudo probee -o profile.pb.gz -t 5000

# AWS CodeGuru Profiler JSON (uploadable via AWS CLI)
sudo probee -o profile.codeguru.json -t 5000

# All output formats at once
sudo probee -t 5000 -o out.html -o out.json -o out.folded -o out.svg -o out.pb.gz

# Grouped by CPU
sudo probee -o profile.svg -f 999 -t 2000 --group-by-cpu

# Grouped by process (each PID gets its own flamegraph sub-tree)
sudo probee -o profile.svg -t 5000 --group-by-process
```

### Targeting

```bash
# Profile specific PID (auto-stops when process exits)
sudo probee -p <pid> -o output.svg -t 10000

# Profile specific CPU core
sudo probee --cpu 0 -o output.svg -t 5000

# Profile a command
sudo probee -o output.svg -- ./my-binary arg1 arg2

# Real-time flamegraphs via web server
sudo probee -t 5000 --serve --skip-idle --stream-mode 1
# Then open http://localhost:8000/ and click "realtime-updates"
```

### Kprobe & Tracepoint

Use `-e` with a probe type prefix:

```bash
# Profile kernel function calls
sudo probee -e kprobe:vfs_write -t 200 -o kprobe.svg

# Profile tracepoint events
sudo probee -e tracepoint:tcp:tcp_probe -t 200 -o tracepoint.svg
```

### Smart Uprobe Targeting

Profile-bee supports GDB-style symbol resolution for uprobes. Instead of manually specifying which library a function lives in, you provide a probe spec and the tool auto-discovers matching symbols across all loaded ELF binaries.

```bash
# Auto-discover library
sudo probee -e uprobe:malloc -t 1000 -o malloc.svg

# Multiple probes at once
sudo probee -e uprobe:malloc -e uretprobe:free -t 1000 -o alloc.svg

# Glob matching — trace all pthread functions
sudo probee -e 'uprobe:pthread_*' -t 1000 -o pthread.svg

# Regex matching
sudo probee -e 'uprobe:/^sql_.*query/' -p 1234 -t 2000 -o sql.svg

# Demangled C++/Rust name matching
sudo probee -e 'uprobe:std::vector::push_back' -p 1234 -t 1000 -o vec.svg

# Source file and line number (requires DWARF debug info)
sudo probee -e 'uprobe:main.c:42' -p 1234 -t 1000 -o source.svg

# Explicit library prefix
sudo probee -e uprobe:libc:malloc -t 1000 -o malloc.svg

# Absolute path to binary
sudo probee -e 'uprobe:/usr/lib/libc.so.6:malloc' -t 1000 -o malloc.svg

# Return probe (uretprobe)
sudo probee -e uretprobe:malloc -t 1000 -o malloc_ret.svg

# Function with offset
sudo probee -e uprobe:malloc+0x10 -t 1000 -o malloc_offset.svg

# Scope to a specific PID
sudo probee -e uprobe:malloc --uprobe-pid 12345 -t 1000 -o malloc_pid.svg

# Discovery mode — list matching symbols without attaching
sudo probee --list-probes 'uprobe:pthread_*' -p 1234
```

**Probe spec syntax:**

| Syntax | Example | Description |
|--------|---------|-------------|
| `function` | `malloc` | Exact match, auto-discover library |
| `lib:function` | `libc:malloc` | Explicit library name prefix |
| `/path:function` | `/usr/lib/libc.so.6:malloc` | Absolute path prefix |
| `ret:function` | `ret:malloc` | Return probe (uretprobe) |
| `function+offset` | `malloc+0x10` | Function with byte offset |
| `glob_pattern` | `pthread_*` | Glob matching (`*`, `?`, `[...]`) |
| `/regex/` | `/^sql_.*query/` | Regex matching |
| `Namespace::func` | `std::vector::push_back` | Demangled C++/Rust name match |
| `file.c:line` | `main.c:42` | Source location (requires DWARF) |

**Resolution order:**
1. If `--pid` or `--uprobe-pid` is set, scans `/proc/<pid>/maps` for all mapped executables
2. Otherwise, scans system libraries via `ldconfig` cache and standard paths
3. For each candidate ELF, reads `.symtab` and `.dynsym` symbol tables
4. Demangled matching uses both Rust and C++ demanglers
5. Source locations are resolved via gimli `.debug_line` parsing

**Multi-attach:** If a spec matches multiple symbols (e.g. `pthread_*` matching 20 functions), uprobes are attached to all of them.

---

## TUI Mode

The interactive terminal flamegraph viewer is included by default (forked and adapted from [flamelens](https://github.com/YS-L/flamelens)).

```bash
# Interactive TUI with a command
sudo probee --tui -- your-command

# Live profiling of a running process
sudo probee --tui -p <pid> -t 30000

# With DWARF unwinding for optimized binaries
sudo probee --tui --dwarf -- ./optimized-binary

# Build without TUI support
cargo build --release --no-default-features
```

**Key Bindings:**

| Key | Action |
|-----|--------|
| `hjkl` / arrows | Navigate cursor |
| `Enter` | Zoom into selected frame |
| `Esc` | Reset zoom |
| `Tab` | Cycle views: Flamegraph → Top → Processes (→ Output) |
| `t` | Toggle tree mode (expandable call tree in Top/Processes) |
| `p` | Toggle PID mode (split flamegraph by process) |
| `/` | Search frames with regex |
| `#` | Highlight selected frame |
| `n` / `N` | Next / previous match |
| `m` | Cycle update mode: Accumulate / Reset / Decay |
| `z` | Freeze / unfreeze live updates |
| `q` or `Ctrl+C` | Quit |

**Views:**

| View | Description |
|------|-------------|
| **Flamegraph** | Interactive flame chart (default) |
| **Top** | Flat function list sorted by overhead. Press `t` for expandable call tree. |
| **Processes** | Process list with CPU% breakdown. `Enter` to zoom into a process. Press `t` for tree. |
| **Output** | Child process stdout/stderr (when using `-- <command>`) |

---

## Stack Unwinding

Profile Bee supports two methods for stack unwinding. Both run the actual stack walking in eBPF (kernel space) for performance. Symbolization always happens in userspace.

### Frame Pointer Method (default)

Uses the kernel's `bpf_get_stackid` to walk the frame pointer chain. Works out of the box for binaries compiled with frame pointers:
- Rust: `RUSTFLAGS="-Cforce-frame-pointers=yes"`
- C/C++: `-fno-omit-frame-pointer` flag

### DWARF Method (`--dwarf`)

Handles binaries compiled without frame pointers (the default for most `-O2`/`-O3` builds). Use `--dwarf` to enable DWARF-based stack unwinding.

**How it works:**
1. At startup, userspace parses `/proc/[pid]/maps` and `.eh_frame` sections from each executable mapping
2. Pre-evaluates DWARF CFI rules into a flat `UnwindEntry` table (PC → CFA rule + RA rule)
3. Loads the table into eBPF maps before profiling begins
4. At sample time, the eBPF program binary-searches the table and walks the stack using CFA computation + `bpf_probe_read_user`
5. A background thread polls for newly loaded libraries (e.g. via `dlopen`) and updates the unwind tables at runtime

This is the same approach used by [parca-agent](https://github.com/parca-dev/parca-agent) and other production eBPF profilers.

```bash
# Enable DWARF unwinding for a no-frame-pointer binary
sudo probee --dwarf -o output.svg -t 5000 -- ./my-optimized-binary

# Frame pointer unwinding (the default)
sudo probee -o output.svg -t 5000 -- ./my-fp-binary
```

**Note**: For symbol resolution, you still need debug information:
- Rust: Add `-g` flag when compiling
- C/C++: Compile with debug symbols (`-g` flag)

**Limitations:** Max 8 executable mappings per process, 131K unwind table entries per binary (up to 64 binaries), up to 165 frame depth (via tail-call chaining; legacy fallback: 21 frames). x86_64 only. Libraries loaded via dlopen are detected within ~1 second.

See [docs/dwarf_unwinding_design.md](docs/dwarf_unwinding_design.md) for architecture details, and [Polar Signals' article on profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers) for background.

---

## Cloud Integration

### AWS CodeGuru Profiler

Upload profiles directly to [AWS CodeGuru Profiler](https://docs.aws.amazon.com/codeguru/latest/profiler-ug/what-is-codeguru-profiler.html) for continuous profiling with anomaly detection and optimization recommendations.

```bash
# One-time setup: create a profiling group
aws codeguruprofiler create-profiling-group \
  --profiling-group-name my-app \
  --compute-platform Default

# Profile and upload directly (use sudo -E to preserve AWS credentials)
sudo -E probee --codeguru-upload --profiling-group my-app -t 10000

# Off-CPU profiling uploads as WAITING counter type (visible in Latency view)
sudo -E probee --codeguru-upload --profiling-group my-app --off-cpu -t 10000

# Save a local copy while uploading
sudo -E probee --codeguru-upload --profiling-group my-app -o local.codeguru.json -t 10000

# Or generate the JSON locally and upload separately via AWS CLI
sudo probee -o profile.codeguru.json -t 10000
aws codeguruprofiler post-agent-profile \
  --profiling-group-name my-app \
  --agent-profile fileb://profile.codeguru.json \
  --content-type application/json
```

Uses the standard AWS credential chain (environment variables, `~/.aws/credentials`, IAM role, IMDS). When running with `sudo`, use `sudo -E` to preserve environment variables.

On-CPU samples use `RUNNABLE` counter type (visible in CPU and Latency views). Off-CPU samples use `WAITING` (visible in Latency view only). See [docs/codeguru_format.md](docs/codeguru_format.md) for format details.

### pprof Format

The `-o profile.pb.gz` output produces gzip-compressed [pprof](https://github.com/google/pprof) protobuf, the standard interchange format for profiling data:

```bash
sudo probee -o profile.pb.gz -t 5000

# View with go tool pprof
go tool pprof -http :8080 profile.pb.gz

# Upload to Grafana Cloud Profiles, Pyroscope, Datadog, or Polar Signals
```

Compatible with: `go tool pprof`, Grafana/Pyroscope, Speedscope, Datadog Continuous Profiler, Polar Signals/Parca.

### Building Without Cloud Features

```bash
# Build without AWS SDK (smaller binary, fewer dependencies)
cargo build --release --no-default-features --features tui
```

---

## Library API

Profile Bee can be used as a Rust library (not just a CLI). The `ProfilingSession` API consolidates eBPF loading, DWARF setup, and the event loop into a single entry point.

### Process Metadata Cache

When building a custom profiling agent, you often need per-process context (command line, environment variables, working directory) to enrich stack traces. The `ProcessMetadataCache` provides a lazy, capacity-bounded cache backed by `/proc/[pid]/`:

```rust
use profile_bee::process_metadata::ProcessMetadataCache;

let mut cache = ProcessMetadataCache::new(1024);

// Lazily loads from /proc on first access
if let Some(meta) = cache.get_or_load(pid) {
    println!("exe: {:?}", meta.exe);
    println!("cwd: {:?}", meta.cwd);

    // Read a specific environment variable
    if let Some(val) = meta.environ_var("APOLLO_GRAPH_REF") {
        println!("graph ref: {}", val);
    }
}

// Shorthand for get_or_load + environ_var
let db_url = cache.environ_var(pid, "DATABASE_URL");
```

The cache integrates with eBPF lifecycle events: exec events invalidate entries (same PID, new binary), exit events remove them. PID reuse is detected via `/proc/[pid]/stat` starttime comparison.

### Process Lifecycle Tracking

Enable `SessionConfig::track_process_lifecycle` to receive eBPF-driven exec and exit events. This is auto-enabled when DWARF unwinding is active (unwind tables need to be reloaded on exec). Custom agents should enable it for metadata cache management:

```rust
use profile_bee::session::{SessionConfig, ProfilingSession};
use profile_bee::ebpf::ProfilerConfig;

let config = SessionConfig {
    track_process_lifecycle: true,
    profiler: ProfilerConfig::default(),
    ..Default::default()
};

let session = ProfilingSession::new(config).await?;
// The event loop automatically handles exec (cache invalidation, DWARF reload)
// and exit (deferred eviction) events.
// Access the metadata cache via session's event loop:
// event_loop.process_metadata().get_or_load(pid)
```

---

## Limitations

- Linux only (requires eBPF support)
- DWARF unwinding: x86_64 only, see limits above
- Interpreted / JIT stack traces not yet supported
- [VDSO](https://man7.org/linux/man-pages/man7/vdso.7.html) `.eh_frame` parsed for DWARF unwinding; VDSO symbolization not yet supported

## Development

### Prerequisites

1. Install stable and nightly Rust: `rustup install stable nightly`
2. Install bpf-linker: `cargo install bpf-linker`

### Build

```bash
# Build eBPF program (requires nightly)
cargo xtask build-ebpf

# Build userspace (uses fresh eBPF build if available, otherwise prebuilt)
cargo build --release

# Run
cargo xtask run
```

To perform a release build of the eBPF program, use `cargo xtask build-ebpf --release`. You may also change the target architecture with the `--target` flag.

More documentation in the [docs](docs) directory.

### Alternatives

- [perf](https://perf.wiki.kernel.org/) + [Cargo flamegraph](https://github.com/flamegraph-rs/flamegraph)
- [BCC profile](https://github.com/iovisor/bcc/blob/master/tools/profile.py)
- [parca-agent](https://github.com/parca-dev/parca-agent) — always-on eBPF profiling in Go
