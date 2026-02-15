# profile-bee

An eBPF-based CPU profiler for Linux, written in Rust. Single binary, no BCC/libbpf dependencies.

![Architecture](https://raw.githubusercontent.com/zz85/profile-bee/main/docs/architecture-sketch.png)

![TUI Screenshot](https://raw.githubusercontent.com/zz85/profile-bee/main/docs/tui-self-profile-screenshot.png)

## About

Profile Bee is an eBPF-based CPU profiler that ships as a single binary — no BCC, libbpf, or perf tooling needed on the target host. Built with Rust and [aya](https://aya-rs.dev/).

- Just `cargo install`, `sudo probee --tui`, and you're looking at a live flamegraph — no package manager dance, no Python dependencies, no separate visualization step
- Walks stacks directly in the kernel via frame pointers (fast, the default) or DWARF unwind tables (for those `-O2` binaries everyone ships without frame pointers)
- Attaches to perf events, kprobes, uprobes, or tracepoints — auto-discovers uprobe targets with glob and regex matching
- Demangles Rust and C++ symbols out of the box
- Outputs to interactive TUI, SVG, HTML, JSON, stackcollapse, or a real-time web server — whatever fits your workflow

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
sudo probee --tui --cmd "my-application"

# Generate an SVG flamegraph
sudo probee --svg flamegraph.svg --time 5000

# Profile a command with args
sudo probee --svg output.svg -- ./my-binary arg1 arg2

# Real-time flamegraphs via web server
sudo probee --serve --skip-idle

# Trace function calls with uprobe
sudo probee --uprobe malloc --time 1000 --svg malloc.svg
```

Run `probee` with no arguments or `probee --help` for the full list of options and examples.

## Features

- **Interactive TUI** — real-time flamegraph viewer with vim-style navigation, search, and zoom
- **Multiple output formats** — SVG, HTML, JSON (d3), and [stackcollapse](https://www.speedscope.app/) format
- **Frame pointer unwinding** (default) — fast eBPF-based stack walking via `bpf_get_stackid`
- **DWARF unwinding** (`--dwarf`) — profiles `-O2`/`-O3` binaries without frame pointers using `.eh_frame` tables loaded into eBPF maps
- **Smart uprobes** — GDB-style symbol resolution with glob, regex, demangled name matching, and multi-attach
- **kprobe & tracepoint** support — profile kernel functions and tracepoint events
- **Real-time web server** (`--serve`) — live flamegraph updates over HTTP
- **Automatic termination** — stops when `--pid` target or `--cmd` process exits
- **Rust & C++ demangling** — via gimli/blazesym
- **BPF-based aggregation** — stack counting in kernel to reduce userspace data transfer
- **Group by CPU** — per-core flamegraph breakdown

---

## Detailed Usage

### Output Formats

```bash
# SVG flamegraph
sudo probee --svg profile.svg --frequency 999 --time 5000

# HTML flamegraph
sudo probee --time 5000 --html flamegraphs.html

# Stackcollapse format (compatible with speedscope, flamegraph.pl)
sudo probee --collapse profile.txt --frequency 999 --time 10000

# All output formats at once
sudo probee --time 5000 --html out.html --json out.json --collapse out.txt --svg out.svg

# Grouped by CPU
sudo probee --svg profile.svg --frequency 999 --time 2000 --group-by-cpu
```

### Targeting

```bash
# Profile specific PID (auto-stops when process exits)
sudo probee --pid <pid> --svg output.svg --time 10000

# Profile specific CPU core
sudo probee --cpu 0 --svg output.svg --time 5000

# Profile a command
sudo probee --svg output.svg -- ./my-binary arg1 arg2

# Real-time flamegraphs via web server
sudo probee --time 5000 --serve --skip-idle --stream-mode 1
# Then open http://localhost:8000/ and click "realtime-updates"
```

### Kprobe & Tracepoint

```bash
# Profile kernel function calls
sudo probee --kprobe vfs_write --time 200 --svg kprobe.svg

# Profile tracepoint events
sudo probee --tracepoint tcp:tcp_probe --time 200 --svg tracepoint.svg
```

### Smart Uprobe Targeting

Profile-bee supports GDB-style symbol resolution for uprobes. Instead of manually specifying which library a function lives in, you provide a probe spec and the tool auto-discovers matching symbols across all loaded ELF binaries.

```bash
# Auto-discover library
sudo probee --uprobe malloc --time 1000 --svg malloc.svg

# Multiple probes at once
sudo probee --uprobe malloc --uprobe 'ret:free' --time 1000 --svg alloc.svg

# Glob matching — trace all pthread functions
sudo probee --uprobe 'pthread_*' --time 1000 --svg pthread.svg

# Regex matching
sudo probee --uprobe '/^sql_.*query/' --pid 1234 --time 2000 --svg sql.svg

# Demangled C++/Rust name matching
sudo probee --uprobe 'std::vector::push_back' --pid 1234 --time 1000 --svg vec.svg

# Source file and line number (requires DWARF debug info)
sudo probee --uprobe 'main.c:42' --pid 1234 --time 1000 --svg source.svg

# Explicit library prefix
sudo probee --uprobe libc:malloc --time 1000 --svg malloc.svg

# Absolute path to binary
sudo probee --uprobe '/usr/lib/libc.so.6:malloc' --time 1000 --svg malloc.svg

# Return probe (uretprobe)
sudo probee --uprobe ret:malloc --time 1000 --svg malloc_ret.svg

# Function with offset
sudo probee --uprobe malloc+0x10 --time 1000 --svg malloc_offset.svg

# Scope to a specific PID
sudo probee --uprobe malloc --uprobe-pid 12345 --time 1000 --svg malloc_pid.svg

# Discovery mode — list matching symbols without attaching
sudo probee --list-probes 'pthread_*' --pid 1234
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
sudo probee --tui --cmd "your-command"

# Live profiling of a running process
sudo probee --tui --pid <pid> --time 30000

# With DWARF unwinding for optimized binaries
sudo probee --tui --dwarf --cmd "./optimized-binary"

# Build without TUI support
cargo build --release --no-default-features
```

**Key Bindings:**

| Key | Action |
|-----|--------|
| `hjkl` / arrows | Navigate cursor |
| `Enter` | Zoom into selected frame |
| `Esc` | Reset zoom |
| `/` | Search frames with regex |
| `#` | Highlight selected frame |
| `n` / `N` | Next / previous match |
| `z` | Freeze / unfreeze live updates |
| `q` or `Ctrl+C` | Quit |

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
sudo probee --dwarf --svg output.svg --time 5000 -- ./my-optimized-binary

# Frame pointer unwinding (the default)
sudo probee --svg output.svg --time 5000 -- ./my-fp-binary
```

**Note**: For symbol resolution, you still need debug information:
- Rust: Add `-g` flag when compiling
- C/C++: Compile with debug symbols (`-g` flag)

**Limitations:** Max 16 executable mappings per process, 500K unwind table entries per binary, up to 165 frame depth (via tail-call chaining; legacy fallback: 21 frames). x86_64 only. Libraries loaded via dlopen are detected within ~1 second.

See [docs/dwarf_unwinding_design.md](docs/dwarf_unwinding_design.md) for architecture details, and [Polar Signals' article on profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers) for background.

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
