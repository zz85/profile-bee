 # profile-bee 🐝🦀🔥

Profile Bee is an eBPF-based CPU profiler written in Rust that provides efficient and lightweight profiling capabilities even though several features are experimental.

Leveraging aya-tools for eBPF integration, this runs as a single binary without the need for
additional libraries such as bcctools or libbpf on target hosts.

In CPU sampling mode, eBPF is attached to perf events for sampling.

Stacktraces are retrieved in the user space program for symbols resolution.

Stacks can be counted in kernel or sent via events in raw form.

More documentation in [docs](docs) directory.

### Supported output formats
- **TUI (Terminal User Interface)**: Interactive flamegraph viewer directly in your terminal (requires `tui` feature)
- A SVG flamegraph (generated with inferno) you can load in your browser
- [Branden Gregg's](https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html) Stack Collapsed [format](https://github.com/BrendanGregg/flamegraph#2-fold-stacks) that can be loaded up using [speedscope visualizer](https://www.speedscope.app/)
- D3 flamegraph JSON and static HTML output
- Your own custom format

### Stack unwinding, Symbolization and Debug info

Profile Bee supports two methods for stack unwinding:

1. **Frame Pointer Unwinding** (eBPF): Fast, but requires binaries compiled with `-fno-omit-frame-pointer`.
2. **DWARF-based Unwinding** (eBPF + userspace): Profiles binaries without frame pointers by using `.eh_frame` unwind tables.

Both methods run the actual stack walking in eBPF (kernel space) for performance. Symbolization always happens in userspace.

#### Frame Pointer Method

Uses the kernel's `bpf_get_stackid` to walk the frame pointer chain. Works out of the box for binaries compiled with frame pointers:
- Rust: `RUSTFLAGS="-Cforce-frame-pointers=yes"`
- C/C++: `-fno-omit-frame-pointer` flag

#### DWARF Method (default)

Enabled by default. Handles binaries compiled without frame pointers (the default for most `-O2`/`-O3` builds). Use `--dwarf=false` to disable and fall back to frame pointer unwinding.

**How it works:**
1. At startup, userspace parses `/proc/[pid]/maps` and `.eh_frame` sections from each executable mapping
2. Pre-evaluates DWARF CFI rules into a flat `UnwindEntry` table (PC → CFA rule + RA rule)
3. Loads the table into eBPF maps before profiling begins
4. At sample time, the eBPF program binary-searches the table and walks the stack using CFA computation + `bpf_probe_read_user`
5. A background thread polls for newly loaded libraries (e.g. via `dlopen`) and updates the unwind tables at runtime

This is the same approach used by [parca-agent](https://github.com/parca-dev/parca-agent) and other production eBPF profilers.

```bash
# Profile a no-frame-pointer binary (DWARF unwinding is on by default)
profile-bee --svg output.svg --time 5000 -- ./my-optimized-binary

# Disable DWARF unwinding to use frame pointers only
profile-bee --dwarf=false --svg output.svg --time 5000 -- ./my-fp-binary
```

See `docs/dwarf_unwinding_design.md` for architecture details.

#### Current limitations

- Max 16 executable mappings per process, 500K unwind table entries total, 32 frame depth
- Libraries loaded via dlopen are detected within ~1 second

**Note**: For symbol resolution, you still need debug information:
- Rust: Add `-g` flag when compiling
- C/C++: Compile with debug symbols (`-g` flag)

For more information on DWARF-based profiling, see:
- [Polar Signals' article on profiling without frame pointers](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers)
- `docs/dwarf_unwinding_design.md` for architecture details

### Usage

```bash
# Interactive TUI flamegraph viewer (requires tui feature)
profile-bee --tui --cmd "top -b -n 5 -d 1"

# TUI with live profiling updates
profile-bee --tui --pid 1234 --time 30000

# Profile a command (runs top for 5 seconds), writing flamegraph to test.svg
profile-bee --svg test.svg -- top -b -n 5 -d 1

# Profile a command with multiple arguments
profile-bee --svg test.svg -- ls -la /tmp

# Profile system wide for 5s, generating a html flamegraph
profile-bee --time 5000 --html flamegraphs.html

# Profile at 9999hz for 2s, writing output to profile.svg
profile-bee --svg profile.svg --frequency 9999 --time 2000

# Realtime flamegraphs
profile-bee --time 5000 --serve --skip-idle --stream-mode 1
# Then goto http://localhost:8000/ and click "realtime-updates"

# Same as above, grouped by CPU ids
profile-bee --svg profile.svg --frequency 9999 --time 2000 --group-by-cpu

# Profile at 999hz for 10s, writing output to profile.txt
profile-bee --collapse profile.txt --frequency 999 --time 10000

# Kitchen sink of all output formats
profile-bee --time 5000 --html flamegraphs.html --json profile.json --collapse profile.txt --svg profile.svg

# Profile at 99hz for 5s, writing output to screen, idle CPU cycles not counted
cargo xtask run --release -- --collapse profile.txt --frequency 99 --time 5000 --skip-idle

# Profile using kprobe over a short interval of 200ms
profile-bee --kprobe vfs_write --time 200 --svg kprobe.svg

# Profile using a tracepoint over a interval of 200ms
profile-bee --tracepoint tcp:tcp_probe --time 200 --svg tracepoint.svg

# Profile specific pid (includes child processes, automatically stops when process exits)
profile-bee --pid <pid> --svg output.svg --time 10000

# Profile specific cpu
profile-bee --cpu 0 --svg output.svg --time 5000

# Profile a command with DWARF unwinding (for binaries without frame pointers)
profile-bee --svg output.svg -- ./my-optimized-binary

```

### TUI (Terminal User Interface)

Profile-bee includes an interactive terminal-based flamegraph viewer, forked and adapted from [flamelens](https://github.com/YS-L/flamelens). The TUI mode provides a rich interactive experience directly in your terminal without needing a browser.

**Key Features:**
- Real-time flamegraph updates during profiling
- Navigate and zoom into specific stack frames
- Search and highlight frames using regex patterns
- Freeze/unfreeze live updates with 'z' key
- Keyboard-driven interface (vim-style navigation)

**Usage:**
```bash
# Build with TUI support
cargo build --release --features tui

# Interactive TUI with a command
sudo ./target/release/profile-bee --tui --cmd "your-command"

# Live profiling of a running process
sudo ./target/release/profile-bee --tui --pid <pid> --time 30000

# With DWARF unwinding for optimized binaries (enabled by default)
sudo ./target/release/profile-bee --tui --cmd "./optimized-binary"
```

**Key Bindings:**
- `hjkl` or arrow keys: Navigate cursor
- `Enter`: Zoom into selected frame
- `Esc`: Reset zoom
- `/`: Search frames with regex
- `#`: Highlight selected frame
- `n/N`: Next/previous match
- `z`: Freeze/unfreeze live updates
- `q` or `Ctrl+C`: Quit

The TUI viewer is optional and can be enabled with the `tui` feature flag. See [profile-bee-tui/](profile-bee-tui/) for implementation details.

### Features
- **DWARF-based stack unwinding** (enabled by default) for profiling binaries without frame pointers
- Frame pointer-based unwinding in eBPF for maximum performance
- Rust and C++ symbols demangling supported (via gimli/blazesym)
- Some source mapping supported
- Simple symbol lookup cache
- SVG Flamegraph generation (via inferno)
- BPF based stacktrace aggregation for reducing kernel <-> userspace transfers
- Basic Kernel and tracepoint probing
- Group by CPUs
- Profile target PIDs, CPU id, or itself
- **Automatic termination** when target PID (via `--pid`) or spawned process (via `--cmd`) exits
- Static d3 flamegraph JSON and/or HTML output
- Real time flamegraphs served over integrated web server (using warp)

### Limitations
- Linux only
- DWARF unwinding: max 16 mappings per process / 500K total entries / 32 frames
- Libraries loaded via dlopen are detected within ~1 second
- Interpreted / JIT stacktraces not yet supported
- [VDSO](https://man7.org/linux/man-pages/man7/vdso.7.html) `.eh_frame` parsed for DWARF unwinding; VDSO symbolization not yet supported

### TODOs
- Optimize CPU usage
- Check stack correctness (compare with perf, pprof etc)
- implement uprobing/USDT
- pid nesting
- Off CPU profiling
- Publish to crates.io
- ~~Optimize symbol lookup via binary search~~
- ~~Measure cache hit ratio~~
- ~~Missing symbols~~
- ~~switch over to Perf buffers~~
- ~~Stacktrace and Hashmap clearing~~


### Alternatives
- Perf
- Bcc's [profile tool](https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/profile.py)
- [Cargo flamegraph](https://github.com/flamegraph-rs/flamegraph), utilizing perf without the hassle
- [Parca-agent](https://github.com/parca-dev/parca-agent), always on profiling with BPF, except using [golang](https://github.com/parca-dev/parca-agent/pull/869).

# Development

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
