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

#### DWARF Method

Disabled by default. Handles binaries compiled without frame pointers (the default for most `-O2`/`-O3` builds). Use `--dwarf` to enable DWARF-based stack unwinding.

**How it works:**
1. At startup, userspace parses `/proc/[pid]/maps` and `.eh_frame` sections from each executable mapping
2. Pre-evaluates DWARF CFI rules into a flat `UnwindEntry` table (PC → CFA rule + RA rule)
3. Loads the table into eBPF maps before profiling begins
4. At sample time, the eBPF program binary-searches the table and walks the stack using CFA computation + `bpf_probe_read_user`
5. A background thread polls for newly loaded libraries (e.g. via `dlopen`) and updates the unwind tables at runtime

This is the same approach used by [parca-agent](https://github.com/parca-dev/parca-agent) and other production eBPF profilers.

```bash
# Enable DWARF unwinding for a no-frame-pointer binary
probee --dwarf --svg output.svg --time 5000 -- ./my-optimized-binary

# Frame pointer unwinding (the default)
probee --svg output.svg --time 5000 -- ./my-fp-binary
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

### Installation

```bash
cargo install profile-bee
```

This installs two binaries: `probee` (primary) and `pbee` (short alias). No nightly Rust required — a prebuilt eBPF binary is bundled.

### Usage

```bash
# Interactive TUI flamegraph viewer
probee --tui --cmd "top -b -n 5 -d 1"

# TUI with live profiling updates
probee --tui --pid 1234 --time 30000

# Profile a command (runs top for 5 seconds), writing flamegraph to test.svg
probee --svg test.svg -- top -b -n 5 -d 1

# Profile a command with multiple arguments
probee --svg test.svg -- ls -la /tmp

# Profile system wide for 5s, generating a html flamegraph
probee --time 5000 --html flamegraphs.html

# Profile at 9999hz for 2s, writing output to profile.svg
probee --svg profile.svg --frequency 9999 --time 2000

# Realtime flamegraphs
probee --time 5000 --serve --skip-idle --stream-mode 1
# Then goto http://localhost:8000/ and click "realtime-updates"

# Same as above, grouped by CPU ids
probee --svg profile.svg --frequency 9999 --time 2000 --group-by-cpu

# Profile at 999hz for 10s, writing output to profile.txt
probee --collapse profile.txt --frequency 999 --time 10000

# Kitchen sink of all output formats
probee --time 5000 --html flamegraphs.html --json profile.json --collapse profile.txt --svg profile.svg

# Profile at 99hz for 5s, writing output to screen, idle CPU cycles not counted
cargo xtask run --release -- --collapse profile.txt --frequency 99 --time 5000 --skip-idle

# Profile using kprobe over a short interval of 200ms
probee --kprobe vfs_write --time 200 --svg kprobe.svg

# Profile using a tracepoint over a interval of 200ms
probee --tracepoint tcp:tcp_probe --time 200 --svg tracepoint.svg

# Profile using uprobe on malloc in libc (auto-discovered)
probee --uprobe malloc --time 1000 --svg malloc.svg

# Profile multiple functions at once
probee --uprobe malloc --uprobe 'ret:free' --time 1000 --svg alloc.svg

# Glob matching — trace all pthread functions
probee --uprobe 'pthread_*' --time 1000 --svg pthread.svg

# Regex matching
probee --uprobe '/^sql_.*query/' --pid 1234 --time 2000 --svg sql.svg

# Demangled C++/Rust name matching
probee --uprobe 'std::vector::push_back' --pid 1234 --time 1000 --svg vec.svg

# Source file and line number (requires DWARF debug info)
probee --uprobe 'main.c:42' --pid 1234 --time 1000 --svg source.svg

# Explicit library prefix
probee --uprobe libc:malloc --time 1000 --svg malloc.svg

# Absolute path to binary
probee --uprobe '/usr/lib/libc.so.6:malloc' --time 1000 --svg malloc.svg

# Return probe (uretprobe)
probee --uprobe ret:malloc --time 1000 --svg malloc_ret.svg

# Function with offset
probee --uprobe malloc+0x10 --time 1000 --svg malloc_offset.svg

# Scope to a specific PID
probee --uprobe malloc --uprobe-pid 12345 --time 1000 --svg malloc_pid.svg

# Discovery mode — list matching symbols without attaching
probee --list-probes 'pthread_*' --pid 1234

# Profile specific pid (includes child processes, automatically stops when process exits)
probee --pid <pid> --svg output.svg --time 10000

# Profile specific cpu
probee --cpu 0 --svg output.svg --time 5000

# Profile a command with DWARF unwinding (for binaries without frame pointers)
probee --svg output.svg -- ./my-optimized-binary

```

### Smart Uprobe Targeting

Profile-bee supports GDB-style symbol resolution for uprobes. Instead of manually specifying which library a function lives in, you provide a probe spec and the tool auto-discovers matching symbols across all loaded ELF binaries.

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

**Discovery mode:** Use `--list-probes` to search without attaching:

```bash
$ sudo probee --list-probes 'pthread_*' --pid 1234

/usr/lib/x86_64-linux-gnu/libc.so.6:
  pthread_create                                     0x0008fe30  (456 bytes)
  pthread_join                                       0x00090a10  (312 bytes)
  pthread_mutex_lock                                 0x00094230  (128 bytes)
  ...

Total: 20 matches across 1 library
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
- `hjkl` or arrow keys: Navigate cursor
- `Enter`: Zoom into selected frame
- `Esc`: Reset zoom
- `/`: Search frames with regex
- `#`: Highlight selected frame
- `n/N`: Next/previous match
- `z`: Freeze/unfreeze live updates
- `q` or `Ctrl+C`: Quit

The TUI viewer is included by default. Use `--no-default-features` to build without it. See [profile-bee-tui/](profile-bee-tui/) for implementation details.

### Features
- **DWARF-based stack unwinding** (opt-in with `--dwarf`) for profiling binaries without frame pointers
- Frame pointer-based unwinding in eBPF for maximum performance
- Rust and C++ symbols demangling supported (via gimli/blazesym)
- Some source mapping supported
- Simple symbol lookup cache
- SVG Flamegraph generation (via inferno)
- BPF based stacktrace aggregation for reducing kernel <-> userspace transfers
- **Smart uprobe/uretprobe** with GDB-style symbol resolution:
  - Auto-discovers which library a function lives in (no `--uprobe-path` needed)
  - Glob (`pthread_*`), regex (`/pattern/`), and demangled name matching
  - Source file:line targeting via DWARF debug info
  - Multi-attach: one spec can match multiple symbols across libraries
  - Discovery mode (`--list-probes`) to inspect available symbols
- Basic Kernel probing (kprobe) and tracepoint support
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
- Implement USDT (User Statically-Defined Tracing) support
- pid nesting
- Off CPU profiling
- Publish to crates.io
- ~~Implement uprobing (uprobe/uretprobe)~~
- ~~Smart uprobe symbol resolution (GDB-style auto-discovery)~~
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
