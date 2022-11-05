 # profile-bee 🐝🦀🔥

Profile Bee is an eBPF based CPU profiler written in Rust for performance and efficiency.

Aya is used for building the BPF programs that is attached to perf events for sampling.
The beauty of this tool is that it runs from a single binary without the need to install
additional libraries such as bcctools or libbpf on target hosts.

Stacktraces are retrieved in the user space program and symbols resolution is handled.

Stacks are counted and sorted and can be output with the follow choices

- A SVG flamegraph (generated with inferno) you can load in your browser
- [Branden Gregg's](https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html) Stack Collapsed [format](https://github.com/BrendanGregg/flamegraph#2-fold-stacks) that can be loaded up using [speedscope visualizer](https://www.speedscope.app/)
- D3 flamegraph JSON and HTML output
- Your own custom format

Note: if symbols for your C/Rust programs doesn't appear correct, you may want to build your software with frame pointers.

For rust programs, you can emit frame pointer by setting `RUSTFLAGS="-Cforce-frame-pointers=yes"` with building (or modifying ./cargo/config)
and `-fno-omit-frame-pointer` for gcc.

### Usage

```
# Profile system wide for 5s, generating a html flamegraph
profile-bee --time 5000 --html flamegraphs.html

# Profile at 9999hz for 2s, writing output to profile.svg
profile-bee --svg profile.svg --frequency 9999 --time 2000

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

# Profile specific pid (or cpu)
profile-bee --pid <pid> ...

```

### Features
- Rust and C++ symbols demangling supported (via gimli)
- Some source mapping supported (via addr2line)
- Simple symbol lookup cache
- SVG Flamegraph generation (via inferno)
- BPF based stacktrace aggregation for reducing kernel <-> userspace transfers
- Basic Kernel and tracepoint probing
- Group by CPUs
- Profile target PIDs, CPU id, or itself
- d3 flamegraph JSON and/or HTML output
- Integrated web server (using warp)

### Limitations
- Linux only
- Interpreted / JIT stacktraces not yet supported
- [VDSO](https://man7.org/linux/man-pages/man7/vdso.7.html) and binary offsets not calculated

### TODOs
- Optimize CPU usage
- Check stack correctness (compare with perf, pprof etc)
- switch over to Perf buffers
- implement uprobing/USDT
- pid nesting
- Off CPU profiling
- Optimize symbol lookup via binary search
- Publish to crates.io
- Measure cache hit ratio
- Stacktrace and Hashmap clearing
- Missing symbols

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
