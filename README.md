 # profile-bee

🐝🦀 Profile Bee is an eBPF based CPU profiler written in Rust for performance and efficiency.

Aya is used for building the BPF programs that is attached to perf events for sampling.
The beauty of this tool is that it runs from a single binary without the need to install
additional libraries such as bcctools or libbpf on target hosts.

Stacktraces are retrieved in the user space program and symbols resolution is handled.

Stacks are counted and sorted, the resulting output is [Branden Gregg's](https://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html) Stack Collapsed [format](https://github.com/BrendanGregg/flamegraph#2-fold-stacks).
This format can be turned into a flamegraph visualization using [speedscope](https://www.speedscope.app/) or inferno-flamegraph.

### Supported
- Rust and C++ symbols demangling supported (via gimli)
- Some source mapping supported (via addr2line)

### Limitations
- Linux only
- No caching in symbol lookup
- Interpreted / JIT stacktraces not yet supported

### TODOs
- switch over to Perf buffers
- implement k/uprobing
- Integrate inferno-flamegraph for svg generation
- Add CPU id information
- Off CPU profiling

### Alternatives
- Perf
- Bcc's [profile tool](https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/profile.py)
- [Cargo flamegraph](https://github.com/flamegraph-rs/flamegraph), utilizing perf without the hassle
- [Parca-agent](https://github.com/parca-dev/parca-agent), always on profiling with BPF, except for golang for userspace tools

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
