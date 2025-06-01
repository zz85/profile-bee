# Profile Bee Architecture Overview

Profile Bee is an eBPF-based CPU profiler written in Rust that provides efficient and lightweight profiling capabilities. This document outlines the high-level architecture and component interactions within the system.

## Core Components

### 1. eBPF Programs
The eBPF programs are the kernel-space components that:
- Attach to perf events, kprobes, or tracepoints
- Collect stack traces at specified sampling frequencies
- Aggregate data in BPF maps to minimize kernel-userspace transfers
- Utilize the Aya framework for BPF program management

### 2. User Space Program
The user space component handles:
- Loading and managing eBPF programs
- Reading and processing stack traces from BPF maps
- Symbol resolution and demangling for Rust and C++ programs
- Stack trace aggregation and processing
- Caching symbol lookups for performance

### 3. Output Generators
Multiple output formats are supported:
- SVG flamegraphs (via inferno)
- Collapsed stack format (compatible with speedscope)
- D3 flamegraph JSON and HTML
- Custom output formats

### 4. Web Server
For real-time profiling:
- Built with Warp framework
- Provides WebSocket streaming for real-time updates
- Serves interactive flamegraph visualizations
- Supports grouping by CPU

## Data Flow

1. User initiates profiling with specific parameters (frequency, duration, output format)
2. eBPF programs attach to specified events (perf, kprobe, tracepoint)
3. Stack samples are collected at the specified frequency
4. User space program retrieves stack traces and resolves symbols
5. Data is aggregated and processed
6. Output is generated in the requested format(s)
7. For real-time mode, updates are streamed to the web interface

## Key Features

- **Single Binary**: No dependencies on external libraries like bcctools or libbpf
- **Symbol Resolution**: Handles Rust and C++ symbol demangling
- **Multiple Output Formats**: Supports various visualization formats
- **Real-time Analysis**: Stream updates to a web interface
- **Flexible Targeting**: Profile system-wide, specific PIDs, or CPUs
- **Probe Types**: Support for perf events, kprobes, and tracepoints

## Limitations and Future Work

- Linux only
- Interpreted/JIT stacktraces not yet supported
- VDSO and binary offsets not calculated
- Planned improvements for CPU usage optimization and symbol lookup
- Future support for uprobing/USDT and off-CPU profiling
