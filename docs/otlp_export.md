# OTLP Profiles Export

profile-bee can export profiling data in the [OpenTelemetry Profiles](https://opentelemetry.io/docs/specs/otel/profiles/) format via gRPC, enabling integration with:

- **[Grafana Pyroscope](https://grafana.com/oss/pyroscope/)** — continuous profiling storage + Grafana flamegraph visualization
- **[devfiler](https://github.com/elastic/devfiler)** — Elastic's local profiling viewer with server-side symbolization
- **[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)** — route profiles to any OTLP-compatible backend

## Quick Start

```bash
# Send profiles to Pyroscope (simplest — pre-symbolized, no symbol server needed)
sudo probee --otlp-endpoint pyroscope:4040 --flush-interval 10000 --skip-idle

# Send profiles to devfiler with symbol server (full native symbolization)
symbol-server --port 8888 &
devfiler --symb-endpoint http://localhost:8888 &
sudo probee --otlp-endpoint 127.0.0.1:11000 --symbol-server http://localhost:8888 --flush-interval 10000 --skip-idle

# One-shot batch profile (5 seconds, then exit)
sudo probee --otlp-endpoint 127.0.0.1:11000 --time 5000

# Profile a specific command
sudo probee --otlp-endpoint pyroscope:4040 --otlp-service-name my-app -- ./my-app

# Combine with local output
sudo probee --otlp-endpoint 127.0.0.1:11000 -o flame.svg --flush-interval 10000
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          profile-bee                                   │
│                                                                        │
│  eBPF sampler → symbolize → ┬─ OtlpNativeSink (batch/flush-interval) │
│                              │    real ELF VAs + htlhash build IDs     │
│                              │    profile.frame.type = "native"        │
│                              │                                         │
│                              └─ OtlpSink (serve/TUI mode)             │
│                                   pre-symbolized function names        │
│                                   profile.frame.type = "go"            │
└───────────┬────────────────────────────────┬─────────────────────────┘
            │ OTLP gRPC                       │ POST /upload (binaries)
            ▼                                 ▼
    ┌───────────────┐                 ┌──────────────┐
    │   devfiler    │ ◀──GET ranges──│ symbol-server │
    │  :11000       │                 │   :8888      │
    └───────────────┘                 └──────────────┘
            │
    or      ▼
    ┌───────────────┐
    │  Pyroscope    │  (no symbol server needed)
    │  :4040        │
    └───────────────┘
```

## Two Export Modes

### 1. Pre-symbolized (for Pyroscope, OTel Collector)

Used when `--symbol-server` is NOT set, or in `--serve`/`--tui` modes.

- Sends function names directly in the OTLP proto's `Location.lines`
- Uses `profile.frame.type = "go"` so receivers read names from the proto
- No additional infrastructure needed
- Works with any OTLP Profiles receiver

### 2. Native addresses (for devfiler)

Used in batch/`--flush-interval` mode when `--symbol-server` IS set.

- Sends real ELF virtual addresses in `Location.address`
- Includes proper `Mapping` entries from `/proc/<pid>/maps`
- Computes htlhash build IDs (SHA-256 of head+tail+length) for each binary
- Uses `profile.frame.type = "native"` so devfiler does server-side symbolization
- Requires the `symbol-server` daemon for devfiler to fetch symbols from

## CLI Flags

| Flag | Description |
|------|-------------|
| `--otlp-endpoint <host:port>` | OTLP gRPC endpoint (e.g., `127.0.0.1:11000` for devfiler, `pyroscope:4040`) |
| `--otlp-insecure` | Use plaintext gRPC (default: true) |
| `--otlp-service-name <name>` | Service name for resource attributes (default: profiled command name) |
| `--symbol-server <url>` | Symbol server URL for automatic binary upload (enables native address mode) |
| `--flush-interval <ms>` | Continuous profiling: upload every N ms (runs until Ctrl-C or `--time`) |

## Symbol Server

The `symbol-server` crate is a standalone daemon that bridges profile-bee and devfiler:

```bash
# Start the symbol server
cargo run -p symbol-server -- --port 8888 --store-dir ./symbols

# Check status
curl http://localhost:8888/status
```

### How it works

1. profile-bee discovers binaries from `/proc/*/maps` and POSTs them to `/upload`
2. symbol-server computes htlhash FileId, extracts symbols from `.symtab`/`.dynsym`
3. symbol-server stores pre-processed symbfiles (zstd-compressed protobuf)
4. devfiler polls `--symb-endpoint` using htlhash to fetch symbol ranges
5. devfiler resolves ELF VA addresses to function names using the interval tree

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload?filename=<name>` | POST | Upload ELF binary for processing |
| `/:a/:b/:id/metadata.json` | GET | devfiler auto-fetch: symbol metadata |
| `/:a/:b/:id/ranges` | GET | devfiler auto-fetch: zstd-compressed symbfile |
| `/status` | GET | List all stored symbol entries |

## Symbolization Approaches Across the Ecosystem

| System | Where symbolization happens | Symbol server? | Protocol |
|--------|----------------------------|----------------|----------|
| **devfiler** (Elastic) | Server-side. Profiler sends raw ELF VAs. devfiler fetches symbols from HTTP endpoint. | Yes — separate HTTP symbol server | Custom htlhash + symbfile format |
| **Pyroscope** (Grafana) | Client-side. Stores whatever function names arrive in OTLP. No server-side symbolization. | No | OTLP gRPC on port 4040 |
| **OTel Collector** | Pass-through. Routes profiles to backends. No symbolization. | No | OTLP gRPC |
| **Parca** (Polar Signals) | Server-side. Agent sends raw addresses + build IDs. Server fetches debuginfo. | Yes — debuginfod protocol | Custom gRPC |
| **Grafana Alloy** (eBPF) | Client-side. Resolves in the OTel eBPF profiler's Go process before sending. | No | OTLP gRPC via OTel Collector |

### Implications for profile-bee

- **Pyroscope/OTel Collector**: Just send pre-symbolized names. No extra infra.
- **devfiler**: Send native ELF VAs + run `symbol-server` alongside. More setup but enables server-side features (inline frames, source lines).
- **Parca**: Would need a debuginfod-compatible symbol source. Not currently supported but could be added via the `profile-bee-symbols` shared crate.

## Shared Libraries

The `profile-bee-symbols` crate provides shared functionality used by both profile-bee and symbol-server:

- **`fileid`** — htlhash FileId computation (SHA-256 of first 4096 + last 4096 + file length, truncated to 128 bits)
- **`extract`** — ELF symbol extraction from `.symtab`/`.dynsym` with Rust/C++ demangling

This enables future optimizations where profile-bee can pre-extract symbols and POST them directly in symbfile format, reducing symbol-server's workload when the profiler is already doing symbolization locally.
