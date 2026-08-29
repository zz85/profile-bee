# Java / HotSpot Profiling

profile-bee supports **non-intrusive** Java CPU profiling on Linux by combining
native stack unwinding (frame pointers or DWARF) with **JIT symbol maps**.

This is Phase 1 of the Java roadmap. Full HotSpot VM-struct unwinding in eBPF
(OTel eBPF Profiler style) is planned as a later phase — see below.

## Quick start (system-wide, automatic)

```bash
# Profile the whole machine — probee finds running JVMs, dumps JIT maps,
# and resolves Java method names without manual jcmd:
sudo probee --tui

# Or target one PID (still auto-dumps Compiler.perfmap if needed):
sudo probee --pid <pid> --tui

# Spawn a workload under the profiler:
sudo probee --cmd "java -XX:+PreserveFramePointer -jar myapp.jar" --tui
```

Collapsed / SVG output works the same as for native apps:

```bash
sudo probee -o java.svg -t 10000
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--auto-java true\|false` | `true` | Scan `/proc`, dump/load JIT perf-maps for HotSpot |
| `--java-refresh-secs N` | `30` | Re-dump/reload maps every N seconds (`0` = off) |

Disable attach traffic if you only want passive map loading:

```bash
sudo probee --auto-java false --tui
```

## What you get today (Phase 1)

| Capability | Status |
|------------|--------|
| Detect HotSpot/`libjvm.so` processes | ✅ automatic |
| **System-wide JVM scan at startup** | ✅ automatic |
| **Auto-dump `Compiler.perfmap`** (jcmd / attach / nsenter) | ✅ automatic |
| Resolve JIT PCs via `/tmp/perf-<pid>.map` | ✅ automatic |
| Demangle `Ljava/lang/String;equals` → `java.lang.String.equals` | ✅ |
| Tag JVM stubs (`Interpreter`, …) as `[jvm] …` | ✅ |
| Container path + NSpid-aware map names | ✅ |
| Live reload + periodic re-dump for JIT churn | ✅ |
| Native `libjvm.so` frames via DWARF/FP | ✅ (existing) |
| Interpreter / nmethod frame walk in eBPF | ❌ Phase 3 |
| Inlined Java frames (`ScopeDesc`) | ❌ Phase 3 |
| Allocation / lock profiling | ❌ use async-profiler |
| JFR output | ⏳ separate roadmap item |

If automatic dump fails (permissions, exotic JVM), JIT frames may still appear
as `[unknown]`. profile-bee logs a one-time hint with recovery steps.

## How auto-dump works

On startup (and when a new JVM PID is first sampled), profile-bee:

1. Scans `/proc` for processes mapping `libjvm.so` or named `java`
2. Looks for an existing `/tmp/perf-<pid>.map` (host, NSpid, container root)
3. If missing, tries in order:
   - host `jcmd <pid> Compiler.perfmap`
   - `jcmd` next to the process’s own `java` binary
   - direct HotSpot attach socket (`.java_pid*`, SIGQUIT trigger)
   - `nsenter -t <pid> -m -p` + in-namespace `jcmd` (containers)
4. Loads the map into the JIT symbol cache and refreshes periodically

### Manual `jcmd` (optional)

You can still dump maps yourself; profile-bee will pick them up:

```bash
jcmd <pid> Compiler.perfmap
```

### async-profiler as a symbol helper

You can still use async-profiler to generate maps or to **validate** profile-bee
stacks:

```bash
asprof -d 30 -f ap.html <pid>          # gold-standard Java flamegraph
asprof dump-perfmap <pid>               # if your build supports it
```

### Frame pointers

`-XX:+PreserveFramePointer` improves mixed native/Java unwinding when using
the FP path. DWARF mode (`--dwarf`) helps for `libjvm.so` built without FPs.

## How it works

```text
perf_event sample
    → eBPF: FP or DWARF unwind (native IPs, including JIT PCs as raw addresses)
    → userspace TraceHandler
         1. blazesym (ELF symbols for libjvm, libc, …)
         2. V8 SFI path (Node only)
         3. perf-map lookup for remaining [unknown] addresses  ← Java Phase 1
         4. format HotSpot names for flamegraphs
```

Relevant code:

| Module | Role |
|--------|------|
| `profile-bee/src/java/mod.rs` | JVM detection, symbol display helpers |
| `profile-bee/src/java/attach.rs` | Discover JVMs, jcmd/attach/nsenter dump |
| `profile-bee/src/perf_map.rs` | Parse/cache `/tmp/perf-<pid>.map` |
| `profile-bee/src/trace_handler.rs` | Symbolize + JIT fallback + auto-dump |
| `profile-bee/src/event_loop.rs` | Startup scan + periodic refresh |

## Comparison with other tools

### async-profiler

- **In-process** JVMTI agent; VM-struct / AGCT stack walking; best Java fidelity
  (inlines, interpreter, alloc/lock modes).
- profile-bee does **not** inject an agent. Use async-profiler when you need
  maximum Java detail or non-CPU modes; use profile-bee for system-wide
  native+JVM with a single external binary.

### OpenTelemetry eBPF Profiler (`opentelemetry-ebpf-profiler`)

- Full **HotSpot eBPF unwinder**: code-cache segmap, interpreter frames,
  userspace Method* symbolization via VM structs.
- This is the blueprint for profile-bee **Phase 3**.

### OBI (`opentelemetry-ebpf-instrumentation`)

- Java **APM** (TLS spans via injected ByteBuddy agent) + JVM memory USDT metrics.
- Not a CPU profiler. Optional future work: read OBI’s pinned `traces_ctx_v1`
  map to correlate profile samples with active trace/span IDs.

## Roadmap

### Phase 2 — HotSpot introspection (userspace)

- Parse `gHotSpotVMStructs` from `libjvm.so` (per JDK build).
- Remote `process_vm_readv` of `Method*` / `nmethod*` for names when cookies
  are available (mirrors `v8/heap.rs`).

### Phase 3 — eBPF HotSpot unwinder

- `HotspotProcInfo` in `profile-bee-common` + BPF maps (parallel to `V8ProcInfo`).
- Code-cache residency → interpreter / nmethod / stub unwind actions.
- Side-channel metadata array (parallel to `v8_sfi`) with pointer + cookie.
- Tail-call stepping under `perf_event` (same constraints as DWARF/V8).

### Phase 4 — Product polish

- OTLP/pprof frame types (`java` / `jvm`).
- JFR writer (see `docs/NEXT_STEPS.md` §10d).
- e2e fixtures vs async-profiler collapse output.
- Optional OBI trace correlation.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| All Java frames `[unknown]` | Run `jcmd <pid> Compiler.perfmap`; confirm `/tmp/perf-<pid>.map` exists and is readable by root |
| Only `libjvm.so` C++ symbols | Map missing or empty; JIT not warmed up |
| Broken stacks at JIT boundaries | Try `--dwarf` and/or `-XX:+PreserveFramePointer` |
| Container PID | profile-bee also checks `/proc/<pid>/root/tmp/perf-<pid>.map` |
| OpenJ9 / Graal native image | Not targeted yet (HotSpot-first) |

## References

- [async-profiler Stack Walking Modes](https://github.com/async-profiler/async-profiler/blob/master/docs/StackWalkingModes.md)
- [OTel eBPF Profiler HotSpot interpreter](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/hotspot)
- Linux `perf-map-agent` / JIT dump conventions
