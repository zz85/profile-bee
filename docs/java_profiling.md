# Java / HotSpot Profiling

profile-bee supports **non-intrusive** Java CPU profiling on Linux by combining
native stack unwinding (frame pointers or DWARF) with **JIT symbol maps**.

This is Phase 1 of the Java roadmap. Full HotSpot VM-struct unwinding in eBPF
(OTel eBPF Profiler style) is planned as a later phase — see below.

## Quick start

```bash
# 1. Run your JVM with frame pointers when possible (helps native+JIT boundaries)
java -XX:+PreserveFramePointer -jar myapp.jar

# 2. Dump JIT symbols into the standard perf-map path (OpenJDK 17+)
jcmd <pid> Compiler.perfmap
# creates /tmp/perf-<pid>.map

# 3. Profile with probee (auto-detects JVM + loads the map)
sudo probee --pid <pid> --tui
# or
sudo probee --cmd "java -XX:+PreserveFramePointer -jar myapp.jar" --tui
```

Collapsed / SVG output works the same as for native apps:

```bash
sudo probee --pid <pid> -o java.svg -t 10000
```

## What you get today (Phase 1)

| Capability | Status |
|------------|--------|
| Detect HotSpot/`libjvm.so` processes | ✅ automatic |
| Resolve JIT PCs via `/tmp/perf-<pid>.map` | ✅ automatic |
| Demangle `Ljava/lang/String;equals` → `java.lang.String.equals` | ✅ |
| Tag JVM stubs (`Interpreter`, …) as `[jvm] …` | ✅ |
| Container path `/proc/<pid>/root/tmp/perf-<pid>.map` | ✅ |
| Live reload when the map file grows (recompilation) | ✅ |
| Native `libjvm.so` frames via DWARF/FP | ✅ (existing) |
| Interpreter / nmethod frame walk in eBPF | ❌ Phase 3 |
| Inlined Java frames (`ScopeDesc`) | ❌ Phase 3 |
| Allocation / lock profiling | ❌ use async-profiler |
| JFR output | ⏳ separate roadmap item |

Without a perf-map, JIT frames appear as `[unknown]` (anonymous executable
mappings). profile-bee logs a one-time hint when it sees a JVM without a map.

## Enabling perf-maps

### `jcmd Compiler.perfmap` (recommended)

```bash
jcmd <pid> Compiler.perfmap
```

OpenJDK writes `/tmp/perf-<pid>.map` with current code-cache methods. Re-run
after warm-up or major recompilation; profile-bee reloads on mtime/size change.

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
| `profile-bee/src/java/` | JVM detection, symbol display helpers |
| `profile-bee/src/perf_map.rs` | Parse/cache `/tmp/perf-<pid>.map` |
| `profile-bee/src/trace_handler.rs` | Symbolize + JIT fallback |
| `profile-bee/src/event_loop.rs` | Auto-register JVM/perf-map on new PIDs |

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
