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

# Or target one PID (still auto-dumps Compiler.perfmap if needed).
# When a PID is targeted, Java auto-discovery is SCOPED to that PID only —
# no other JVMs on the host are scanned or attached to:
sudo probee --pid <pid> --tui

# Spawn a workload under the profiler. `-XX:+PreserveFramePointer` is injected
# automatically via JAVA_TOOL_OPTIONS — you do not need to pass it yourself:
sudo probee --tui -- java -jar myapp.jar
```

Collapsed / SVG output works the same as for native apps:

```bash
sudo probee -o java.svg -t 10000
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--auto-java true\|false` | `true` | Dump/load JIT perf-maps for HotSpot (scoped to `--pid`/`--cmd` target; system-wide `/proc` scan only when no target) |
| `--java-refresh-secs N` | `30` | Re-dump/reload maps every N seconds (`0` = off) |

### Scoping and attach safety

Auto-discovery is **scoped to the profiling target**:

- With `--pid` / `--cmd` / `-- <cmd>`, profile-bee only dumps and reloads the
  perf-map for **that** process. It never scans `/proc` for other JVMs and
  never sends `jcmd`/SIGQUIT attach traffic to unrelated (possibly production)
  JVMs on the host. This also keeps startup fast — no synchronous attach to
  every JVM before sampling begins.
- Only a truly system-wide profile (no target) scans and attaches to all JVMs.

Note that the HotSpot attach protocol (used as a fallback when `jcmd` is
unavailable) triggers the JVM's attach listener via `SIGQUIT`, which prints a
thread dump to the target's console. That fallback is therefore only ever
directed at the process you explicitly chose to profile.

Disable attach traffic entirely if you only want passive map loading:

```bash
sudo probee --auto-java false --tui
```

## What you get today (Phase 1)

| Capability | Status |
|------------|--------|
| Detect HotSpot/`libjvm.so` processes | ✅ automatic |
| **Inject `-XX:+PreserveFramePointer`** when spawning `java` | ✅ automatic |
| **JVM scan at startup** (system-wide) / **scoped to target** (`--pid`) | ✅ automatic |
| **Auto-dump `Compiler.perfmap`** (jcmd / attach / nsenter) | ✅ automatic (JDK 17+) |
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

When a JVM PID is first sampled (and, for system-wide profiling, at startup),
profile-bee:

1. Identifies the JVM (maps `libjvm.so`, or an exact `java`/`javaw` launcher —
   siblings like `javac`/`javadoc` are not treated as launchers)
2. Looks for an existing `/tmp/perf-<pid>.map` (host, NSpid, container root)
3. If missing, tries in order:
   - host `jcmd <pid> Compiler.perfmap`
   - `jcmd` next to the process’s own `java` binary
   - direct HotSpot attach socket (`.java_pid*`, SIGQUIT trigger)
   - `nsenter -t <pid> -m -p` + in-namespace `jcmd` (containers)
4. Loads the map into the JIT symbol cache and refreshes periodically

> **JDK version:** the `Compiler.perfmap` diagnostic command requires
> **JDK 17+**. On JDK 8/11 it fails with *"Unknown diagnostic command"*, so
> auto-dump cannot generate a map — use
> [`perf-map-agent`](https://github.com/jvm-profiling-tools/perf-map-agent) or
> async-profiler to produce `/tmp/perf-<pid>.map`, and profile-bee will load
> it. `-XX:+PreserveFramePointer` (auto-injected on spawn) works on 8u60+.

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

`-XX:+PreserveFramePointer` (JDK 8u60+, usually <1% overhead) keeps RBP as a
real frame pointer in JIT-compiled code so the FP unwinder can walk mixed
native/Java stacks. When you launch the JVM through profile-bee
(`probee -- java …` or `--cmd`), it is **injected automatically** via
`JAVA_TOOL_OPTIONS`; for already-running JVMs you must have started them with
the flag. DWARF mode (`--dwarf`) helps for `libjvm.so` built without FPs.

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
