# Java Profiling

Profile-bee samples HotSpot JVM processes from eBPF, preserving kernel and
native JVM frames. Launching a JVM through profile-bee enables
`-XX:+PreserveFramePointer` through `JAVA_TOOL_OPTIONS`:

```bash
sudo probee --dwarf -o profile.svg -- java -jar service.jar
```

This option preserves frame-pointer-based native stack traversal. It does not
turn anonymous HotSpot code-cache addresses into Java method names.

## JIT symbols

The process symbolizer accepts the standard perf-map convention:
`/tmp/perf-<pid>.map`. A compatible JVMTI agent can emit current code-cache
entries in that file as:

```text
<hex-address> <hex-size> <method-name>
```

When the map is present, profile-bee resolves its JIT entries through the same
process-symbolization path used for Node.js. A missing map results in an
explicit warning for `--pid`; native and kernel frames remain usable, while
compiled Java methods are `[unknown]`.

## JVMTI boundary

Perf maps provide compiled-method names but cannot represent interpreted
frames, inlined methods, or reliable code-cache invalidation by themselves.
Accurate Java stacks require an optional in-process JVMTI companion that
receives compiled-method load/unload notifications and captures Java frames at
safe points. That agent is intentionally not bundled in profile-bee yet:
HotSpot private-structure walking must be maintained and tested per supported
JDK version.

The intended hybrid arrangement is eBPF sampling for system, kernel, and
native frames, plus JVMTI-supplied Java frames correlated by JVM thread and
sample time. It avoids attempting to decode arbitrary HotSpot internals from
eBPF.
