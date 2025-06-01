# Profile-Bee Architecture Diagram

Below is a diagram showing the relationships between the main public structs in the profile-bee codebase:

```
                                +----------------+
                                |    Profiler    |
                                +----------------+
                                | - symbols      |
                                | - cache        |
                                +-------+--------+
                                        |
                                        | manages
                                        v
         +-------------------------+    |    +-------------------------+
         |    PointerStackFrames   |<---+---->|     SymbolFinder       |
         |         Cache           |         +-------------------------+
         +-------------------------+         | - ksyms                 |
         | - map: (i32,i32) -> Vec |         | - obj_cache             |
         |   of StackFrameInfo     |         | - addr_cache            |
         +-------------------------+         | - process_cache         |
                                            | - use_dwarf             |
                                            +------------+------------+
                                                         |
                                                         | uses
                    +--------------------------------+   |   +----------------+
                    |                                |<--+-->|   AddrCache    |
                    v                                |       +----------------+
        +------------------------+                   |       | - map: (i32,u64)|
        |      ProcessCache      |<------------------+       |   -> StackFrame |
        +------------------------+                           +----------------+
        | - map: usize -> Process|
        |        Info            |
        +----------+-------------+
                   |
                   | contains
                   v
        +------------------------+
        |      ProcessInfo       |
        +------------------------+
        | - process              |
        | - environ              |
        | - cmdline              |
        | - stat                 |
        | - cwd                  |
        | - ns                   |
        | - mapper               |
        | - exe_link             |
        +----------+-------------+
                   |
                   | uses
                   v
        +------------------------+
        |     ProcessMapper      |
        +------------------------+
        | - maps                 |
        +------------------------+
                   |
                   | resolves
                   v
        +------------------------+
        |     StackFrameInfo     |
        +------------------------+
        | - pid                  |
        | - cmd                  |
        | - address              |
        | - object_path          |
        | - symbol               |
        | - source               |
        | - cpu_id               |
        | - ns                   |
        +------------------------+
                   ^
                   |
                   | contains
        +------------------------+
        |      FrameCount        |
        +------------------------+
        | - frames               |
        | - count                |
        +------------------------+

        +------------------------+
        |      StackInfo         |
        +------------------------+
        | - tgid                 |
        | - user_stack_id        |
        | - kernel_stack_id      |
        | - cmd                  |
        | - cpu                  |
        +------------------------+
```

## Component Descriptions

1. **Profiler**: Main entry point for the profiler that manages symbol resolution and caching for efficient stack trace processing and visualization.

2. **SymbolFinder**: Handles resolving memory addresses to human-readable symbols and source locations using kernel symbols, debug information, and binary analysis.

3. **PointerStackFramesCache**: Maps kernel and user stack trace IDs to fully resolved stack frame information to avoid repeated expensive symbol resolution.

4. **AddrCache**: Maps memory addresses to resolved stack frame information to avoid expensive symbol resolution for addresses seen multiple times.

5. **ProcessCache**: Caches process information to avoid repeated expensive lookups of process details from the /proc filesystem.

6. **ProcessInfo**: Holds metadata about a running process including environment variables, command line, working directory, and memory mappings.

7. **ProcessMapper**: Maps virtual memory addresses to physical addresses and associated binary files by analyzing process memory maps.

8. **StackFrameInfo**: Represents a single frame in a stack trace with information about its memory address, associated binary, symbol name, and source location.

9. **FrameCount**: Container for stack frame information with count, used to track how many times a particular stack trace appears in the profile data.

10. **StackInfo**: Contains the process ID, stack trace IDs for both kernel and user stacks, process name, and CPU ID for a single stack sample collected by the profiler.

## Data Flow

1. The eBPF program collects stack traces and creates `StackInfo` objects.
2. The `Profiler` receives these and uses `SymbolFinder` to resolve symbols.
3. `SymbolFinder` uses various caches (`AddrCache`, `ProcessCache`) to efficiently resolve symbols.
4. `ProcessMapper` helps translate virtual addresses to physical addresses and associated binaries.
5. Resolved stack frames are stored as `StackFrameInfo` objects.
6. `FrameCount` tracks how many times each stack trace appears.
7. The resolved data is then used to generate flamegraphs or other visualizations.
