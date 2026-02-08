# DWARF Stack Unwinding: Literature Review & Improvement Plan

## Background

Most Linux binaries are compiled without frame pointers (`-fomit-frame-pointer` is the default at `-O2`+). This breaks the simple linked-list stack walk that `bpf_get_stackid()` relies on. The `.eh_frame` ELF section — originally for C++ exception handling — contains DWARF Call Frame Information (CFI) that describes how to restore registers at every program counter. It's present in virtually all ELF binaries, even pure C ones.

## Literature & Prior Art

### Elastic / Prodfiler (now OTel eBPF Profiler)

- **Source**: [Elastic blog post](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf), [GitHub](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
- **Patented**: [US11604718B1](https://patents.google.com/patent/US11604718B1/en)

Pioneered `.eh_frame`-based unwinding from eBPF in 2019 (launched as Prodfiler in 2021). The eBPF code detects executables compiled without frame pointers and notifies userspace. Userspace parses `.eh_frame`, converts DWARF CFI into a compact lookup structure, and loads it back into BPF maps. Key characteristics:

- System-wide profiling with dynamic process discovery
- Full DWARF expression VM support
- Multi-runtime: native + JVM + Python + Ruby + PHP + Node.js + .NET + Perl + Erlang
- ARM64 support
- Native inline frame resolution
- Production-proven at 10K+ core scale since 2021

### Parca Agent

- **Source**: [Polar Signals blog post](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf), [GitHub](https://github.com/parca-dev/parca-agent)

Open-source DWARF-based eBPF unwinder (Go). Architecture:

1. Userspace parses `.eh_frame`, evaluates DWARF CFI state machine, produces a flat sorted table
2. Table loaded into BPF array map; per-process mapping info into hash map
3. eBPF binary-searches the table, computes CFA, reads return address via `bpf_probe_read_user`

Notable design choices:

- **Compact 8-byte row**: `u64 pc, u16 reserved, u8 cfa_type, u8 rbp_type, i16 cfa_offset, i16 rbp_offset` — uses `i16` offsets since most real-world offsets fit in 16 bits
- **Hardcodes 2 most common DWARF expressions** (covering >50% of expression-based entries) rather than skipping all expressions
- System-wide profiling with dynamic process discovery
- Snapshot testing of unwind tables against known-good outputs for correctness

### INRIA Paper: "Reliable and Fast DWARF-Based Stack Unwinding" (OOPSLA'19)

- **Source**: [ACM DL](https://dl.acm.org/doi/10.1145/3360572), Bastian et al.

Key contributions:

- **Validation**: Fixed-point control flow analysis to verify that compiler-generated `.eh_frame` tables are correct. Found real bugs in GCC and LLVM unwind table generation.
- **Synthesis**: Generate unwind tables from object code when `.eh_frame` is missing or broken — useful as a fallback for stripped binaries.
- Comprehensive description of the DWARF CFI format and its interaction with x86_64 ABI.
- Demonstrated that unwind table correctness is not guaranteed — compilers do produce incorrect entries.

### Converged Architecture

All three production systems converge on the same high-level design:

```
Userspace:  parse .eh_frame → evaluate DWARF CFI → flat table (PC → CFA/RA/RBP rules)
                                    ↓
BPF maps:   Array<UnwindEntry> + HashMap<pid, ProcInfo>
                                    ↓
eBPF:       binary search table → compute CFA → bpf_probe_read_user(RA) → loop
```

## Profile-Bee's Current Implementation

### Active Path (`dwarf_unwind.rs` + eBPF `lib.rs`)

Follows the Parca architecture:

- `DwarfUnwindManager` parses `/proc/[pid]/maps`, reads `.eh_frame` via `gimli`, generates `Vec<UnwindEntry>` sorted by PC
- `UnwindEntry` is **32 bytes**: `u64 pc` + `u8 cfa_type` + 3 pad + `i32 cfa_offset` + `u8 ra_type` + 3 pad + `i32 ra_offset` + `u8 rbp_type` + 3 pad + `i32 rbp_offset`
- Loaded into BPF `Array<UnwindEntry>` (max 250K entries) + `HashMap<ProcInfoKey, ProcInfo>`
- eBPF: `dwarf_copy_stack()` does linear mapping scan (max 8), binary search (max 16 iterations), CFA computation, `bpf_probe_read_user` for RA/RBP, up to 32 frames
- Falls back to FP-based `copy_stack()` if no proc_info found for the tgid

### Dead Code: `unwinder/` Module

An earlier, incomplete iteration that should be removed:

- `unwinder/ehframe.rs`: Parses `.eh_frame` into `UnwindTableRow` with `Instruction` types
- `unwinder/maps.rs`: Reads `/proc/[pid]/maps` via `procmaps` crate
- `unwinder/mod.rs`: Flattens into `DwarfUnwindInfo` with `DwarfDelta` (`i8` offsets — far too small for real use)
- Has commented-out BPF walk code; `find_instruction()` is incomplete
- Uses different common types (`DwarfDelta`, `DwarfUnwindInfo`) from the active path

## Comparison with Production Systems

| Aspect | Profile-Bee | Parca Agent | OTel eBPF Profiler |
|--------|------------|-------------|-------------------|
| Row size | 32 bytes (i32 + padding) | 8 bytes (i16, packed) | ~similar to Parca |
| DWARF expressions | Skipped entirely | 2 most common hardcoded | Full support |
| Scope | Single process only | System-wide, dynamic | System-wide, dynamic |
| Max mappings/process | 8 | Dynamic | Dynamic |
| Max table entries | 250K global | Dynamic (sharded) | Dynamic |
| Signal trampolines | Not handled | Handled | Handled |
| Architecture | x86_64 only | x86_64 + arm64 | x86_64 + arm64 |
| dlopen support | None | Dynamic reload | Dynamic reload |
| Inline frames | No | No | Yes |
| Runtime support | Native only | Native only | Native + 8 HLL runtimes |
| Binary cache key | File path | Build ID | File ID |

## Improvement Plan

### High Impact, Lower Effort

#### 1. Compact UnwindEntry to ~12 bytes

Parca uses `i16` offsets and packs to 8 bytes. Profile-bee's 32-byte entries waste 4x BPF map memory. Most real-world CFA/RA/RBP offsets fit in `i16`. Proposed layout:

```rust
#[repr(C, packed)]
pub struct UnwindEntry {
    pub pc: u64,        // 8 bytes
    pub cfa_offset: i16, // 2 bytes
    pub rbp_offset: i16, // 2 bytes
    pub cfa_type: u8,    // 1 byte
    pub rbp_type: u8,    // 1 byte
}                        // 14 bytes (RA is always CFA-8 on x86_64)
```

This would fit 4x more entries in the same budget, or reduce memory from 7.6MB to ~2MB.

#### 2. Handle the 2 Most Common DWARF Expressions

Currently all `CFA_REG_EXPRESSION` entries are skipped. Parca found two specific expressions cover >50% of expression-based rows (typically in glibc). Implementing these would improve coverage for system libraries.

#### 3. Remove Dead `unwinder/` Module

Remove `unwinder/ehframe.rs`, `unwinder/maps.rs`, `unwinder/mod.rs`, and the `DwarfDelta`/`DwarfUnwindInfo` types from `profile-bee-common`. They're unused dead code from an earlier iteration with `i8` offsets that can't represent real-world values.

#### 4. Handle Signal Trampolines (vDSO `__restore_rt`)

When a signal interrupts execution, the kernel pushes a signal frame. Without special handling, unwinding stops at the signal trampoline. Both Parca and OTel handle this by detecting the vDSO sigreturn address and manually stepping over the signal frame.

#### 5. Fix `copy_stack()` Early Return Bug

The FP-based `copy_stack()` in `profile-bee-ebpf/src/lib.rs` has a `return (ip, bp, 1, sp);` before the actual frame-walking loop (line ~186), making FP unwinding always return depth 1. This means non-DWARF mode is effectively broken.

### Medium Impact, Medium Effort

#### 6. System-Wide DWARF Profiling

Currently limited to `--pid`/`--cmd`. The eBPF program could notify userspace of newly-seen tgids via ring buffer, triggering on-demand unwind table loading (the Elastic/Prodfiler approach).

#### 7. Dynamic Library Hot-Loading (dlopen)

Monitor `/proc/[pid]/maps` periodically or use `mmap`/`munmap` tracepoints to detect new mappings. Reload unwind tables for newly loaded shared libraries.

#### 8. Build-ID Based Caching

Use ELF build IDs instead of file paths as cache keys. Handles container environments where the same binary appears at different paths, and avoids re-parsing when the same library is loaded by multiple processes.

#### 9. Increase MAX_PROC_MAPS

8 mappings is tight. A typical process has main binary + libc + ld-linux + libpthread + libm + libgcc_s + libstdc++ + more, easily exceeding 8. Bumping to 16-32 would cover most real-world cases.

#### 10. Unwind Table Validation

Per the INRIA paper, compiler-generated `.eh_frame` tables can have bugs. A validation pass (checking CFA offset monotonicity within functions, RA always at CFA-8 for x86_64, etc.) would catch corrupt entries before loading them into eBPF.

### Lower Priority, Higher Effort

#### 11. ARM64 Support

Different register constants and CFA rules, but the same overall architecture.

#### 12. Inline Frame Resolution

Use `.debug_info` to resolve inline function boundaries for more accurate flamegraphs of optimized code.

#### 13. Sharded Unwind Tables

Replace the single global 250K-entry array with per-binary or per-mapping tables. Removes the global limit and enables profiling very large binaries (Chrome, Firefox).

## Recommended Priority

The most impactful quick wins:

1. **Remove dead code** (#3) — immediate cleanup, no risk
2. **Fix FP unwinding bug** (#5) — one-line fix, restores non-DWARF functionality
3. **Compact UnwindEntry** (#1) — 4x memory efficiency improvement
4. **Expression support** (#2) — better stack quality for glibc-heavy workloads
5. **Signal trampolines** (#4) — deeper stacks through signal handlers

## References

1. [Polar Signals: DWARF-based Stack Walking Using eBPF](https://www.polarsignals.com/blog/posts/2022/11/29/dwarf-based-stack-walking-using-ebpf)
2. [Elastic: How Universal Profiling unwinds stacks without frame pointers](https://www.elastic.co/blog/universal-profiling-frame-pointers-symbols-ebpf)
3. [Bastian et al.: Reliable and Fast DWARF-Based Stack Unwinding (OOPSLA'19)](https://dl.acm.org/doi/10.1145/3360572)
4. [OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
5. [Parca Agent](https://github.com/parca-dev/parca-agent)
6. [Ian Lance Taylor: .eh_frame](https://www.airs.com/blog/archives/460)
7. [MaskRay: Stack unwinding](https://maskray.me/blog/2020-11-08-stack-unwinding)
8. [corsix.org: ELF .eh_frame](https://www.corsix.org/content/elf-eh-frame)
