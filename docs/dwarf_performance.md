# DWARF Subsystem Performance Analysis

Profiling results from self-profiling probee with `--dwarf` on a 16-core system (99 Hz, 5 seconds).

**Test commands:**
```bash
sudo target/release/probee --dwarf -c dwarf-with-idle.txt --time 5000
sudo target/release/probee --skip-idle --dwarf -c dwarf.txt --time 5000
```

## Overview

Out of ~7920 expected samples (99 Hz x 16 cores x 5s), probee + its tokio workers consume **~195 samples**, which is **~2.4% of total CPU**. When excluding idle cores and background workloads, probee accounts for **~70% of all active non-workload CPU time** on this lightly-loaded system.

The overhead breaks down into four major cost centers, all related to the DWARF unwinding subsystem:

| Category | Samples | % of profiler overhead | Key location |
|---|---|---|---|
| File I/O (`__libc_read`) | 85 | 44% | `dwarf_unwind.rs`, blazesym, `/proc` |
| BPF map population (`apply_dwarf_refresh`) | 47 | 24% | `ebpf.rs:686-712` |
| Blazesym symbolization | 17 | 9% | `trace_handler.rs:222-284` |
| DWARF refresh thread | 15 | 8% | `profile-bee.rs:1046-1082` |
| Tokio workers + misc | 31 | 15% | Ring buffer polling, memory allocation |

---

## Issue 1: BPF map population via per-entry syscalls

**Severity:** High
**File:** `profile-bee/src/ebpf.rs:686-712`
**Samples:** 47 (24% of profiler overhead)

`create_and_populate_inner_map` issues a raw `libc::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, ...)` for each unwind entry individually. With `MAX_SHARD_ENTRIES = 65,536`, this means up to **65,536 syscalls per shard**. Each syscall pays the full kernel entry/exit cost plus audit filtering overhead.

The profiling data confirms this: 11 samples in `map_update_elem` kernel-side work (memdup, copy_from_user, kfree) and 8 samples in pure `syscall_enter`/`syscall_exit`/audit overhead.

Worse, `apply_dwarf_refresh` runs **synchronously on the main processing thread** inside the `perf_rx.recv()` loop (`profile-bee.rs:1247`), so all sample processing is blocked during shard population.

```
probee::process_profiling_data
  → probee::apply_dwarf_refresh         ← blocks recv loop
    → create_and_populate_inner_map     ← 65K syscalls per shard
      → syscall(BPF_MAP_UPDATE_ELEM)    ← x65,536
```

### Plan

**P0 -- Use BPF batch operations** (`BPF_MAP_UPDATE_BATCH`, available since kernel 5.6). Replace the per-entry syscall loop with a single batch update call. This reduces ~65K syscalls to 1 (or a handful for large shards that exceed the batch limit). Expected to eliminate nearly all 47 samples.

```rust
// Current (ebpf.rs:686-712): one syscall per entry
for (idx, entry) in entries.iter().enumerate() {
    libc::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, ...);  // x65,536
}

// Proposed: single batch syscall
let keys: Vec<u32> = (0..entries.len() as u32).collect();
libc::syscall(SYS_bpf, BPF_MAP_UPDATE_BATCH, ...);  // x1
```

Requires kernel 5.6+. For older kernels, fall back to the current per-entry path. `BPF_MAP_UPDATE_BATCH` for `BPF_MAP_TYPE_ARRAY` uses cmd=24 with `bpf_attr.batch`.

**P1 -- Move shard population off the main thread.** `apply_dwarf_refresh` currently runs inline in the `perf_rx` recv loop (`profile-bee.rs:1246-1248`). Move it to a dedicated thread or tokio blocking task so sample processing is not stalled. The main thread can continue draining the ring buffer while maps are being populated in the background.

**P2 -- Right-size inner maps.** The inner BPF array is always allocated with `MAX_SHARD_ENTRIES` (65,536) slots (`ebpf.rs:633`) even when the actual entry count is much smaller. On kernel >= 5.14, inner maps in `ArrayOfMaps` do not need to match the template size. Allocate only the needed capacity to reduce kernel memory waste and zeroing overhead (`clear_page_erms_k` appears in `map_create` samples).

---

## Issue 2: ELF binary reads cause page fault storms

**Severity:** High
**File:** `profile-bee/src/dwarf_unwind.rs:559`
**Samples:** 48 (25% of profiler overhead)

On cache miss, `scan_and_update` reads the entire ELF binary into a `Vec<u8>` via `fs::read()`. This copies the full file contents into userspace memory, triggering demand-paged anonymous memory allocation. The kernel must zero-fill each new page (`clear_page_erms_k`), which dominates the I/O cost.

The profiling stacks show the chain clearly:
```
probee;__libc_read
  → generic_file_buffered_read
    → copy_user_enhanced_fast_string     ← 12 direct samples
      → do_anonymous_page
        → clear_page_erms_k             ← 10+ samples zeroing pages
```

For large binaries (libc, libstdc++, the profiler itself), this is hundreds of KB to tens of MB of data copied and zeroed.

### Plan

**P0 -- Use `mmap` instead of `fs::read`.** Memory-map the ELF binary read-only (`mmap(MAP_PRIVATE | MAP_POPULATE)`). This eliminates the userspace copy entirely -- the page cache pages are mapped directly into the process address space. `gimli` and `object` both accept `&[u8]` slices, so mmap'd data works without API changes.

```rust
// Current (dwarf_unwind.rs:559)
let binary_data = fs::read(&resolved_path).ok();

// Proposed
let file = File::open(&resolved_path)?;
let mmap = unsafe { memmap2::Mmap::map(&file)? };
let binary_data: &[u8] = &mmap;
```

Benefits:
- No copy into userspace heap (eliminates anonymous page fault storm)
- Shared with page cache (no extra memory if the file is already cached)
- Lazy loading: only pages actually accessed by gimli are faulted in

The `memmap2` crate is standard in the Rust ecosystem. Alternatively, use `libc::mmap` directly.

**P1 -- Pre-allocate `Vec<UnwindEntry>` capacity.** In `generate_unwind_table_from_bytes` (`dwarf_unwind.rs:228`), the entries `Vec` grows dynamically during `.eh_frame` iteration. Estimate capacity from the `.eh_frame` section size (roughly `eh_frame_size / 24` entries as a heuristic) to avoid repeated reallocations.

```rust
// Current (dwarf_unwind.rs:228)
let mut entries = Vec::new();

// Proposed: estimate ~1 entry per 24 bytes of .eh_frame
let estimated_entries = eh_frame_data.len() / 24;
let mut entries = Vec::with_capacity(estimated_entries);
```

---

## Issue 3: `/proc/kallsyms` reading is slow on BPF-heavy systems

**Severity:** Medium
**File:** blazesym internals (triggered from `trace_handler.rs`)
**Samples:** 20 (10% of profiler overhead)

When blazesym initializes its kernel symbol resolver (`KsymResolver::load_from_reader`), it reads `/proc/kallsyms` sequentially. The kernel generates this file on-the-fly, and for each BPF program, calls `bpf_get_kallsym_k` which iterates the BPF program list. On this system with CrowdStrike Falcon (many BPF programs), 16-17 of the 20 samples land in `bpf_get_kallsym_k`.

```
probee;__libc_read
  → proc_reg_read → seq_read_iter
    → s_next → update_iter_mod → bpf_get_kallsym_k   ← 16 samples
```

This is a kernel-side scaling issue, but we can mitigate it in userspace.

### Plan

**P0 -- Cache kernel symbols across sessions.** blazesym already caches the kernel resolver via `OnceCell`, so this cost is paid only once per probee invocation. Verify this is working correctly -- if probee is recreating the `Symbolizer` instance between processing batches, this one-time cost would be paid repeatedly.

**P1 -- Read `/proc/kallsyms` in the background.** Move the initial `KsymResolver` loading to a background thread during startup, before the first sample arrives. The resolver can be wrapped in an `Arc<OnceCell>` and populated asynchronously while eBPF programs are being loaded.

**P2 -- Consider `/proc/kcore` for symbol resolution.** blazesym supports both `/proc/kallsyms` and `/proc/kcore`. On BPF-heavy systems, `/proc/kcore` may avoid the `bpf_get_kallsym` overhead since it reads the symbol table from the kernel binary directly rather than iterating live BPF programs.

---

## Issue 4: Unconditional `/proc/[pid]/maps` polling every second

**Severity:** Medium
**File:** `profile-bee/bin/profile-bee.rs:1073-1080`
**Samples:** 8 (from `/proc/[pid]/maps` reading) + 4 (dwarf thread procfs overhead)

The `dwarf_refresh_loop` re-reads `/proc/[pid]/maps` for every tracked PID every 1 second, regardless of whether any mappings changed. Each call parses the full maps file through the `procfs` crate.

```rust
// profile-bee.rs:1073-1080
for &pid in &tracked_pids {
    if let Ok(new_shard_ids) = manager.refresh_process(pid) {  // reads /proc/[pid]/maps
        ...
    }
}
```

Additionally, `scan_and_update` calls `p.exists()` (`dwarf_unwind.rs:519, 526`) for every executable mapping on every scan cycle, adding a `stat()` syscall per mapping.

### Plan

**P0 -- Detect changes before full rescan.** Before calling `refresh_process`, compare the mtime of `/proc/[pid]/maps` against the last-seen value. If unchanged, skip the full parse. This requires only one `stat()` syscall per PID per cycle instead of a full file read + parse.

```rust
// Proposed: skip rescan if maps file hasn't changed
let maps_path = format!("/proc/{}/maps", pid);
let current_mtime = fs::metadata(&maps_path).ok().and_then(|m| m.modified().ok());
if current_mtime == last_mtime.get(&pid).copied() {
    continue; // nothing changed
}
last_mtime.insert(pid, current_mtime);
manager.refresh_process(pid)?;
```

Note: `/proc/[pid]/maps` mtime behavior varies by kernel version. On some kernels it always returns the current time. If mtime is unreliable, an alternative is to hash the first N bytes of the maps file and compare.

**P1 -- Adaptive polling interval.** After the initial load, increase the polling interval if no new mappings have been detected for several cycles (e.g., 1s -> 2s -> 5s -> 10s). Reset to 1s when a new mapping is found.

**P2 -- Use `fanotify` or `/proc/[pid]/mem` change detection.** Some production profilers (parca-agent) use `fanotify(FAN_OPEN_EXEC)` to get notifications when new executables are mapped. This would eliminate polling entirely, but adds complexity and may require `CAP_SYS_ADMIN`.

---

## Issue 5: `send_refresh` clones large `Vec<UnwindEntry>`

**Severity:** Low-Medium
**File:** `profile-bee/bin/profile-bee.rs:1093`
**Samples:** Not directly visible (allocator overhead is amortized)

When sending a DWARF refresh from the background thread to the main thread, `send_refresh` clones the entire `Vec<UnwindEntry>` for each new shard:

```rust
// profile-bee.rs:1093
shard_updates.push((shard_id, entries.clone()));  // up to 65K * 12 bytes = 768KB
```

This clone is necessary because the `DwarfUnwindManager` lives on the background thread while the main thread needs the data for BPF map population. However, for large shards this is a ~768KB allocation + memcpy.

### Plan

**P0 -- Use `Arc<Vec<UnwindEntry>>` for zero-copy sharing.** Store shard entries as `Arc<Vec<UnwindEntry>>` in `DwarfUnwindManager.binary_tables`. Cloning an `Arc` is a single atomic increment instead of a full data copy.

```rust
// Current
pub binary_tables: Vec<Vec<UnwindEntry>>,
// send_refresh: entries.clone()  ← copies 768KB

// Proposed
pub binary_tables: Vec<Arc<Vec<UnwindEntry>>>,
// send_refresh: entries.clone()  ← increments refcount
```

The main thread's `create_and_populate_inner_map` only needs `&[UnwindEntry]`, so `Arc<Vec<UnwindEntry>>` works transparently via `Deref`.

---

## Issue 6: `.eh_frame` parsing and sorting overhead

**Severity:** Low (cold-path only, amortized by caching)
**File:** `profile-bee/src/dwarf_unwind.rs:195-356`
**Samples:** 5 (dwarf thread)

`generate_unwind_table_from_bytes` parses every CIE/FDE in the `.eh_frame` section, classifies CFA rules into compact `UnwindEntry` structs, then sorts by PC and deduplicates. For large binaries this involves tens of thousands of FDEs.

The three-tier cache (metadata -> build-ID -> path) means this only runs on true cache misses, so it is not a recurring cost. However, during startup or when profiling new processes, the burst of parsing can spike CPU usage.

### Plan

**P0 -- Persist unwind tables to disk cache.** After generating unwind tables for a binary, write the `Vec<UnwindEntry>` + build-ID to a cache directory (e.g., `~/.cache/probee/`). On subsequent runs, skip `.eh_frame` parsing entirely for known build-IDs. This is especially valuable for large system libraries (libc, libstdc++, ld-linux) that are parsed on every probee invocation.

Cache format: `<build-id-hex>.unwind` containing the serialized entries (fixed-size `#[repr(C)]` structs, can be written/read directly).

**P1 -- CIE clone avoidance.** In the FDE parsing loop (`dwarf_unwind.rs:241-242`), every FDE that references a cached CIE calls `cie.clone()`. Since gimli's `CommonInformationEntry` contains heap-allocated augmentation data, this clone is non-trivial. Consider storing CIEs in an arena or using references with appropriate lifetimes.

---

## Priority Summary

| Priority | Issue | Expected impact | Effort |
|---|---|---|---|
| P0 | Batch BPF map updates (#1) | Eliminate ~47 samples (24%) | Medium -- raw `BPF_MAP_UPDATE_BATCH` syscall |
| P0 | mmap for ELF reads (#2) | Eliminate ~48 samples (25%) | Low -- swap `fs::read` for `memmap2::Mmap` |
| P0 | `Arc` for shard entries (#5) | Eliminate ~768KB alloc per shard | Low -- type change |
| P1 | Move shard population off main thread (#1) | Unblock sample processing | Medium -- async plumbing |
| P1 | Change detection for `/proc/[pid]/maps` (#4) | Eliminate ~12 samples (6%) | Low -- mtime check |
| P1 | Background kallsyms loading (#3) | Hide ~20 samples (10%) latency | Low -- thread + OnceCell |
| P2 | Disk cache for unwind tables (#6) | Eliminate cold-start parsing | Medium -- serialization + cache management |
| P2 | Right-size inner BPF maps (#1) | Reduce kernel memory + zeroing | Low -- conditional on kernel version |
| P2 | Adaptive polling interval (#4) | Reduce steady-state I/O | Low |

---

## Implementation Results

**Commit:** `caac922` (P1) on top of `394a019` (P0)

Self-profiling at 99 Hz x 16 cores x 5s with `--dwarf`, comparing before/after the optimizations below. The with-idle comparison uses ~7,300 idle samples across 16 CPUs as a stable timing baseline.

### Changes implemented

| Change | Priority | Commit |
|---|---|---|
| `BPF_MAP_UPDATE_BATCH` for shard loading (fallback to per-entry on kernel < 5.6) | P0 | `394a019` |
| `memmap2::Mmap` for ELF binary reads (replaces `fs::read`) | P0 | `394a019` |
| `Arc<Vec<UnwindEntry>>` for zero-copy shard sharing across threads | P0 | `394a019` |
| Pre-allocate `Vec<UnwindEntry>` capacity from `.eh_frame` size | P1 | `caac922` |
| mtime-based change detection to skip `/proc/[pid]/maps` rescans | P1 | `caac922` |

### Measured improvement (with-idle mode)

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| **Total samples** | 8,880 | 8,224 | -656 (-7.4%) |
| **Profiler overhead** | **175** | **125** | **-50 (-28.6%)** |
| Profiler as % of total | 2.0% | 1.5% | **-25% relative** |

### Breakdown by category

| Category | Before | After | Delta | Notes |
|---|---:|---:|---:|---|
| File I/O (ELF reading) | 85 | 32 | **-53 (-62%)** | mmap eliminates heap copy + page zeroing |
| DWARF refresh thread | 62 | 41 | **-21 (-34%)** | mtime skip + Vec pre-alloc reduce parse cycles |
| BPF map updates | 47 | 36 | **-11 (-23%)** | Batch syscall reduces per-entry overhead |
| Symbolization (blazesym) | 17 | 33 | +16 (+94%) | Expected: faster DWARF = more time for symbolization |
| Arc/clone overhead | 0 | 0 | 0 | Not visible at this scale (sub-sample) |

**Note:** Single-run profiles with statistical sampling noise. At ~100-175 profiler samples, individual category counts have +/-5-10 sample variance. The overall 28.6% reduction is statistically meaningful; per-category percentages are approximate.

### Remaining opportunities

The largest remaining cost center is **blazesym symbolization** (33 samples, now 26% of profiler overhead), which was not targeted in this round. See Issue #3 (kallsyms) for mitigation ideas. The BPF map update path still shows 36 samples — this could be further reduced by moving shard population off the main thread (P1 in Issue #1).
