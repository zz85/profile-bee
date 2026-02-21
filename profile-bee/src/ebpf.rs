use anyhow::anyhow;
use aya::maps::{
    Array, HashMap, InnerMap, MapData, PerCpuArray, PerCpuValues, ProgramArray, RingBuf,
    StackTraceMap,
};
use aya::programs::{
    perf_event::{PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent},
    KProbe, PerfEvent,
};
use aya::programs::{RawTracePoint, TracePoint, UProbe};
use aya::{include_bytes_aligned, util::online_cpus};
use aya::{Btf, Ebpf, EbpfLoader};

use aya::Pod;
use profile_bee_common::{ProcInfo, ProcInfoKey, ProcessExitEvent, UnwindEntry};

// Create a newtype wrapper around StackInfo
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct StackInfoPod(pub profile_bee_common::StackInfo);
unsafe impl Pod for StackInfoPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct FramePointersPod(pub profile_bee_common::FramePointers);
unsafe impl Pod for FramePointersPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct UnwindEntryPod(pub UnwindEntry);
unsafe impl Pod for UnwindEntryPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ProcInfoKeyPod(pub ProcInfoKey);
unsafe impl Pod for ProcInfoKeyPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct ProcInfoPod(pub ProcInfo);
unsafe impl Pod for ProcInfoPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessExitEventPod(pub ProcessExitEvent);
unsafe impl Pod for ProcessExitEventPod {}

/// Wrapper for eBPF stuff
#[derive(Debug)]
pub struct EbpfProfiler {
    pub bpf: Ebpf,
    /// eBPF stacktrace map
    pub stack_traces: StackTraceMap<MapData>,
    /// Count stacktraces
    pub counts: HashMap<MapData, StackInfoPod, u64>,
    /// Custom storage of StackTrace IPs
    pub stacked_pointers: HashMap<MapData, StackInfoPod, FramePointersPod>,
}
/// Legacy configuration for uprobe attachment (single target).
/// Kept for backward compatibility; prefer `ResolvedProbe` for new code.
#[derive(Debug, Clone)]
pub struct UProbeConfig {
    /// Function name (with optional +offset)
    pub function: String,
    /// Path to binary/library (absolute or library name)
    pub path: String,
    /// Whether this is a return probe
    pub is_retprobe: bool,
    /// Optional PID to attach to (None = all processes)
    pub pid: Option<i32>,
}

/// Configuration for the new smart uprobe system.
/// Holds one or more resolved probe targets for multi-attach.
#[derive(Debug, Clone)]
pub struct SmartUProbeConfig {
    /// Resolved probe targets to attach to.
    pub probes: Vec<crate::probe_resolver::ResolvedProbe>,
    /// Optional PID to attach to (None = all processes).
    pub pid: Option<i32>,
}

pub struct ProfilerConfig {
    pub skip_idle: bool,
    pub stream_mode: u8,
    pub frequency: u64,
    pub kprobe: Option<String>,
    /// Legacy single-target uprobe config (backward compat).
    pub uprobe: Option<UProbeConfig>,
    /// New smart uprobe config with multi-attach support.
    pub smart_uprobe: Option<SmartUProbeConfig>,
    pub tracepoint: Option<String>,
    /// Raw tracepoint name for syscall raw_tp (e.g., "sys_enter").
    /// Uses collect_trace_raw_syscall which reads pt_regs from args[0].
    pub raw_tracepoint: Option<String>,
    /// Raw tracepoint name for generic raw_tp with task pt_regs (e.g., "sched_switch").
    /// Uses bpf_get_current_task_btf() + bpf_task_pt_regs() for full FP/DWARF unwinding.
    /// Requires kernel >= 5.15; falls back to raw_tracepoint_generic on older kernels.
    pub raw_tracepoint_task_regs: Option<String>,
    /// Raw tracepoint name for generic raw_tp (e.g., "sched_switch").
    /// Uses collect_trace_raw_tp_generic which relies on bpf_get_stackid only.
    pub raw_tracepoint_generic: Option<String>,
    /// Target syscall number for raw tracepoint filtering (-1 = all).
    pub target_syscall_nr: i64,
    pub pid: Option<u32>,
    pub cpu: Option<u32>,
    pub self_profile: bool,
    pub dwarf: bool,
    /// Enable off-CPU profiling mode (trace context switches, measure blocked time)
    pub off_cpu: bool,
    /// Minimum off-CPU block time in microseconds to record (default 1)
    pub min_block_us: u64,
    /// Maximum off-CPU block time in microseconds to record (default u64::MAX)
    pub max_block_us: u64,
}

/// Creates an aya Ebpf object
pub fn load_ebpf(config: &ProfilerConfig) -> Result<Ebpf, anyhow::Error> {
    // The eBPF object file is selected by build.rs: it uses a freshly-built
    // binary from `cargo xtask build-ebpf` if available, otherwise the prebuilt
    // binary shipped in ebpf-bin/. Either way it ends up in OUT_DIR.
    let data = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/profile-bee.bpf.o"));

    let skip_idle = if config.skip_idle { 1u8 } else { 0u8 };
    let dwarf_enabled = if config.dwarf { 1u8 } else { 0u8 };
    let off_cpu_enabled = if config.off_cpu { 1u8 } else { 0u8 };
    let target_syscall_nr: i64 = config.target_syscall_nr;

    let bpf = EbpfLoader::new()
        .override_global("SKIP_IDLE", &skip_idle, true)
        .override_global("NOTIFY_TYPE", &config.stream_mode, true)
        .override_global("DWARF_ENABLED", &dwarf_enabled, true)
        .override_global("TARGET_SYSCALL_NR", &target_syscall_nr, true)
        .override_global("OFF_CPU_ENABLED", &off_cpu_enabled, true)
        .override_global("MIN_BLOCK_US", &config.min_block_us, true)
        .override_global("MAX_BLOCK_US", &config.max_block_us, true)
        .btf(Btf::from_sys_fs().ok().as_ref())
        .load(data)
        .map_err(|e| {
            println!("{:?}", e);
            e
        })?;

    // // this might be useful for debugging, but definitely disable bpf logging for performance purposes
    // aya_log::EbpfLogger::init(&mut bpf)?;

    Ok(bpf)
}

/// Load the dwarf_unwind_step program and register it in PROG_ARRAY for tail-call
/// DWARF unwinding. Operates on raw `Ebpf` so it can be called both from
/// `setup_ebpf_profiler()` (before attach) and from `EbpfProfiler::setup_tail_call_unwinding()`.
fn setup_tail_call_unwinding_inner(bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    use aya::programs::PerfEvent;

    // Load the step program (but don't attach it to any perf event —
    // it's only invoked via tail call from collect_trace)
    {
        let step_prog: &mut PerfEvent = bpf
            .program_mut("dwarf_unwind_step")
            .ok_or(anyhow!("dwarf_unwind_step program not found"))?
            .try_into()?;
        step_prog.load()?;
    }
    // Mutable borrow released

    // Clone the program FD so we can pass it to ProgramArray::set
    // without conflicting borrows on bpf
    let step_fd = bpf
        .program("dwarf_unwind_step")
        .ok_or(anyhow!("dwarf_unwind_step not found after load"))?
        .fd()?
        .try_clone()?;

    // Register the step program at index 0 of PROG_ARRAY
    let mut prog_array = ProgramArray::try_from(
        bpf.map_mut("prog_array")
            .ok_or(anyhow!("prog_array map not found"))?,
    )?;
    prog_array.set(0, &step_fd, 0)?;

    tracing::info!("Tail-call DWARF unwinding enabled (up to 165 frames)");
    Ok(())
}

pub fn setup_ebpf_profiler(config: &ProfilerConfig) -> Result<EbpfProfiler, anyhow::Error> {
    let mut bpf = load_ebpf(config)?;

    if config.off_cpu {
        // Off-CPU profiling: attach kprobe to finish_task_switch
        let program: &mut KProbe = bpf.program_mut("offcpu_profile").unwrap().try_into()?;
        program.load()?;

        // Try the standard symbol name first, then the .isra.* variant
        // (some kernels compile finish_task_switch with interprocedural
        // scalar replacement of aggregates, renaming the symbol).
        match program.attach("finish_task_switch", 0) {
            Ok(_) => {
                eprintln!("Off-CPU profiling: attached to finish_task_switch");
            }
            Err(e1) => match program.attach("finish_task_switch.isra.0", 0) {
                Ok(_) => {
                    eprintln!("Off-CPU profiling: attached to finish_task_switch.isra.0");
                }
                Err(e2) => {
                    return Err(anyhow!(
                        "Failed to attach off-CPU kprobe to finish_task_switch: {:?}, \
                             also tried finish_task_switch.isra.0: {:?}",
                        e1,
                        e2
                    ));
                }
            },
        }
    } else if let Some(kprobe) = &config.kprobe {
        let program: &mut KProbe = bpf.program_mut("kprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(kprobe, 0)?;
    } else if let Some(smart) = &config.smart_uprobe {
        use aya::programs::uprobe::UProbeAttachLocation;

        // New smart uprobe path: attach to all resolved probe targets
        if smart.probes.is_empty() {
            return Err(anyhow!("no probe targets resolved — nothing to attach"));
        }

        // Separate probes by type (uprobe vs uretprobe)
        let has_uprobe = smart.probes.iter().any(|p| !p.is_ret);
        let has_uretprobe = smart.probes.iter().any(|p| p.is_ret);

        if has_uprobe {
            let program: &mut UProbe = bpf.program_mut("uprobe_profile").unwrap().try_into()?;
            program.load()?;

            for probe in smart.probes.iter().filter(|p| !p.is_ret) {
                let display_name = probe.demangled.as_deref().unwrap_or(&probe.symbol_name);
                eprintln!(
                    "  attaching uprobe: {}:{} (0x{:x})",
                    probe.library_path.display(),
                    display_name,
                    probe.address,
                );
                let point = if probe.offset > 0 {
                    UProbeAttachLocation::SymbolOffset(probe.symbol_name.as_str(), probe.offset)
                } else {
                    UProbeAttachLocation::Symbol(probe.symbol_name.as_str())
                };
                program.attach(point, &probe.library_path, smart.pid.map(|p| p as u32))?;
            }
        }

        if has_uretprobe {
            let program: &mut UProbe = bpf.program_mut("uretprobe_profile").unwrap().try_into()?;
            program.load()?;

            for probe in smart.probes.iter().filter(|p| p.is_ret) {
                let display_name = probe.demangled.as_deref().unwrap_or(&probe.symbol_name);
                eprintln!(
                    "  attaching uretprobe: {}:{} (0x{:x})",
                    probe.library_path.display(),
                    display_name,
                    probe.address,
                );
                let point = if probe.offset > 0 {
                    UProbeAttachLocation::SymbolOffset(probe.symbol_name.as_str(), probe.offset)
                } else {
                    UProbeAttachLocation::Symbol(probe.symbol_name.as_str())
                };
                program.attach(point, &probe.library_path, smart.pid.map(|p| p as u32))?;
            }
        }
    } else if let Some(uprobe_config) = &config.uprobe {
        use aya::programs::uprobe::UProbeAttachLocation;
        use std::path::Path;

        // Choose the right program based on is_retprobe flag
        let program_name = if uprobe_config.is_retprobe {
            "uretprobe_profile"
        } else {
            "uprobe_profile"
        };

        let program: &mut UProbe = bpf.program_mut(program_name).unwrap().try_into()?;
        program.load()?;

        // Parse function name and offset (format: "function_name" or "function_name+offset")
        let (fn_name, offset) = if let Some(plus_pos) = uprobe_config.function.find('+') {
            let (name, offset_str) = uprobe_config.function.split_at(plus_pos);
            let offset = offset_str[1..]
                .parse::<u64>()
                .map_err(|e| anyhow::anyhow!("Invalid offset in uprobe function: {}", e))?;
            (Some(name), offset)
        } else {
            (Some(uprobe_config.function.as_str()), 0)
        };

        let point = match fn_name {
            Some(name) if offset > 0 => UProbeAttachLocation::SymbolOffset(name, offset),
            Some(name) => UProbeAttachLocation::Symbol(name),
            None => UProbeAttachLocation::AbsoluteOffset(offset),
        };

        program.attach(
            point,
            Path::new(&uprobe_config.path),
            uprobe_config.pid.map(|p| p as u32),
        )?;
    } else if let Some(raw_tp) = &config.raw_tracepoint {
        // Pick the correct syscall raw_tp program based on enter vs exit
        let prog_name = if raw_tp == "sys_exit" {
            "raw_tp_sys_exit"
        } else {
            "raw_tp_sys_enter"
        };
        let program: &mut RawTracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
        program.load()?;
        program.attach(raw_tp)?;
    } else if let Some(raw_tp) = &config.raw_tracepoint_task_regs {
        let program: &mut RawTracePoint =
            bpf.program_mut("raw_tp_with_regs").unwrap().try_into()?;
        program.load()?;
        program.attach(raw_tp)?;
    } else if let Some(raw_tp) = &config.raw_tracepoint_generic {
        let program: &mut RawTracePoint = bpf.program_mut("raw_tp_generic").unwrap().try_into()?;
        program.load()?;
        program.attach(raw_tp)?;
    } else if let Some(tracepoint) = &config.tracepoint {
        let program: &mut TracePoint = bpf.program_mut("tracepoint_profile").unwrap().try_into()?;
        program.load()?;

        let mut split = tracepoint.split(':');
        let category = split.next().expect("category");
        let name = split.next().expect("name");

        program.attach(category, name)?;
    } else {
        // Load profile_cpu program first, then release the borrow
        {
            let program: &mut PerfEvent = bpf.program_mut("profile_cpu").unwrap().try_into()?;
            program.load()?;
        }

        // Set up tail-call DWARF unwinding BEFORE attaching perf events.
        // Once attached, samples fire immediately — if PROG_ARRAY isn't populated yet,
        // those samples fall back to the legacy inline DWARF path.
        //
        // NOTE: If more pre-attach setup is needed in the future, consider splitting
        // this function into separate load() and attach() phases (Option B) so callers
        // can do arbitrary setup between program loading and event attachment.
        if config.dwarf {
            match setup_tail_call_unwinding_inner(&mut bpf) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "Warning: tail-call unwinding setup failed, falling back to legacy path: {:?}",
                        e
                    );
                }
            }
        }

        // Re-borrow for attaching
        let program: &mut PerfEvent = bpf.program_mut("profile_cpu").unwrap().try_into()?;

        let perf_config = PerfEventConfig::Software(SoftwareEvent::CpuClock);

        if config.self_profile {
            program.attach(
                perf_config,
                PerfEventScope::CallingProcess { cpu: None },
                SamplePolicy::Frequency(config.frequency),
                true,
            )?;
        } else if config.pid.is_some() || config.cpu.is_some() {
            // When filtering by PID or CPU, attach to all/specific CPUs
            // and let eBPF filter by tgid. This allows profiling child processes.
            let cpus = if let Some(cpu) = config.cpu {
                vec![cpu]
            } else {
                online_cpus().map_err(|(_, error)| error)?
            };

            let nprocs = cpus.len();
            if let Some(pid) = config.pid {
                eprintln!(
                    "Profiling PID {} and child processes across {} CPUs",
                    pid, nprocs
                );
            } else if let Some(cpu) = config.cpu {
                eprintln!("Profiling CPU {}", cpu);
            }

            for cpu in cpus {
                program.attach(
                    perf_config,
                    PerfEventScope::AllProcessesOneCpu { cpu },
                    SamplePolicy::Frequency(config.frequency),
                    true,
                )?;
            }
        } else {
            let cpus = online_cpus().map_err(|(_, error)| error)?;
            let nprocs = cpus.len();
            eprintln!("CPUs: {}", nprocs);

            for cpu in cpus {
                program.attach(
                    perf_config,
                    PerfEventScope::AllProcessesOneCpu { cpu },
                    SamplePolicy::Frequency(config.frequency),
                    true,
                )?;
            }
        }
    }

    let stack_traces = StackTraceMap::try_from(
        bpf.take_map("stack_traces")
            .ok_or(anyhow!("stack_traces not found"))?,
    )?;

    let counts = bpf
        .take_map("counts")
        .ok_or(anyhow!("counts not found"))?
        .try_into()?;

    let stacked_pointers = bpf
        .take_map("stacked_pointers")
        .ok_or(anyhow!("stacked_pointers not found"))?
        .try_into()?;

    Ok(EbpfProfiler {
        bpf,
        stack_traces,
        counts,
        stacked_pointers,
    })
}

pub fn setup_ring_buffer(bpf: &mut Ebpf) -> Result<RingBuf<MapData>, anyhow::Error> {
    let ring_buf = RingBuf::try_from(
        bpf.take_map("RING_BUF_STACKS")
            .ok_or(anyhow!("RING_BUF_STACKS not found"))?,
    )?;

    Ok(ring_buf)
}

pub fn setup_process_exit_ring_buffer(bpf: &mut Ebpf) -> Result<RingBuf<MapData>, anyhow::Error> {
    let ring_buf = RingBuf::try_from(
        bpf.take_map("process_exit_events")
            .ok_or(anyhow!("process_exit_events not found"))?,
    )?;

    Ok(ring_buf)
}

/// Attach the sched_process_exit tracepoint for monitoring process exits
pub fn attach_process_exit_tracepoint(bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    let program: &mut TracePoint = bpf
        .program_mut("tracepoint_process_exit")
        .ok_or(anyhow!("tracepoint_process_exit not found"))?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;
    Ok(())
}

impl EbpfProfiler {
    /// Set the target PID for eBPF filtering (0 = profile all processes)
    pub fn set_target_pid(&mut self, pid: u32) -> Result<(), anyhow::Error> {
        let mut target_pid_map: Array<&mut MapData, u32> = Array::try_from(
            self.bpf
                .map_mut("target_pid_map")
                .ok_or(anyhow!("target_pid_map not found"))?,
        )?;
        target_pid_map.set(0, pid, 0)?;
        Ok(())
    }

    /// Set the PID to monitor for exit events (0 = don't monitor)
    pub fn set_monitor_exit_pid(&mut self, pid: u32) -> Result<(), anyhow::Error> {
        let mut monitor_exit_pid_map: Array<&mut MapData, u32> = Array::try_from(
            self.bpf
                .map_mut("monitor_exit_pid_map")
                .ok_or(anyhow!("monitor_exit_pid_map not found"))?,
        )?;
        monitor_exit_pid_map.set(0, pid, 0)?;
        Ok(())
    }

    /// Load DWARF unwind tables into eBPF maps for a process
    pub fn load_dwarf_unwind_tables(
        &mut self,
        manager: &crate::dwarf_unwind::DwarfUnwindManager,
    ) -> Result<(), anyhow::Error> {
        // Load all shards - using array indexing pattern
        let all_shard_ids: Vec<u8> = (0..manager.binary_tables.len() as u8).collect();
        self.update_dwarf_tables(manager, &all_shard_ids)
    }

    /// Load a single shard's unwind entries by creating a new inner Array map
    /// and inserting it into the outer ArrayOfMaps at `shard_id`.
    fn load_shard(&mut self, shard_id: u8, entries: &[UnwindEntry]) -> Result<(), anyhow::Error> {
        if entries.is_empty() {
            return Ok(());
        }

        // Create and populate a new inner Array map via aya's typed API.
        // Uses MAX_SHARD_ENTRIES to match the eBPF-side template (required on kernel <5.14).
        let inner_array = create_and_populate_inner_map(shard_id, entries)?;

        // Get the outer ArrayOfMaps and insert the inner map's FD
        let mut outer: aya::maps::ArrayOfMaps<&mut MapData> = aya::maps::ArrayOfMaps::try_from(
            self.bpf
                .map_mut("unwind_shards")
                .ok_or(anyhow!("unwind_shards map not found"))?,
        )?;

        outer
            .set(shard_id as u32, inner_array.fd(), 0)
            .map_err(|e| {
                anyhow!(
                    "failed to insert shard_{} into outer ArrayOfMaps: {}",
                    shard_id,
                    e
                )
            })?;

        // inner_array is dropped here — the kernel holds a reference to the inner map
        // via the outer ArrayOfMaps, so the inner map stays alive.
        Ok(())
    }

    /// Incrementally update eBPF maps with new unwind shard entries,
    /// and refresh all proc_info entries.
    pub fn update_dwarf_tables(
        &mut self,
        manager: &crate::dwarf_unwind::DwarfUnwindManager,
        new_shard_ids: &[u8],
    ) -> Result<(), anyhow::Error> {
        if !new_shard_ids.is_empty() {
            let mut total_entries = 0usize;
            for &shard_id in new_shard_ids {
                // Array of maps pattern: use get() for safe access
                if let Some(entries) = manager.binary_tables.get(shard_id as usize) {
                    self.load_shard(shard_id, entries)?;
                    total_entries += entries.len();
                    tracing::info!("Loaded shard {} with {} entries", shard_id, entries.len());
                }
            }

            tracing::info!(
                "Loaded {} total unwind entries across {} shards",
                total_entries,
                new_shard_ids.len()
            );
        }

        let mut proc_info_map: HashMap<&mut MapData, ProcInfoKeyPod, ProcInfoPod> =
            HashMap::try_from(
                self.bpf
                    .map_mut("proc_info")
                    .ok_or(anyhow!("proc_info map not found"))?,
            )?;

        for (&tgid, proc_info) in &manager.proc_info {
            let key = ProcInfoKeyPod(ProcInfoKey { tgid, _pad: 0 });
            let value = ProcInfoPod(*proc_info);
            proc_info_map.insert(key, value, 0)?;

            tracing::info!(
                "Loaded process info for tgid {} ({} mappings)",
                tgid,
                proc_info.mapping_count,
            );
        }

        Ok(())
    }

    /// Set up tail-call unwinding: load the dwarf_unwind_step program and register
    /// it in PROG_ARRAY so the eBPF collect_trace can tail-call into it for deep
    /// DWARF stack unwinding (up to 165 frames vs 21 with legacy inline loop).
    ///
    /// Note: For perf_event programs, this is now called automatically inside
    /// `setup_ebpf_profiler()` before attaching events. This method remains public
    /// for kprobe/uprobe/tracepoint callers that need it separately.
    pub fn setup_tail_call_unwinding(&mut self) -> Result<(), anyhow::Error> {
        setup_tail_call_unwinding_inner(&mut self.bpf)
    }

    /// Read DWARF unwinding diagnostics from the dwarf_stats PerCpuArray map.
    /// Returns the total tail-call fallback count across all CPUs, or None if
    /// the map doesn't exist (e.g., DWARF not enabled).
    pub fn read_dwarf_stats(&mut self) -> Option<u64> {
        let map = self.bpf.map_mut("dwarf_stats")?;
        let stats: PerCpuArray<&mut MapData, u64> = PerCpuArray::try_from(map).ok()?;
        let values: PerCpuValues<u64> = stats.get(&0, 0).ok()?;
        let total: u64 = values.iter().sum();
        Some(total)
    }
}

/// Create a new BPF_MAP_TYPE_ARRAY map suitable as an inner map for the
/// unwind_shards ArrayOfMaps, and populate it with the provided entries.
///
/// Uses aya's typed `Array::create()` API instead of raw bpf() syscalls.
/// The map is always created with `MAX_SHARD_ENTRIES` slots (matching the
/// eBPF-side template) because kernel <5.14 requires inner maps to have
/// exactly the same `max_entries` as the template used when creating the
/// outer ArrayOfMaps.
///
/// TODO: On kernel 5.14+ the max_entries restriction is relaxed (commit 134fede4eecf).
/// A runtime feature probe could detect this: create a throwaway ArrayOfMaps with
/// template max_entries=1, try inserting an inner map with max_entries=2 — if it
/// succeeds, use right-sized inner maps to save memory. Until then, every inner
/// map is allocated at the fixed maximum size.
///
/// The kernel only needs the inner map's FD to persist as long as it's
/// referenced from the outer ArrayOfMaps; once inserted there, the returned
/// Array handle (and its FD) can be dropped (the kernel holds its own reference).
pub fn create_and_populate_inner_map(
    shard_id: u8,
    entries: &[UnwindEntry],
) -> Result<aya::maps::Array<MapData, UnwindEntryPod>, anyhow::Error> {
    if entries.is_empty() {
        return Err(anyhow!("cannot create inner map with zero entries"));
    }

    // Always use fixed size to match the eBPF-side template (required on kernel <5.14).
    let max_entries = profile_bee_common::MAX_SHARD_ENTRIES;

    let mut inner: aya::maps::Array<MapData, UnwindEntryPod> =
        aya::maps::Array::create(max_entries, 0)
            .map_err(|e| anyhow!("failed to create inner Array for shard_{}: {}", shard_id, e))?;

    // Populate the inner map with unwind entries
    for (idx, entry) in entries.iter().enumerate() {
        inner
            .set(idx as u32, UnwindEntryPod(*entry), 0)
            .map_err(|e| anyhow!("failed to populate shard_{} index {}: {}", shard_id, idx, e))?;
    }

    Ok(inner)
}
