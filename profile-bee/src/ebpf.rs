use std::os::fd::{AsFd, AsRawFd};

use anyhow::{anyhow, Result};
use aya::maps::lpm_trie::{Key as LpmKey, LpmTrie};
use aya::maps::{
    Array, CreatableMap, HashMap, IterableMap, MapData, PerCpuArray, PerCpuValues, ProgramArray,
    RingBuf, StackTraceMap,
};
use aya::programs::{
    perf_event::{PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent},
    KProbe, PerfEvent,
};
use aya::programs::{RawTracePoint, TracePoint, UProbe};
use aya::{include_bytes_aligned, util::online_cpus};
use aya::{Btf, Ebpf, EbpfLoader};

use aya::Pod;
use profile_bee_common::{ExecMapping, ExecMappingKey, ProcessExitEvent, UnwindEntry, V8ProcInfo};

use crate::dwarf_unwind::{summarize_address_range, DwarfUnwindManager, MappingsDiff};

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
pub struct ExecMappingKeyPod(pub ExecMappingKey);
unsafe impl Pod for ExecMappingKeyPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct ExecMappingPod(pub ExecMapping);
unsafe impl Pod for ExecMappingPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessExitEventPod(pub ProcessExitEvent);
unsafe impl Pod for ProcessExitEventPod {}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct V8ProcInfoPod(pub V8ProcInfo);
unsafe impl Pod for V8ProcInfoPod {}

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
            tracing::error!("Failed to load eBPF program: {:?}", e);
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

    // Register the DWARF step program at index 0 of PROG_ARRAY
    let mut prog_array = ProgramArray::try_from(
        bpf.map_mut("prog_array")
            .ok_or(anyhow!("prog_array map not found"))?,
    )?;
    prog_array.set(0, &step_fd, 0)?;

    tracing::info!("Tail-call DWARF unwinding enabled (up to 165 frames)");
    Ok(())
}

/// Load the fp_v8_unwind_step program and register it at PROG_ARRAY index 1
/// for tail-call FP walking with V8 SFI extraction. Called unconditionally
/// (not gated on DWARF mode) because the FP+V8 path runs in the NON-DWARF
/// branch of collect_trace.
fn setup_fp_v8_tail_call(bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
    use aya::programs::PerfEvent;

    {
        let fp_v8_prog: &mut PerfEvent = bpf
            .program_mut("fp_v8_unwind_step")
            .ok_or(anyhow!("fp_v8_unwind_step program not found"))?
            .try_into()?;
        fp_v8_prog.load()?;
    }
    let fp_v8_fd = bpf
        .program("fp_v8_unwind_step")
        .ok_or(anyhow!("fp_v8_unwind_step not found after load"))?
        .fd()?
        .try_clone()?;

    let mut prog_array = ProgramArray::try_from(
        bpf.map_mut("prog_array")
            .ok_or(anyhow!("prog_array map not found"))?,
    )?;
    prog_array.set(1, &fp_v8_fd, 0)?;

    tracing::info!("Tail-call FP+V8 walking enabled (up to 165 frames with V8 SFI)");
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
                tracing::info!("Off-CPU profiling: attached to finish_task_switch");
            }
            Err(e1) => match program.attach("finish_task_switch.isra.0", 0) {
                Ok(_) => {
                    tracing::info!("Off-CPU profiling: attached to finish_task_switch.isra.0");
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
                tracing::info!(
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
                tracing::info!(
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
        if config.dwarf {
            match setup_tail_call_unwinding_inner(&mut bpf) {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        "Tail-call unwinding setup failed, falling back to legacy path: {:?}",
                        e
                    );
                }
            }
        }

        // Always register the FP+V8 tail-call program (PROG_ARRAY index 1).
        // This runs in the NON-DWARF path of collect_trace, so it must be
        // available regardless of whether DWARF mode is enabled.
        match setup_fp_v8_tail_call(&mut bpf) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    "FP+V8 tail-call setup failed, falling back to inline FP path: {:?}",
                    e
                );
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
                tracing::info!(
                    "Profiling PID {} and child processes across {} CPUs",
                    pid,
                    nprocs
                );
            } else if let Some(cpu) = config.cpu {
                tracing::info!("Profiling CPU {}", cpu);
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
            tracing::info!("Profiling across {} CPUs", nprocs);

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

/// Set up the ring buffer for process exec events.
/// Returns `Ok(None)` if the eBPF binary doesn't include the exec map
/// (backward compat with older eBPF builds).
pub fn setup_process_exec_ring_buffer(
    bpf: &mut Ebpf,
) -> Result<Option<RingBuf<MapData>>, anyhow::Error> {
    match bpf.take_map("process_exec_events") {
        Some(map) => Ok(Some(RingBuf::try_from(map)?)),
        None => {
            tracing::debug!("process_exec_events map not found (older eBPF binary)");
            Ok(None)
        }
    }
}

/// Attach the sched_process_exec tracepoint for monitoring process exec events.
/// Returns `Ok(false)` if the eBPF binary doesn't include the exec program
/// (backward compat with older eBPF builds).
pub fn attach_process_exec_tracepoint(bpf: &mut Ebpf) -> Result<bool, anyhow::Error> {
    let program = match bpf.program_mut("tracepoint_process_exec") {
        Some(p) => p,
        None => {
            tracing::debug!("tracepoint_process_exec not found (older eBPF binary)");
            return Ok(false);
        }
    };
    let tp: &mut TracePoint = program.try_into()?;
    tp.load()?;
    tp.attach("sched", "sched_process_exec")?;
    tracing::info!("attached sched_process_exec tracepoint");
    Ok(true)
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

    /// Enable or disable process lifecycle tracking in eBPF.
    /// When enabled, exit events fire for all processes (not just DWARF-tracked
    /// or monitored PIDs).
    pub fn set_lifecycle_tracking(&mut self, enabled: bool) -> Result<(), anyhow::Error> {
        match self.bpf.map_mut("lifecycle_tracking_map") {
            Some(map) => {
                let mut arr: Array<&mut MapData, u32> = Array::try_from(map)?;
                arr.set(0, if enabled { 1 } else { 0 }, 0)?;
                Ok(())
            }
            None => {
                tracing::debug!("lifecycle_tracking_map not found (older eBPF binary)");
                Ok(())
            }
        }
    }

    /// Load V8 introspection data for a Node.js process into the eBPF map.
    ///
    /// When the eBPF FP walker encounters this PID, it will read the V8 FP
    /// context using the offsets in `V8ProcInfo` to extract the JSFunction →
    /// SharedFunctionInfo pointer for each frame.
    pub fn load_v8_proc_info(&mut self, tgid: u32, info: &V8ProcInfo) -> Result<(), anyhow::Error> {
        match self.bpf.map_mut("v8_proc_info") {
            Some(map) => {
                let mut v8_map: HashMap<&mut MapData, u32, V8ProcInfoPod> = HashMap::try_from(map)?;
                v8_map.insert(tgid, V8ProcInfoPod(*info), 0)?;
                tracing::debug!(
                    "loaded V8ProcInfo for pid {} (version={:#x}, JSFunction types [{}, {}])",
                    tgid,
                    info.version,
                    info.type_jsfunction_first,
                    info.type_jsfunction_last,
                );
                Ok(())
            }
            None => {
                tracing::debug!("v8_proc_info map not found (older eBPF binary)");
                Ok(())
            }
        }
    }

    /// Remove V8 introspection data for a process that exited.
    pub fn remove_v8_proc_info(&mut self, tgid: u32) -> Result<(), anyhow::Error> {
        match self.bpf.map_mut("v8_proc_info") {
            Some(map) => {
                let mut v8_map: HashMap<&mut MapData, u32, V8ProcInfoPod> = HashMap::try_from(map)?;
                let _ = v8_map.remove(&tgid); // ignore error if not present
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Load DWARF unwind tables into eBPF maps for a process
    pub fn load_dwarf_unwind_tables(
        &mut self,
        manager: &crate::dwarf_unwind::DwarfUnwindManager,
    ) -> Result<(), anyhow::Error> {
        // Load all shards - using array indexing pattern
        let all_shard_ids: Vec<u16> = (0..manager.binary_tables.len() as u16).collect();
        self.update_dwarf_tables(manager, &all_shard_ids)
    }

    /// Load a single shard's unwind entries by creating a new inner Array map
    /// and inserting it into the outer ArrayOfMaps at `shard_id`.
    fn load_shard(&mut self, shard_id: u16, entries: &[UnwindEntry]) -> Result<(), anyhow::Error> {
        if entries.is_empty() {
            return Ok(());
        }

        // Create and populate a new inner Array map via aya's typed API.
        // Uses MAX_SHARD_ENTRIES to match the eBPF-side template (required on kernel <5.14).
        let inner_array = create_and_populate_inner_map(shard_id, entries)?;

        // Get the outer ArrayOfMaps and insert the inner map's FD
        let mut outer: aya::maps::ArrayOfMaps<
            &mut MapData,
            aya::maps::Array<MapData, UnwindEntryPod>,
        > = aya::maps::ArrayOfMaps::try_from(
            self.bpf
                .map_mut("unwind_shards")
                .ok_or(anyhow!("unwind_shards map not found"))?,
        )?;

        outer.set(shard_id as u32, &inner_array, 0).map_err(|e| {
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
    /// and refresh exec_mappings LPM trie for all processes.
    pub fn update_dwarf_tables(
        &mut self,
        manager: &crate::dwarf_unwind::DwarfUnwindManager,
        new_shard_ids: &[u16],
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

        // Populate exec_mappings LPM trie for all processes
        let mut trie: LpmTrie<&mut MapData, ExecMappingKeyPod, ExecMappingPod> = LpmTrie::try_from(
            self.bpf
                .map_mut("exec_mappings")
                .ok_or(anyhow!("exec_mappings map not found"))?,
        )?;

        let mut total_lpm_entries = 0usize;
        for (&tgid, mappings) in &manager.proc_mappings {
            for mapping in mappings {
                debug_assert!(
                    mapping.end > mapping.begin,
                    "Invalid mapping range for tgid {}: begin={:#x} end={:#x}",
                    tgid,
                    mapping.begin,
                    mapping.end,
                );
                for block in crate::dwarf_unwind::summarize_address_range(
                    mapping.begin,
                    mapping.end.saturating_sub(1),
                ) {
                    let key = LpmKey::new(
                        64 + block.prefix_len,
                        ExecMappingKeyPod(ExecMappingKey {
                            tgid: tgid.to_be(),
                            _pad: 0,
                            address: block.addr.to_be(),
                        }),
                    );
                    trie.insert(&key, ExecMappingPod(*mapping), 0)?;
                    total_lpm_entries += 1;
                }
            }
        }

        tracing::info!(
            "Loaded {} LPM trie entries for {} processes",
            total_lpm_entries,
            manager.proc_mappings.len(),
        );

        // Populate dwarf_tgids map so BPF exit handler knows which processes to track
        if let Some(map) = self.bpf.map_mut("dwarf_tgids") {
            if let Ok(mut dwarf_tgids) =
                aya::maps::HashMap::<&mut aya::maps::MapData, u32, u8>::try_from(map)
            {
                for &tgid in manager.proc_mappings.keys() {
                    let _ = dwarf_tgids.insert(tgid, 1, 0);
                }
            }
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
        Self::read_dwarf_stats_from_bpf(&mut self.bpf)
    }

    /// Read DWARF tail-call fallback stats from a raw `Ebpf` handle.
    ///
    /// This is a static method so it can be called from `ProfilingEventLoop`
    /// which owns the `Ebpf` handle after consuming the profiler.
    pub fn read_dwarf_stats_from_bpf(bpf: &mut Ebpf) -> Option<u64> {
        let map = bpf.map_mut("dwarf_stats")?;
        let stats: PerCpuArray<&mut MapData, u64> = PerCpuArray::try_from(map).ok()?;
        let values: PerCpuValues<u64> = stats.get(&0, 0).ok()?;
        let total: u64 = values.iter().sum();
        Some(total)
    }
}

/// BPF command number for BPF_MAP_UPDATE_BATCH (kernel 5.6+).
/// Note: 24=LOOKUP_BATCH, 25=LOOKUP_AND_DELETE_BATCH, 26=UPDATE_BATCH, 27=DELETE_BATCH
const BPF_MAP_UPDATE_BATCH: libc::c_ulong = 26;

/// Try to batch-populate a BPF array map using BPF_MAP_UPDATE_BATCH.
/// Returns Ok(()) on success, Err on failure (e.g., kernel < 5.6).
fn batch_populate_inner_map(
    inner: &aya::maps::Array<MapData, UnwindEntryPod>,
    entries: &[UnwindEntry],
) -> Result<(), anyhow::Error> {
    if entries.is_empty() {
        return Ok(());
    }

    let fd = inner.map().fd().as_fd().as_raw_fd();

    // Build contiguous key array [0, 1, 2, ..., n-1]
    let keys: Vec<u32> = (0..entries.len() as u32).collect();

    // Build contiguous value array (UnwindEntryPod is #[repr(transparent)])
    let values: Vec<UnwindEntryPod> = entries.iter().map(|e| UnwindEntryPod(*e)).collect();

    let count = entries.len() as u32;

    // bpf_attr for batch update — matches the kernel's union bpf_attr { struct { batch } }.
    #[repr(C)]
    #[derive(Default)]
    struct BpfAttrBatch {
        in_batch: u64,   // NULL for update
        out_batch: u64,  // unused for update
        keys: u64,       // pointer to keys array
        values: u64,     // pointer to values array
        count: u32,      // in: number of entries to update, out: number updated
        map_fd: u32,     // fd of the map
        elem_flags: u64, // BPF_ANY = 0
        flags: u64,      // 0
    }

    let mut attr = BpfAttrBatch {
        keys: keys.as_ptr() as u64,
        values: values.as_ptr() as u64,
        count,
        map_fd: fd as u32,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_BATCH,
            &mut attr as *mut BpfAttrBatch,
            std::mem::size_of::<BpfAttrBatch>(),
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!(
            "BPF_MAP_UPDATE_BATCH failed: errno={} (updated {} of {} entries)",
            errno,
            attr.count,
            count,
        ));
    }

    Ok(())
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
/// Population uses BPF_MAP_UPDATE_BATCH (single syscall, kernel 5.6+) with
/// automatic fallback to per-entry updates for older kernels.
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
    shard_id: u16,
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

    // Try batch update first (single syscall, kernel 5.6+)
    match batch_populate_inner_map(&inner, entries) {
        Ok(()) => {
            tracing::debug!(
                "shard_{}: batch-loaded {} entries in single syscall",
                shard_id,
                entries.len()
            );
        }
        Err(batch_err) => {
            // Fall back to per-entry updates (kernel < 5.6)
            tracing::debug!(
                "shard_{}: batch update unavailable ({}), falling back to per-entry",
                shard_id,
                batch_err,
            );
            for (idx, entry) in entries.iter().enumerate() {
                inner
                    .set(idx as u32, UnwindEntryPod(*entry), 0)
                    .map_err(|e| {
                        anyhow!("failed to populate shard_{} index {}: {}", shard_id, idx, e)
                    })?;
            }
        }
    }

    Ok(inner)
}

/// Incremental DWARF unwind table update.
/// Each shard update is a (shard_id, entries) pair for a newly-loaded binary.
pub struct DwarfRefreshUpdate {
    pub shard_updates: Vec<(u16, std::sync::Arc<Vec<UnwindEntry>>)>,
    pub mapping_diffs: Vec<MappingsDiff>,
}

/// Build a `DwarfRefreshUpdate` from new shard IDs and a mapping diff,
/// cloning only the new shard entries (not the entire binary_tables).
///
/// Uses the [`DwarfUnwindManager`]'s `binary_tables`, `new_shard_ids`, and
/// [`MappingsDiff`] to construct a [`DwarfRefreshUpdate`].
///
/// Returns `Some(DwarfRefreshUpdate)` when there is a change, or `None`
/// when nothing changed (no new shards and the diff is empty).
pub fn build_dwarf_refresh(
    manager: &DwarfUnwindManager,
    new_shard_ids: &[u16],
    diff: MappingsDiff,
) -> Option<DwarfRefreshUpdate> {
    let mut shard_updates = Vec::new();
    for &shard_id in new_shard_ids {
        if let Some(entries) = manager.binary_tables.get(shard_id as usize) {
            shard_updates.push((shard_id, std::sync::Arc::clone(entries)));
        }
    }

    let total_entries: usize = shard_updates.iter().map(|(_, v)| v.len()).sum();
    tracing::debug!(
        "DWARF refresh: tgid={}, {} new shards ({} entries), +{} -{} mappings",
        diff.tgid,
        new_shard_ids.len(),
        total_entries,
        diff.added.len(),
        diff.removed.len(),
    );

    if shard_updates.is_empty() && diff.is_empty() {
        return None; // Nothing to do
    }

    Some(DwarfRefreshUpdate {
        shard_updates,
        mapping_diffs: vec![diff],
    })
}

/// Apply incremental DWARF unwind table updates to eBPF maps.
///
/// Updates three maps:
/// 1. `unwind_shards` ArrayOfMaps — creates inner arrays, inserts into outer map
/// 2. `exec_mappings` LPM trie — removes stale entries, inserts new ones
/// 3. `dwarf_tgids` HashMap — registers/unregisters processes for exit tracking
pub fn apply_dwarf_refresh(bpf: &mut Ebpf, update: DwarfRefreshUpdate) -> Result<()> {
    let mut failures: usize = 0;

    // Create inner maps and insert them into the outer ArrayOfMaps
    if !update.shard_updates.is_empty() {
        // First, create all inner maps (doesn't borrow bpf)
        let mut created_maps = Vec::new();
        for (shard_id, entries) in &update.shard_updates {
            if entries.is_empty() {
                continue;
            }
            match create_and_populate_inner_map(*shard_id, entries) {
                Ok(inner_array) => {
                    created_maps.push((*shard_id, inner_array));
                }
                Err(e) => {
                    tracing::warn!("DWARF refresh: failed to create shard_{}: {}", shard_id, e);
                    failures += 1;
                }
            }
        }

        // Then, get the outer ArrayOfMaps and insert all inner maps
        if !created_maps.is_empty() {
            if let Some(map) = bpf.map_mut("unwind_shards") {
                match aya::maps::ArrayOfMaps::<
                    &mut MapData,
                    Array<MapData, UnwindEntryPod>,
                >::try_from(map)
                {
                    Ok(mut outer) => {
                        for (shard_id, inner_array) in &created_maps {
                            if let Err(e) = outer.set(*shard_id as u32, inner_array, 0) {
                                tracing::warn!(
                                    "DWARF refresh: failed to insert shard_{} into outer map: {}",
                                    shard_id,
                                    e
                                );
                                failures += 1;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("DWARF refresh: unwind_shards is not ArrayOfMaps: {}", e);
                        failures += created_maps.len();
                    }
                }
            } else {
                tracing::warn!("DWARF refresh: unwind_shards map not found");
                failures += created_maps.len();
            }
        }
        // created_maps dropped; kernel holds references via the outer map
    }

    if let Some(map) = bpf.map_mut("exec_mappings") {
        if let Ok(mut trie) =
            LpmTrie::<&mut MapData, ExecMappingKeyPod, ExecMappingPod>::try_from(map)
        {
            for diff in &update.mapping_diffs {
                let tgid = diff.tgid;

                // Remove stale entries first
                for mapping in &diff.removed {
                    for block in
                        summarize_address_range(mapping.begin, mapping.end.saturating_sub(1))
                    {
                        let key = LpmKey::new(
                            64 + block.prefix_len,
                            ExecMappingKeyPod(ExecMappingKey {
                                tgid: tgid.to_be(),
                                _pad: 0,
                                address: block.addr.to_be(),
                            }),
                        );
                        // Removal failure is non-fatal (entry may already be gone)
                        let _ = trie.remove(&key);
                    }
                }

                // Insert new entries
                for mapping in &diff.added {
                    for block in
                        summarize_address_range(mapping.begin, mapping.end.saturating_sub(1))
                    {
                        let key = LpmKey::new(
                            64 + block.prefix_len,
                            ExecMappingKeyPod(ExecMappingKey {
                                tgid: tgid.to_be(),
                                _pad: 0,
                                address: block.addr.to_be(),
                            }),
                        );
                        if let Err(e) = trie.insert(&key, ExecMappingPod(*mapping), 0) {
                            tracing::warn!(
                                "LPM trie insert failed: tgid={}, mapping=[{:#x},{:#x}), block addr={:#x} prefix_len={}: {}",
                                tgid,
                                mapping.begin,
                                mapping.end,
                                block.addr,
                                block.prefix_len,
                                e,
                            );
                            failures += 1;
                        }
                    }
                }
            }
        } else {
            tracing::warn!("DWARF refresh: exec_mappings is not LpmTrie");
            failures += 1;
        }
    } else if update.mapping_diffs.iter().any(|d| !d.is_empty()) {
        tracing::warn!("DWARF refresh: exec_mappings map not found");
        failures += 1;
    }

    // Update dwarf_tgids BPF map: add tgids with new mappings, remove exited tgids
    if let Some(map) = bpf.map_mut("dwarf_tgids") {
        if let Ok(mut dwarf_tgids) = HashMap::<&mut MapData, u32, u8>::try_from(map) {
            for diff in &update.mapping_diffs {
                if !diff.added.is_empty() {
                    // Process has (new) DWARF data — register for exit tracking
                    let _ = dwarf_tgids.insert(diff.tgid, 1, 0);
                }
                if diff.is_exit {
                    // Process exited — stop tracking for exit notifications
                    let _ = dwarf_tgids.remove(&diff.tgid);
                }
            }
        } else {
            tracing::warn!("DWARF refresh: dwarf_tgids is not HashMap");
            failures += 1;
        }
    } else if update
        .mapping_diffs
        .iter()
        .any(|d| !d.added.is_empty() || d.is_exit)
    {
        tracing::warn!("DWARF refresh: dwarf_tgids map not found");
        failures += 1;
    }

    if failures > 0 {
        anyhow::bail!("DWARF refresh completed with {} failure(s)", failures);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint / syscall utilities and fallback setup
// ---------------------------------------------------------------------------

/// Parse a syscall tracepoint name like "syscalls:sys_enter_write" into
/// a raw tracepoint name ("sys_enter") and syscall NR.
/// Returns None if this is not a syscall tracepoint.
///
/// Only `sys_enter_*` tracepoints are handled here because the raw
/// tracepoint args layout exposes the syscall NR in `args[1]`, which
/// the eBPF program uses for filtering.  `sys_exit_*` raw tracepoints
/// put the *return value* in `args[1]` (not the NR), so routing them
/// through the raw-tp + NR-filter path would silently break filtering.
/// Returning None for sys_exit lets the caller fall through to the
/// generic tracepoint / perf-event attachment path instead.
#[cfg(target_arch = "x86_64")]
pub fn parse_syscall_tracepoint(tp: &str) -> Option<(&str, i64)> {
    let (category, name) = tp.split_once(':')?;

    if category != "syscalls" {
        return None;
    }

    // sys_enter_write -> raw_tp="sys_enter", syscall="write"
    // sys_exit_* is intentionally NOT matched — see doc comment above.
    let syscall_name = name.strip_prefix("sys_enter_")?;

    let nr = syscall_name_to_nr(syscall_name)?;
    Some(("sys_enter", nr))
}

/// Map x86_64 syscall name to its number.
/// Based on Linux x86_64 syscall table (stable ABI).
#[cfg(target_arch = "x86_64")]
pub fn syscall_name_to_nr(name: &str) -> Option<i64> {
    // Common syscalls — extend as needed
    let nr = match name {
        "read" => 0,
        "write" => 1,
        "open" => 2,
        "close" => 3,
        "stat" => 4,
        "fstat" => 5,
        "lstat" => 6,
        "poll" => 7,
        "lseek" => 8,
        "mmap" => 9,
        "mprotect" => 10,
        "munmap" => 11,
        "brk" => 12,
        "ioctl" => 16,
        "pread64" => 17,
        "pwrite64" => 18,
        "readv" => 19,
        "writev" => 20,
        "access" => 21,
        "pipe" => 22,
        "select" => 23,
        "sched_yield" => 24,
        "dup" => 32,
        "dup2" => 33,
        "nanosleep" => 35,
        "getpid" => 39,
        "socket" => 41,
        "connect" => 42,
        "accept" => 43,
        "sendto" => 44,
        "recvfrom" => 45,
        "sendmsg" => 46,
        "recvmsg" => 47,
        "bind" => 49,
        "listen" => 50,
        "clone" => 56,
        "fork" => 57,
        "vfork" => 58,
        "execve" => 59,
        "exit" => 60,
        "wait4" => 61,
        "kill" => 62,
        "fcntl" => 72,
        "flock" => 73,
        "fsync" => 74,
        "fdatasync" => 75,
        "getcwd" => 79,
        "chdir" => 80,
        "rename" => 82,
        "mkdir" => 83,
        "rmdir" => 84,
        "creat" => 85,
        "link" => 86,
        "unlink" => 87,
        "readlink" => 89,
        "chmod" => 90,
        "chown" => 92,
        "getuid" => 102,
        "getgid" => 104,
        "geteuid" => 107,
        "getegid" => 108,
        "getppid" => 110,
        "getpgrp" => 111,
        "setsid" => 112,
        "sigaltstack" => 131,
        "statfs" => 137,
        "fstatfs" => 138,
        "prctl" => 157,
        "arch_prctl" => 158,
        "gettid" => 186,
        "futex" => 202,
        "getdents64" => 217,
        "clock_gettime" => 228,
        "exit_group" => 231,
        "epoll_wait" => 232,
        "epoll_ctl" => 233,
        "openat" => 257,
        "newfstatat" => 262,
        "accept4" => 288,
        "epoll_pwait" => 281,
        "pipe2" => 293,
        "preadv" => 295,
        "pwritev" => 296,
        "getrandom" => 318,
        "execveat" => 322,
        "copy_file_range" => 326,
        "preadv2" => 327,
        "pwritev2" => 328,
        "io_uring_setup" => 425,
        "io_uring_enter" => 426,
        "io_uring_register" => 427,
        "clone3" => 435,
        "close_range" => 436,
        "openat2" => 437,
        _ => return None,
    };
    Some(nr)
}

/// Stub for non-x86_64 architectures — syscall NR mapping not available.
#[cfg(not(target_arch = "x86_64"))]
pub fn parse_syscall_tracepoint(_tp: &str) -> Option<(&str, i64)> {
    None
}

/// Stub for non-x86_64 architectures — syscall NR mapping not available.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_name_to_nr(_name: &str) -> Option<i64> {
    None
}

/// Extract the tracepoint name from "category:name" format for raw_tp attachment.
/// For raw tracepoints, the name is just the event name without the category.
pub fn parse_tracepoint_name(tp: &str) -> Option<&str> {
    tp.split(':').nth(1)
}

/// Set up eBPF profiler with automatic raw tracepoint fallback.
///
/// For ALL tracepoints, this tries attaching via `RawTracePoint`
/// (which uses `bpf_raw_tracepoint_open` and bypasses BPF LSM restrictions
/// on `PERF_EVENT_IOC_SET_BPF`). If that fails, it falls back to the
/// regular `TracePoint` attachment.
///
/// Fallback chain for non-syscall tracepoints:
///   1. raw_tp with task pt_regs (kernel >= 5.15, full FP/DWARF unwinding)
///   2. raw_tp generic (bpf_get_stackid only)
///   3. perf TracePoint (legacy, may be blocked by BPF LSM)
///
/// For syscall tracepoints (syscalls:sys_enter_* only):
///   1. raw_tp sys_enter with NR filtering (pt_regs from args[0], syscall NR via args[1])
///   2. raw_tp sys_enter with task pt_regs (no per-syscall filtering, full unwinding)
///   3. raw_tp sys_enter generic (bpf_get_stackid only)
///   4. perf TracePoint (legacy)
///
/// Note: the aggregate raw tracepoint name ("sys_enter") is used for ALL
/// raw_tp fallback attempts, since per-syscall names like "sys_enter_write"
/// don't exist as raw tracepoints.
/// sys_exit_* is NOT routed here — see parse_syscall_tracepoint.
pub fn setup_ebpf_with_tp_fallback(
    config: &mut ProfilerConfig,
) -> Result<EbpfProfiler, anyhow::Error> {
    if let Some(tp) = config.tracepoint.clone() {
        // Determine the raw tracepoint name to use for fallback attempts.
        let (raw_tp_name, syscall_info) =
            if let Some((raw_tp, syscall_nr)) = parse_syscall_tracepoint(&tp) {
                (raw_tp.to_string(), Some(syscall_nr))
            } else if let Some(name) = parse_tracepoint_name(&tp) {
                (name.to_string(), None)
            } else {
                // No parseable tracepoint name — skip raw_tp attempts entirely
                return setup_ebpf_profiler(config);
            };

        // For syscall tracepoints, first try the syscall-specific raw_tp
        if let Some(syscall_nr) = syscall_info {
            let tp_saved = config.tracepoint.take();
            config.raw_tracepoint = Some(raw_tp_name.clone());
            config.target_syscall_nr = syscall_nr;

            match setup_ebpf_profiler(config) {
                Ok(profiler) => {
                    tracing::info!(
                        "Attached via raw tracepoint '{}' (syscall nr={})",
                        raw_tp_name,
                        syscall_nr
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    tracing::info!(
                        "Raw tracepoint (syscall) failed ({}), trying task_pt_regs...",
                        e
                    );
                    config.raw_tracepoint = None;
                    config.target_syscall_nr = -1;
                    config.tracepoint = tp_saved;
                }
            }
        }

        // Try raw_tp with task pt_regs (kernel >= 5.15, full unwinding)
        {
            let tp_saved = config.tracepoint.take();
            config.raw_tracepoint_task_regs = Some(raw_tp_name.clone());

            match setup_ebpf_profiler(config) {
                Ok(profiler) => {
                    tracing::info!(
                        "Attached via raw tracepoint '{}' (task pt_regs, full unwinding)",
                        raw_tp_name
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    tracing::info!(
                        "Raw tracepoint with task_pt_regs failed ({}), trying generic...",
                        e
                    );
                    config.raw_tracepoint_task_regs = None;
                    config.tracepoint = tp_saved;
                }
            }
        }

        // Try generic raw_tp (bpf_get_stackid only, no custom unwinding)
        {
            let tp_saved = config.tracepoint.take();
            config.raw_tracepoint_generic = Some(raw_tp_name.clone());

            match setup_ebpf_profiler(config) {
                Ok(profiler) => {
                    tracing::info!(
                        "Attached via generic raw tracepoint '{}' (stackid only)",
                        raw_tp_name
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    tracing::info!(
                        "Generic raw tracepoint failed ({}), falling back to perf tracepoint...",
                        e
                    );
                    config.raw_tracepoint_generic = None;
                    config.tracepoint = tp_saved;
                }
            }
        }
    }

    // Final fallback: use config as-is (regular TracePoint or other program type)
    setup_ebpf_profiler(config)
}
