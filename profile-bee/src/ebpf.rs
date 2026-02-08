use anyhow::anyhow;
use aya::maps::{Array, HashMap, MapData, RingBuf, StackTraceMap};
use aya::programs::{
    perf_event::{PerfEventScope, PerfTypeId, SamplePolicy},
    KProbe, PerfEvent,
};
use aya::programs::{TracePoint, UProbe};
use aya::{include_bytes_aligned, util::online_cpus};
use aya::{Btf, Ebpf, EbpfLoader};

use aya::Pod;
use profile_bee_common::{UnwindEntry, ProcInfo, ProcInfoKey};

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
pub struct DwarfUnwindInfoPod(pub profile_bee_common::DwarfUnwindInfo);
unsafe impl Pod for DwarfUnwindInfoPod {}

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
pub struct ProfilerConfig {
    pub skip_idle: bool,
    pub stream_mode: u8,
    pub frequency: u64,
    pub kprobe: Option<String>,
    pub uprobe: Option<String>,
    pub tracepoint: Option<String>,
    pub pid: Option<u32>,
    pub cpu: Option<u32>,
    pub self_profile: bool,
    pub dwarf: bool,
}

/// Creates an aya Ebpf object
pub fn load_ebpf(config: &ProfilerConfig) -> Result<Ebpf, anyhow::Error> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/profile-bee");
    #[cfg(not(debug_assertions))]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/profile-bee");

    let skip_idle = if config.skip_idle { 1u8 } else { 0u8 };
    let dwarf_enabled = if config.dwarf { 1u8 } else { 0u8 };

    let bpf = EbpfLoader::new()
        .set_global("SKIP_IDLE", &skip_idle, true)
        .set_global("NOTIFY_TYPE", &config.stream_mode, true)
        .set_global("DWARF_ENABLED", &dwarf_enabled, true)
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

pub fn setup_ebpf_profiler(config: &ProfilerConfig) -> Result<EbpfProfiler, anyhow::Error> {
    let mut bpf = load_ebpf(config)?;

    if let Some(kprobe) = &config.kprobe {
        let program: &mut KProbe = bpf.program_mut("kprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(kprobe, 0)?;
    } else if let Some(uprobe) = &config.uprobe {
        let program: &mut UProbe = bpf.program_mut("uprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(Some(uprobe), 0, "libc", None)?;
    } else if let Some(tracepoint) = &config.tracepoint {
        let program: &mut TracePoint = bpf.program_mut("tracepoint_profile").unwrap().try_into()?;
        program.load()?;

        let mut split = tracepoint.split(':');
        let category = split.next().expect("category");
        let name = split.next().expect("name");

        program.attach(category, name)?;
    } else {
        let program: &mut PerfEvent = bpf.program_mut("profile_cpu").unwrap().try_into()?;

        program.load()?;

        // https://elixir.bootlin.com/linux/v4.2/source/include/uapi/linux/perf_event.h#L103
        const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

        // could change this to Hardware if your system supports
        // `lscpu | grep -i pmu`
        let perf_type = PerfTypeId::Software;

        if config.self_profile {
            program.attach(
                perf_type,
                PERF_COUNT_SW_CPU_CLOCK,
                PerfEventScope::CallingProcessAnyCpu,
                SamplePolicy::Frequency(config.frequency),
                true,
            )?;
        } else if let Some(pid) = config.pid {
            program.attach(
                perf_type,
                PERF_COUNT_SW_CPU_CLOCK,
                PerfEventScope::OneProcessAnyCpu { pid },
                SamplePolicy::Frequency(config.frequency),
                true,
            )?;
        } else if let Some(cpu) = config.cpu {
            program.attach(
                perf_type,
                PERF_COUNT_SW_CPU_CLOCK,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(config.frequency),
                true,
            )?;
        } else {
            let cpus = online_cpus().map_err(|(_, error)| error)?;
            let nprocs = cpus.len();
            eprintln!("CPUs: {}", nprocs);

            for cpu in cpus {
                program.attach(
                    perf_type.clone(),
                    PERF_COUNT_SW_CPU_CLOCK,
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

pub fn setup_ring_buffer(bpf: &mut Ebpf) -> Result<RingBuf<&mut MapData>, anyhow::Error> {
    let ring_buf = RingBuf::try_from(
        bpf.map_mut("RING_BUF_STACKS")
            .ok_or(anyhow!("RING_BUF_STACKS not found"))?,
    )?;

    Ok(ring_buf)
}

impl EbpfProfiler {
    /// Load DWARF unwind tables into eBPF maps for a process
    pub fn load_dwarf_unwind_tables(
        &mut self,
        manager: &crate::dwarf_unwind::DwarfUnwindManager,
    ) -> Result<(), anyhow::Error> {
        // Get the unwind_table array map
        let mut unwind_table: Array<&mut MapData, UnwindEntryPod> =
            Array::try_from(
                self.bpf
                    .map_mut("unwind_table")
                    .ok_or(anyhow!("unwind_table map not found"))?,
            )?;

        // Load all unwind entries into the global array
        for (idx, entry) in manager.global_table.iter().enumerate() {
            unwind_table.set(idx as u32, UnwindEntryPod(*entry), 0)?;
        }

        tracing::info!(
            "Loaded {} unwind table entries into eBPF map",
            manager.global_table.len()
        );

        // Get the proc_info hash map
        let mut proc_info_map: HashMap<&mut MapData, ProcInfoKeyPod, ProcInfoPod> =
            HashMap::try_from(
                self.bpf
                    .map_mut("proc_info")
                    .ok_or(anyhow!("proc_info map not found"))?,
            )?;

        // Load per-process mapping information
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
}
