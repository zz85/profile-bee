use anyhow::anyhow;
use aya::maps::{HashMap, MapData, RingBuf, StackTraceMap};
use aya::programs::{
    perf_event::{PerfEventScope, PerfTypeId, SamplePolicy},
    KProbe, PerfEvent,
};
use aya::programs::{TracePoint, UProbe};
use aya::{include_bytes_aligned, util::online_cpus};
use aya::{Btf, Ebpf, EbpfLoader};
use profile_bee_common::StackInfo;

/// Container for an eBPF stuff
#[derive(Debug)]
pub struct EbpfProfiler {
    pub bpf: Ebpf,
    pub stack_traces: StackTraceMap<MapData>,
    pub counts: HashMap<MapData, [u8; std::mem::size_of::<StackInfo>()], u64>,
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

    let bpf = EbpfLoader::new()
        .set_global("SKIP_IDLE", &skip_idle, true)
        .set_global("NOTIFY_TYPE", &config.stream_mode, true)
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

    let counts = HashMap::<_, [u8; StackInfo::STRUCT_SIZE], u64>::try_from(
        bpf.take_map("counts").ok_or(anyhow!("counts not found"))?,
    )?;

    Ok(EbpfProfiler {
        bpf,
        stack_traces,
        counts,
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
    // todo: move stuff from profile-bee bin into here
}
