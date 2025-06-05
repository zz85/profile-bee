use aya::maps::{MapData, StackTraceMap};
use aya::Ebpf;
use clap::Parser;
use inferno::flamegraph::{self, Options};
use profile_bee::ebpf::FramePointersPod;
use profile_bee::ebpf::{
    setup_ebpf_profiler, setup_ring_buffer, EbpfProfiler, ProfilerConfig, StackInfoPod,
};
use profile_bee::html::{collapse_to_json, generate_html_file};
use profile_bee::spawn::{SpawnProcess, StopHandler};
use profile_bee::TraceHandler;
use profile_bee_common::{FramePointers, StackInfo, EVENT_TRACE_ALWAYS};
use tokio::task;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use profile_bee::types::FrameCount;

/// Message type for the profiler's communication channel
enum PerfWork {
    StackInfo(StackInfo),
    Stop,
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// Filename to write in stackcollapse format
    #[arg(short, long)]
    collapse: Option<PathBuf>,

    /// Filename to generate flamegraph svg
    #[arg(short, long)]
    svg: Option<PathBuf>,

    /// Filename for generate html version of flamegraph
    #[arg(long)]
    html: Option<PathBuf>,

    /// Generate json data format in d3 flamegraph format
    #[arg(long)]
    json: Option<PathBuf>,

    /// Starts a http server to serve the html flamegraph result
    #[arg(long)]
    serve: bool,

    /// Avoid profiling idle cpu cycles
    #[arg(long)]
    skip_idle: bool,

    /// Time to run CPU profiling in milliseconds,
    #[arg(short, long, default_value_t = 10000)]
    time: usize,

    /// Frequency for sampling,
    #[arg(short, long, default_value_t = 99)]
    frequency: u64,

    /// function name to attached kprobe
    #[arg(long)]
    kprobe: Option<String>,

    /// function name to attached uprobe
    #[arg(long)]
    uprobe: Option<String>,

    /// function name to attached tracepoint eg.
    #[arg(long)]
    tracepoint: Option<String>,

    #[arg(long, default_value_t = false)]
    group_by_cpu: bool,

    #[arg(long, default_value_t = false)]
    no_dwarf: bool,

    /// PID to profile
    #[arg(short, long)]
    pid: Option<u32>,

    /// target CPU to profile
    #[arg(long)]
    cpu: Option<u32>,

    /// Profile this process
    #[arg(long, default_value_t = false)]
    self_profile: bool,

    /// method of passes events/traces to
    /// user space.
    /// 1 - always - all events
    /// 2 - new stack traces
    /// 3 - none
    #[arg(long, default_value_t = 2)]
    stream_mode: u8,

    /// Spawn command and profile
    #[arg(short, long)]
    cmd: Option<String>,
}

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    use tokio::sync::broadcast;
    let (tx, rx) = broadcast::channel(16);

    if opt.serve {
        tokio::spawn(async {
            profile_bee::html::start_server(rx).await;
        });
    }

    println!("Starting {:?}", opt);

    let (stopper, spawn) = setup_process_to_profile(&opt.cmd)?;

    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid.clone()
    };

    // Create eBPF profiler configuration from command line options
    let config = ProfilerConfig {
        skip_idle: opt.skip_idle,
        stream_mode: opt.stream_mode,
        frequency: opt.frequency,
        kprobe: opt.kprobe.clone(),
        uprobe: opt.uprobe.clone(),
        tracepoint: opt.tracepoint.clone(),
        pid,
        cpu: opt.cpu,
        self_profile: opt.self_profile,
    };

    // Setup eBPF profiler
    let mut ebpf_profiler = setup_ebpf_profiler(&config)?;

    let counts = &mut ebpf_profiler.counts;
    let stack_traces = &ebpf_profiler.stack_traces;
    let stacked_pointers = &ebpf_profiler.stacked_pointers;

    let mut profiler = TraceHandler::new(); // !opt.no_dwarf

    // Set up communication channels
    let (perf_tx, perf_rx) = mpsc::channel();

    // Set up stopping mechanisms
    setup_stopping_mechanisms(opt.time, perf_tx.clone(), stopper.clone(), spawn);

    task::spawn(async move {
        // Set up ring buffer to collect stack traces
        if let Err(e) = setup_ring_buffer_task(&mut ebpf_profiler.bpf, perf_tx).await {
            eprintln!("Failed to set up ring buffer: {:?}", e);
        }
    });

    let started = Instant::now();

    loop {
        // Process collected data
        let stacks = process_profiling_data(
            counts,
            stack_traces,
            &perf_rx,
            &mut profiler,
            opt.stream_mode,
            opt.group_by_cpu,
            stacked_pointers,
        );

        // Generate and save output files
        output_results(&opt, &stacks, &tx)?;

        if !opt.serve {
            // only loop with serve mode
            break;
        }
    }

    drop(stopper);

    println!("Profiler ran for {:?}", started.elapsed());

    profiler.print_stats();

    Ok(())
}

/// Sets up the process to profile if a command is provided
fn setup_process_to_profile(
    cmd: &Option<String>,
) -> anyhow::Result<(Option<StopHandler>, Option<SpawnProcess>)> {
    if let Some(cmd) = cmd {
        println!("Running cmd: {cmd}");

        // todo: use shelltools
        let args: Vec<_> = cmd.split(' ').collect();
        let (child, stopper) = SpawnProcess::spawn(&args[0], &args[1..])?;

        println!("Profile pid {}..", child.pid());

        Ok((Some(stopper), Some(child)))
    } else {
        Ok((None, None))
    }
}

/// Sets up the mechanisms that can stop the profiling
fn setup_stopping_mechanisms(
    duration: usize,
    perf_tx: mpsc::Sender<PerfWork>,
    stopping: Option<StopHandler>,
    spawn: Option<SpawnProcess>,
) {
    // 3 ways to stop
    // - 1. user defined duration
    // - 2. ctrl-c received
    // - 3. child process stops

    // Timer-based stopping
    let time_stop_tx = perf_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(duration as _)).await;
        time_stop_tx.send(PerfWork::Stop).unwrap_or_default();
    });

    // Child process completion stopping
    if let Some(mut child) = spawn {
        let child_stopper_tx = perf_tx.clone();
        tokio::spawn(async move {
            child.work_done().await;
            child_stopper_tx.send(PerfWork::Stop).unwrap_or_default();
        });
    }

    // Ctrl-C stopping
    let stop_tx = perf_tx.clone();
    let stopping = stopping;
    tokio::spawn(async move {
        println!("Waiting for Ctrl-C...");
        tokio::signal::ctrl_c().await.unwrap_or_default();
        println!("Received Ctrl-C");
        drop(stopping);
        stop_tx.send(PerfWork::Stop).unwrap_or_default();
    });
}

/// Sets up the ring buffer task to collect stack traces
async fn setup_ring_buffer_task(
    ebpf: &mut Ebpf,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
    // Setup the ring buffer before spawning the task
    let ring_buf = setup_ring_buffer(ebpf)?;

    use tokio::io::unix::AsyncFd;
    let mut fd = AsyncFd::new(ring_buf)?;

    while let Ok(mut guard) = fd.readable_mut().await {
        match guard.try_io(|inner| {
            let ring_buf = inner.get_mut();
            while let Some(item) = ring_buf.next() {
                let stack: StackInfo = unsafe { *item.as_ptr().cast() };
                let _ = perf_tx.send(PerfWork::StackInfo(stack));
            }
            Ok(())
        }) {
            Ok(_) => {
                guard.clear_ready();
                continue;
            }
            Err(_would_block) => continue,
        }
    }

    Ok(())
}

// Processes the profiling data collected from eBPF
fn process_profiling_data(
    counts: &mut aya::maps::HashMap<MapData, [u8; StackInfo::STRUCT_SIZE], u64>,
    stack_traces: &StackTraceMap<MapData>,
    perf_rx: &mpsc::Receiver<PerfWork>,
    profiler: &mut TraceHandler,
    stream_mode: u8,
    group_by_cpu: bool,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
) -> Vec<String> {
    // Local counting
    let mut trace_count = HashMap::<StackInfo, usize>::new();
    let mut queue_processed = 0;
    let mut samples = 0;

    // Clear counters
    trace_count.clear();

    // Clear "counts" hashmap
    let keys = counts.keys().flatten().collect::<Vec<_>>();
    for k in keys {
        let _ = counts.remove(&k);
    }

    /* Perf mpsc RX loop */
    while let Ok(work) = perf_rx.recv() {
        match work {
            PerfWork::StackInfo(stack) => {
                queue_processed += 1;

                // User space counting
                let trace = trace_count.entry(stack).or_insert(0);
                *trace += 1;

                if *trace == 1 {
                    // todo pass hashmap or stacked pointers information here

                    let _combined = profiler.get_exp_stacked_frames(
                        &stack,
                        &stack_traces,
                        group_by_cpu,
                        stacked_pointers,
                    );
                }
            }
            PerfWork::Stop => break,
        }
    }

    println!("Processed {} queue events", queue_processed);
    println!("Processing stacks...");

    let mut stacks = Vec::new();
    let local_counting = stream_mode == EVENT_TRACE_ALWAYS;

    if local_counting {
        process_local_counting(
            trace_count,
            profiler,
            stack_traces,
            group_by_cpu,
            &mut samples,
            &mut stacks,
        );
    } else {
        process_kernel_counting(
            counts,
            profiler,
            stack_traces,
            group_by_cpu,
            &mut samples,
            &mut stacks,
        );
    }

    // TODO stack processing can be expensive, so consider moving into a separate task
    // to avoid blocking the collection loop
    println!("Total samples: {}", samples);

    let mut out = stacks
        .into_iter()
        .map(|frames| {
            let key = frames
                .frames
                .iter()
                .map(|s| s.fmt_symbol())
                .collect::<Vec<_>>()
                .join(";");
            let count = frames.count;
            format!("{} {}", &key, count)
        })
        .collect::<Vec<_>>();
    out.sort();

    out
}

/// Process stack traces counted in user space
fn process_local_counting(
    trace_count: HashMap<StackInfo, usize>,
    profiler: &mut TraceHandler,
    stack_traces: &StackTraceMap<MapData>,
    group_by_cpu: bool,
    samples: &mut u64,
    stacks: &mut Vec<FrameCount>,
) {
    for (stack, value) in trace_count.iter() {
        let combined = profiler.get_stacked_frames(stack, stack_traces, group_by_cpu);

        *samples += *value as u64;
        stacks.push(FrameCount {
            frames: combined,
            count: *value as u64,
        });
    }
}

/// Process stack traces counted in kernel space
fn process_kernel_counting(
    counts: &mut aya::maps::HashMap<MapData, [u8; StackInfo::STRUCT_SIZE], u64>,

    profiler: &mut TraceHandler,
    stack_traces: &aya::maps::StackTraceMap<MapData>,
    group_by_cpu: bool,
    samples: &mut u64,
    stacks: &mut Vec<FrameCount>,
) {
    for (key, value) in counts.iter().flatten() {
        let stack: StackInfo = unsafe { *key.as_ptr().cast() };

        *samples += value;

        let combined = profiler.get_stacked_frames(&stack, stack_traces, group_by_cpu);

        stacks.push(FrameCount {
            frames: combined,
            count: value,
        });
    }
}

/// Outputs the results in the requested formats
fn output_results(
    opt: &Opt,
    stacks: &[String],
    tx: &tokio::sync::broadcast::Sender<String>,
) -> anyhow::Result<()> {
    // Generate SVG if requested
    if let Some(svg) = &opt.svg {
        output_svg(
            svg,
            stacks,
            format!(
                "Flamegraph profile generated from profile-bee ({}ms @ {}hz)",
                opt.time, opt.frequency
            ),
        )
        .map_err(|e| {
            println!("Failed to write svg file {:?} - {:?}", e, svg);
            e
        })?;
    }

    // Generate HTML/JSON if requested
    if opt.html.is_some() || opt.json.is_some() || opt.serve {
        let json = collapse_to_json(&stacks.iter().map(|v| v.as_str()).collect::<Vec<_>>());

        if let Some(json_path) = &opt.json {
            std::fs::write(json_path, &json)
                .map_err(|e| anyhow::anyhow!("Unable to write JSON file: {}", e))?;
        }

        if let Some(html_path) = &opt.html {
            generate_html_file(html_path, &json);
        }

        if let Err(e) = tx.send(json) {
            println!("Error sending JSON data: {:?}", e);
        }
    }

    // Write collapsed stacks if requested
    if let Some(name) = &opt.collapse {
        println!("Writing to file: {}", name.display());
        std::fs::write(name, stacks.join("\n"))
            .map_err(|e| anyhow::anyhow!("Unable to write stack collapsed file: {}", e))?;
    }

    Ok(())
}

/// Creates a flamegraph svg file using the inferno-flamegraph lib
fn output_svg(path: &PathBuf, str: &[String], title: String) -> anyhow::Result<()> {
    let mut svg_opts = Options::default();
    svg_opts.title = title;
    let mut svg_file = std::io::BufWriter::with_capacity(1024 * 1024, std::fs::File::create(path)?);
    flamegraph::from_lines(&mut svg_opts, str.iter().map(|v| v.as_str()), &mut svg_file)?;

    Ok(())
}
