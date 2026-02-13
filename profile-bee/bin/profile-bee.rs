use aya::maps::{MapData, RingBuf, StackTraceMap};
use aya::Ebpf;
use clap::Parser;
use inferno::flamegraph::{self, Options};
use profile_bee::dwarf_unwind::DwarfUnwindManager;
use profile_bee::ebpf::{setup_ebpf_profiler, setup_ring_buffer, EbpfProfiler, ProfilerConfig, StackInfoPod, SmartUProbeConfig};
use profile_bee::ebpf::{FramePointersPod};
use profile_bee::html::{collapse_to_json, generate_html_file};
use profile_bee::probe_spec::parse_probe_spec;
use profile_bee::probe_resolver::{format_resolved_probes, ProbeResolver, ResolvedProbe};
use profile_bee::spawn::{SpawnProcess, StopHandler};
use profile_bee::TraceHandler;
use profile_bee_common::{StackInfo, UnwindEntry, ProcInfo, EVENT_TRACE_ALWAYS};
use tokio::task;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use profile_bee::types::FrameCount;

/// Message type for the profiler's communication channel
enum PerfWork {
    StackInfo(StackInfo),
    DwarfRefresh(DwarfRefreshUpdate),
    Stop,
}

/// Incremental DWARF unwind table update
struct DwarfRefreshUpdate {
    shard_updates: Vec<(u8, Vec<UnwindEntry>)>,  // (shard_id, entries)
    proc_info: Vec<(u32, ProcInfo)>,
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

    /// Starts a http server to serve the html flamegraph result. Can be combined with --tui for dual interface access.
    #[arg(long)]
    serve: bool,

    /// Display results in an interactive TUI flamegraph viewer
    #[cfg(feature = "tui")]
    #[arg(long)]
    tui: bool,

    /// How often (in ms) to accumulate samples before refreshing the TUI flamegraph
    #[cfg(feature = "tui")]
    #[arg(long, default_value_t = 2000)]
    tui_refresh_ms: u64,

    /// Update mode for real-time flamegraph: reset (clear each interval), accumulate (sum over time), decay (moving average)
    #[cfg(feature = "tui")]
    #[arg(long, default_value = "accumulate", value_parser = ["reset", "accumulate", "decay"])]
    update_mode: String,

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

    /// Uprobe specification. GDB-style smart matching:
    ///   malloc                        - auto-discover library
    ///   libc:malloc                   - explicit library
    ///   /usr/lib/libc.so.6:malloc     - absolute path
    ///   ret:malloc                    - return probe
    ///   malloc+0x10                   - function + offset
    ///   pthread_*                     - glob pattern
    ///   /regex_pattern/               - regex matching
    ///   std::vector::push_back        - demangled name match
    ///   main.c:42                     - source file:line (DWARF)
    /// Can be specified multiple times to attach multiple probes.
    #[arg(long)]
    uprobe: Vec<String>,

    /// PID to attach uprobe to (if not specified, attaches to all processes)
    #[arg(long)]
    uprobe_pid: Option<i32>,

    /// List matching probe targets without attaching (discovery mode).
    /// Pass a probe spec like --list-probes 'pthread_*'
    #[arg(long)]
    list_probes: Option<String>,

    /// function name to attached tracepoint eg.
    #[arg(long)]
    tracepoint: Option<String>,

    #[arg(long, default_value_t = false)]
    group_by_cpu: bool,

    /// Enable DWARF-based stack unwinding (for binaries without frame pointers)
    #[arg(long, default_value_t = true, value_parser = clap::value_parser!(bool), num_args = 0..=1, default_missing_value = "true")]
    dwarf: bool,

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

    /// Spawn command and profile (deprecated: use `-- <command>` instead)
    #[arg(long)]
    cmd: Option<String>,

    /// Command and arguments to spawn and profile (use after `--`)
    #[arg(last = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // TUI and serve modes can now run together

    // Initialize the tracing subscriber with environment variables
    tracing_subscriber::fmt()
        // Use EnvFilter to read from RUST_LOG environment variable
        .with_env_filter(EnvFilter::from_default_env())
        // Optional: Configure span events
        .with_span_events(FmtSpan::FULL)
        // Initialize the subscriber
        .init();

    use tokio::sync::broadcast;
    let (tx, rx) = broadcast::channel(16);

    #[cfg(feature = "tui")]
    if opt.tui {
        if opt.serve {
            // Combined TUI + serve mode
            return run_combined_mode(opt, tx).await;
        } else {
            // TUI only mode
            return run_tui_mode(opt).await;
        }
    }

    if opt.serve {
        tokio::spawn(async {
            profile_bee::html::start_server(rx).await;
        });
    }

    println!("Starting {:?}", opt);

    // Handle --list-probes discovery mode (print and exit)
    if let Some(ref probe_str) = opt.list_probes {
        return handle_list_probes(probe_str, opt.pid, opt.uprobe_pid);
    }

    // profile_bee::load(&opt.cmd.unwrap()).unwrap();
    // return Ok(());

    // Resolve smart uprobe specs (if any)
    let smart_uprobe = if !opt.uprobe.is_empty() {
        Some(resolve_uprobe_specs(&opt.uprobe, opt.pid, opt.uprobe_pid)?)
    } else {
        None
    };

    // Create eBPF profiler configuration from command line options (without pid first)
    let config = ProfilerConfig {
        skip_idle: opt.skip_idle,
        stream_mode: opt.stream_mode,
        frequency: opt.frequency,
        kprobe: opt.kprobe.clone(),
        uprobe: None,
        smart_uprobe,
        tracepoint: opt.tracepoint.clone(),
        pid: opt.pid.clone(),
        cpu: opt.cpu,
        self_profile: opt.self_profile,
        dwarf: opt.dwarf,
    };

    // Setup eBPF profiler first to ensure verification succeeds
    let verification_start = std::time::Instant::now();
    let mut ebpf_profiler = setup_ebpf_profiler(&config)?;
    let verification_time = verification_start.elapsed();
    println!("eBPF verification completed in {:?}", verification_time);

    // Only spawn process after eBPF verification succeeds
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command)?;

    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid.clone()
    };

    // Set up communication channels (before DWARF block so refresh thread can use it)
    let (perf_tx, perf_rx) = mpsc::channel();

    // If DWARF unwinding is enabled, load unwind tables BEFORE setting TARGET_PID
    // This ensures unwind information is available from the first sample
    let tgid_request_tx = if opt.dwarf {
        let mut dwarf_manager = DwarfUnwindManager::new();

        // Load initial process if specified
        if let Some(target_pid) = pid {
            println!("Loading DWARF unwind tables for pid {}...", target_pid);
            match dwarf_manager.load_process(target_pid) {
                Ok(()) => {
                    println!(
                        "Loaded {} unwind entries for pid {}",
                        dwarf_manager.total_entries(),
                        target_pid,
                    );
                    if let Err(e) = ebpf_profiler.load_dwarf_unwind_tables(&dwarf_manager) {
                        eprintln!("Failed to load DWARF unwind tables into eBPF: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load DWARF info for pid {}: {}", target_pid, e);
                }
            }
        }

        // Channel for requesting new tgid loads (multi-process / dlopen support)
        let (tgid_tx, tgid_rx) = mpsc::channel::<u32>();
        let refresh_tx = perf_tx.clone();
        let initial_pid = pid;
        std::thread::spawn(move || {
            dwarf_refresh_loop(dwarf_manager, initial_pid, tgid_rx, refresh_tx);
        });

        Some(tgid_tx)
    } else {
        None
    };

    // Set target PID for eBPF filtering AFTER DWARF tables are loaded
    // This ensures the eBPF program has unwind information before filtering samples
    if let Some(target_pid) = pid {
        ebpf_profiler.set_target_pid(target_pid)?;
        println!("Profiling PID {}..", target_pid);
    }

    // Take ownership of ring buffer map after DWARF loading
    let ring_buf = setup_ring_buffer(&mut ebpf_profiler.bpf)?;

    let counts = &mut ebpf_profiler.counts;
    let stack_traces = &ebpf_profiler.stack_traces;
    let stacked_pointers = &ebpf_profiler.stacked_pointers;

    let mut profiler = TraceHandler::new();

    // Set up stopping mechanisms
    // Pass the external PID if we're monitoring one (not spawned)
    let external_pid = if spawn.is_none() { opt.pid } else { None };
    setup_stopping_mechanisms(opt.time, perf_tx.clone(), stopper.clone(), spawn, external_pid);

    task::spawn(async move {
        if let Err(e) = setup_ring_buffer_task(ring_buf, perf_tx).await {
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
            &mut ebpf_profiler.bpf,
            &tgid_request_tx,
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

/// Convert an optional i32 PID to u32, rejecting negative values.
fn uprobe_pid_as_u32(uprobe_pid: Option<i32>) -> Result<Option<u32>, anyhow::Error> {
    uprobe_pid
        .map(|p| {
            u32::try_from(p).map_err(|_| anyhow::anyhow!("--uprobe-pid must be non-negative, got {}", p))
        })
        .transpose()
}

/// Handle --list-probes: resolve and display matching symbols, then exit.
fn handle_list_probes(
    probe_str: &str,
    pid: Option<u32>,
    uprobe_pid: Option<i32>,
) -> Result<(), anyhow::Error> {
    let spec = parse_probe_spec(probe_str)
        .map_err(|e| anyhow::anyhow!("invalid probe spec '{}': {}", probe_str, e))?;

    eprintln!("Searching for: {}", spec);

    let resolver = ProbeResolver::new();

    let effective_pid = pid.or(uprobe_pid_as_u32(uprobe_pid)?);

    let probes = if let Some(target_pid) = effective_pid {
        eprintln!("Scanning /proc/{}/maps...", target_pid);
        resolver.resolve_for_pid(&spec, target_pid)
    } else {
        eprintln!("Scanning system libraries (no --pid specified)...");
        resolver.resolve_system_wide(&spec)
    }
    .map_err(|e| anyhow::anyhow!("probe resolution failed: {}", e))?;

    println!("{}", format_resolved_probes(&probes));
    Ok(())
}

/// Resolve uprobe spec strings into a SmartUProbeConfig ready for eBPF attachment.
fn resolve_uprobe_specs(
    specs: &[String],
    pid: Option<u32>,
    uprobe_pid: Option<i32>,
) -> Result<SmartUProbeConfig, anyhow::Error> {
    let resolver = ProbeResolver::new();
    let effective_pid = pid.or(uprobe_pid_as_u32(uprobe_pid)?);
    let mut all_probes: Vec<ResolvedProbe> = Vec::new();

    for spec_str in specs {
        let spec = parse_probe_spec(spec_str)
            .map_err(|e| anyhow::anyhow!("invalid probe spec '{}': {}", spec_str, e))?;

        eprintln!("Resolving uprobe: {}", spec);

        let probes = if let Some(target_pid) = effective_pid {
            resolver.resolve_for_pid(&spec, target_pid)
        } else {
            resolver.resolve_system_wide(&spec)
        }
        .map_err(|e| anyhow::anyhow!("failed to resolve '{}': {}", spec_str, e))?;

        if probes.is_empty() {
            return Err(anyhow::anyhow!(
                "no symbols found matching '{}'. Use --list-probes to search.",
                spec_str,
            ));
        }

        eprintln!(
            "  resolved {} match{} for '{}'",
            probes.len(),
            if probes.len() == 1 { "" } else { "es" },
            spec_str,
        );

        all_probes.extend(probes);
    }

    Ok(SmartUProbeConfig {
        probes: all_probes,
        pid: uprobe_pid,
    })
}

/// Sets up the process to profile if a command is provided
fn setup_process_to_profile(
    cmd: &Option<String>,
    command: &[String],
) -> anyhow::Result<(Option<StopHandler>, Option<SpawnProcess>)> {
    // Prefer the new command format (--) over the old --cmd format
    if !command.is_empty() {
        let program = &command[0];
        let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();
        
        println!("Running command: {} {}", program, args.join(" "));
        
        let (child, stopper) = SpawnProcess::spawn(program, &args)?;
        println!("Profiling PID {}..", child.pid());
        
        return Ok((Some(stopper), Some(child)));
    }
    
    // Fall back to old --cmd format for backward compatibility
    if let Some(cmd) = cmd {
        eprintln!("Warning: --cmd is deprecated. Use '-- <command> <args>' instead.");
        println!("Running cmd: {cmd}");

        // todo: use shelltools
        let args: Vec<_> = cmd.split(' ').collect();
        let (child, stopper) = SpawnProcess::spawn(&args[0], &args[1..])?;

        println!("Profiling PID {}..", child.pid());

        Ok((Some(stopper), Some(child)))
    } else {
        Ok((None, None))
    }
}

/// Monitor a PID and return when it exits
async fn monitor_pid_exit(pid: u32) {
    use tokio::time::{sleep, Duration};
    
    // Check if the PID exists initially
    if !pid_exists(pid) {
        eprintln!("Warning: PID {} does not exist or is not accessible", pid);
        return;
    }
    
    println!("Monitoring PID {} for exit...", pid);
    
    // Poll every 100ms to check if the process is still alive
    loop {
        sleep(Duration::from_millis(100)).await;
        
        if !pid_exists(pid) {
            println!("Target PID {} has exited", pid);
            break;
        }
    }
}

/// Check if a PID exists and is accessible
fn pid_exists(pid: u32) -> bool {
    use std::fs;
    
    // Check if /proc/[pid] exists
    let proc_path = format!("/proc/{}", pid);
    fs::metadata(&proc_path).is_ok()
}

/// Sets up the mechanisms that can stop the profiling
fn setup_stopping_mechanisms(
    duration: usize,
    perf_tx: mpsc::Sender<PerfWork>,
    stopping: Option<StopHandler>,
    spawn: Option<SpawnProcess>,
    target_pid: Option<u32>,
) {
    // 4 ways to stop
    // - 1. user defined duration
    // - 2. ctrl-c received
    // - 3. child process stops (when spawned with -- or --cmd)
    // - 4. target PID exits (when profiling with --pid)

    // Timer-based stopping
    // Clone the stopping handler so that when the timer expires,
    // it will signal the spawned process to be killed
    let time_stop_tx = perf_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(duration as _)).await;
        // Send Stop message to exit the profiling loop
        // NOTE: Don't kill the spawned process here — it must stay alive
        // for symbolization (reading /proc/<pid>/maps) after profiling stops.
        // The caller kills it after processing.
        time_stop_tx.send(PerfWork::Stop).unwrap_or_default();
    });

    // Child process completion stopping (for spawned processes)
    if let Some(mut child) = spawn {
        let child_stopper_tx = perf_tx.clone();
        tokio::spawn(async move {
            child.work_done().await;
            child_stopper_tx.send(PerfWork::Stop).unwrap_or_default();
        });
    }
    
    // Target PID monitoring (for --pid option)
    // Only monitor if we have a target PID and didn't spawn the process ourselves
    if let Some(pid) = target_pid {
        // Only set up PID monitoring if we're not already monitoring a spawned process
        // (i.e., the PID came from --pid, not from a spawned command)
        let pid_stop_tx = perf_tx.clone();
        tokio::spawn(async move {
            monitor_pid_exit(pid).await;
            pid_stop_tx.send(PerfWork::Stop).unwrap_or_default();
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
    ring_buf: RingBuf<MapData>,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
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

/// Background thread: handles dlopen rescans and new process DWARF loading
fn dwarf_refresh_loop(
    mut manager: DwarfUnwindManager,
    initial_pid: Option<u32>,
    tgid_rx: mpsc::Receiver<u32>,
    tx: mpsc::Sender<PerfWork>,
) {
    let mut tracked_pids: Vec<u32> = initial_pid.into_iter().collect();

    loop {
        // Drain all pending tgid requests (non-blocking)
        while let Ok(new_tgid) = tgid_rx.try_recv() {
            if !tracked_pids.contains(&new_tgid) {
                tracked_pids.push(new_tgid);
                // Immediately load the new process
                if let Ok(new_shard_ids) = manager.refresh_process(new_tgid) {
                    if !new_shard_ids.is_empty() {
                        if send_refresh(&manager, &tx, new_shard_ids).is_err() {
                            return;
                        }
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));

        // Periodic rescan of all tracked processes for dlopen'd libraries
        for &pid in &tracked_pids {
            if let Ok(new_shard_ids) = manager.refresh_process(pid) {
                if !new_shard_ids.is_empty() {
                    if send_refresh(&manager, &tx, new_shard_ids).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn send_refresh(
    manager: &DwarfUnwindManager,
    tx: &mpsc::Sender<PerfWork>,
    new_shard_ids: Vec<u8>,
) -> Result<(), ()> {
    let mut shard_updates = Vec::new();
    for &shard_id in &new_shard_ids {
        if let Some(entries) = manager.binary_tables.get(&shard_id) {
            shard_updates.push((shard_id, entries.clone()));
        }
    }
    let proc_info: Vec<(u32, ProcInfo)> = manager
        .proc_info
        .iter()
        .map(|(&t, &p)| (t, p))
        .collect();
    let total_entries: usize = shard_updates.iter().map(|(_, v)| v.len()).sum();
    println!(
        "DWARF refresh: {} new shards with {} total entries",
        new_shard_ids.len(), total_entries,
    );
    tx.send(PerfWork::DwarfRefresh(DwarfRefreshUpdate {
        shard_updates,
        proc_info,
    })).map_err(|_| ())
}

/// Apply incremental DWARF unwind table updates to eBPF maps
fn apply_dwarf_refresh(bpf: &mut Ebpf, update: DwarfRefreshUpdate) {
    use aya::maps::{Array, HashMap};
    use profile_bee::ebpf::{UnwindEntryPod, ProcInfoKeyPod, ProcInfoPod};
    use profile_bee_common::ProcInfoKey;

    for (shard_id, entries) in &update.shard_updates {
        let map_name = format!("shard_{}", shard_id);
        if let Some(map) = bpf.map_mut(&map_name) {
            if let Ok(mut arr) = Array::<&mut MapData, UnwindEntryPod>::try_from(map) {
                for (idx, entry) in entries.iter().enumerate() {
                    let _ = arr.set(idx as u32, UnwindEntryPod(*entry), 0);
                }
            }
        }
    }

    if let Some(map) = bpf.map_mut("proc_info") {
        if let Ok(mut hm) = HashMap::<&mut MapData, ProcInfoKeyPod, ProcInfoPod>::try_from(map) {
            for (tgid, pi) in &update.proc_info {
                let key = ProcInfoKeyPod(ProcInfoKey { tgid: *tgid, _pad: 0 });
                let _ = hm.insert(key, ProcInfoPod(*pi), 0);
            }
        }
    }
}

// Processes the profiling data collected from eBPF
fn process_profiling_data(
    counts: &mut aya::maps::HashMap<MapData, StackInfoPod, u64>,
    stack_traces: &StackTraceMap<MapData>,
    perf_rx: &mpsc::Receiver<PerfWork>,
    profiler: &mut TraceHandler,
    stream_mode: u8,
    group_by_cpu: bool,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    bpf: &mut Ebpf,
    tgid_request_tx: &Option<mpsc::Sender<u32>>,
) -> Vec<String> {
    // Local counting
    let mut trace_count = HashMap::<StackInfo, usize>::new();
    let mut queue_processed = 0;
    let mut samples = 0;
    let mut known_tgids = std::collections::HashSet::<u32>::new();

    // Determine counting strategy before the recv loop so the StackInfo
    // handler knows whether to accumulate into trace_count (local counting)
    // or only prime the symbol cache (kernel counting).
    let local_counting = stream_mode == EVENT_TRACE_ALWAYS;

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

                // Request DWARF loading for newly seen processes
                if let Some(tx) = tgid_request_tx {
                    if stack.tgid != 0 && known_tgids.insert(stack.tgid) {
                        let _ = tx.send(stack.tgid);
                    }
                }

                if local_counting {
                    // User space counting — accumulate into trace_count
                    let trace = trace_count.entry(stack).or_insert(0);
                    *trace += 1;

                    if *trace == 1 {
                        let _combined = profiler.get_exp_stacked_frames(
                            &stack,
                            &stack_traces,
                            group_by_cpu,
                            &stacked_pointers,
                        );
                    }
                } else {
                    // Kernel counts are authoritative; only prime symbol cache
                    let _combined = profiler.get_exp_stacked_frames(
                        &stack,
                        &stack_traces,
                        group_by_cpu,
                        &stacked_pointers,
                    );
                }
            }
            PerfWork::DwarfRefresh(update) => {
                apply_dwarf_refresh(bpf, update);
            }
            PerfWork::Stop => break,
        }
    }

    println!("Processed {} queue events", queue_processed);
    println!("Processing stacks...");

    let mut stacks = Vec::new();

    if local_counting {
        process_local_counting(
            trace_count,
            profiler,
            stack_traces,
            group_by_cpu,
            &mut samples,
            &mut stacks,
            stacked_pointers,
        );
    } else {
        process_kernel_counting(
            counts,
            profiler,
            stack_traces,
            group_by_cpu,
            &mut samples,
            &mut stacks,
            stacked_pointers,
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
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
) {
    for (stack, value) in trace_count.iter() {
        let combined = profiler.get_exp_stacked_frames(stack, stack_traces, group_by_cpu, stacked_pointers);

        *samples += *value as u64;
        stacks.push(FrameCount {
            frames: combined,
            count: *value as u64,
        });
    }
}

/// Process stack traces counted in kernel space
fn process_kernel_counting(
    counts: &mut aya::maps::HashMap<MapData, StackInfoPod, u64>,

    profiler: &mut TraceHandler,
    stack_traces: &aya::maps::StackTraceMap<MapData>,
    group_by_cpu: bool,
    samples: &mut u64,
    stacks: &mut Vec<FrameCount>,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
) {
    for (key, value) in counts.iter().flatten() {
        let stack: StackInfo = key.0;

        *samples += value;

        let combined = profiler.get_exp_stacked_frames(&stack, stack_traces, group_by_cpu, stacked_pointers);

        stacks.push(FrameCount {
            frames: combined,
            count: value,
        });
    }
}

/// Parse update mode from string
#[cfg(feature = "tui")]
fn parse_update_mode(mode: &str) -> profile_bee_tui::state::UpdateMode {
    use profile_bee_tui::state::UpdateMode;
    match mode.to_lowercase().as_str() {
        "reset" => UpdateMode::Reset,
        "accumulate" => UpdateMode::Accumulate,
        "decay" => UpdateMode::Decay,
        _ => UpdateMode::Accumulate, // default
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

// ---------------------------------------------------------------------------
// Shared helpers for TUI and combined (TUI + serve) modes
// ---------------------------------------------------------------------------

/// Builds a `ProfilerConfig` from CLI options, resolving smart uprobe specs.
#[cfg(feature = "tui")]
fn build_profiler_config(
    opt: &Opt,
    pid: Option<u32>,
) -> Result<ProfilerConfig, anyhow::Error> {
    let smart_uprobe = if !opt.uprobe.is_empty() {
        Some(resolve_uprobe_specs(&opt.uprobe, pid, opt.uprobe_pid)?)
    } else {
        None
    };

    Ok(ProfilerConfig {
        skip_idle: opt.skip_idle,
        stream_mode: opt.stream_mode,
        frequency: opt.frequency,
        kprobe: opt.kprobe.clone(),
        uprobe: None,
        smart_uprobe,
        tracepoint: opt.tracepoint.clone(),
        pid,
        cpu: opt.cpu,
        self_profile: opt.self_profile,
        dwarf: opt.dwarf,
    })
}

/// Sets up the eBPF profiler, ring buffer, DWARF unwinding (if enabled),
/// and target-PID filtering.  Returns everything the profiling thread needs.
#[cfg(feature = "tui")]
fn setup_ebpf_and_dwarf(
    config: &ProfilerConfig,
    perf_tx: &mpsc::Sender<PerfWork>,
    pid: Option<u32>,
    dwarf: bool,
) -> Result<
    (
        EbpfProfiler,
        aya::maps::RingBuf<aya::maps::MapData>,
        Option<mpsc::Sender<u32>>,
    ),
    anyhow::Error,
> {
    let mut ebpf_profiler = setup_ebpf_profiler(config)?;
    let ring_buf = setup_ring_buffer(&mut ebpf_profiler.bpf)?;

    // Load DWARF unwind tables and start the background refresh thread
    let tgid_request_tx = if dwarf {
        let mut dwarf_manager = DwarfUnwindManager::new();
        if let Some(target_pid) = pid {
            println!("Loading DWARF unwind tables for pid {}...", target_pid);
            match dwarf_manager.load_process(target_pid) {
                Ok(()) => {
                    println!(
                        "Loaded {} unwind entries for pid {}",
                        dwarf_manager.total_entries(),
                        target_pid,
                    );
                    if let Err(e) = ebpf_profiler.load_dwarf_unwind_tables(&dwarf_manager) {
                        eprintln!("Failed to load DWARF unwind tables into eBPF: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load DWARF info for pid {}: {}", target_pid, e);
                }
            }
        }

        let (tgid_tx, tgid_rx) = mpsc::channel::<u32>();
        let refresh_tx = perf_tx.clone();
        let initial_pid = pid;
        std::thread::spawn(move || {
            dwarf_refresh_loop(dwarf_manager, initial_pid, tgid_rx, refresh_tx);
        });
        Some(tgid_tx)
    } else {
        None
    };

    // Set target PID for eBPF filtering AFTER DWARF tables are loaded
    if let Some(target_pid) = pid {
        ebpf_profiler.set_target_pid(target_pid)?;
        println!("Profiling PID {}..", target_pid);
    }

    Ok((ebpf_profiler, ring_buf, tgid_request_tx))
}

/// Spawns the background profiling thread that collects eBPF data,
/// builds collapsed stacks, updates the TUI, and optionally feeds
/// a web-server broadcast channel.
///
/// `web_tx` — pass `Some(sender)` for combined mode, `None` for TUI-only.
#[cfg(feature = "tui")]
fn spawn_profiling_thread(
    ebpf_profiler: EbpfProfiler,
    perf_rx: mpsc::Receiver<PerfWork>,
    tgid_request_tx: Option<mpsc::Sender<u32>>,
    update_handle: std::sync::Arc<std::sync::Mutex<Option<profile_bee_tui::app::ParsedFlameGraph>>>,
    update_mode_handle: std::sync::Arc<std::sync::Mutex<profile_bee_tui::state::UpdateMode>>,
    web_tx: Option<tokio::sync::broadcast::Sender<String>>,
    stream_mode: u8,
    group_by_cpu: bool,
    tui_refresh_ms: u64,
) {
    std::thread::spawn(move || {
        let mut profiler = TraceHandler::new();
        let mut counts = ebpf_profiler.counts;
        let stack_traces = ebpf_profiler.stack_traces;
        let stacked_pointers = ebpf_profiler.stacked_pointers;
        let mut bpf = ebpf_profiler.bpf;
        let mut trace_count = HashMap::<StackInfo, usize>::new();
        let mut known_tgids = std::collections::HashSet::<u32>::new();

        loop {
            // Drain the eBPF counts map (to prevent it from filling up) but
            // keep trace_count accumulating across cycles so the flamegraph
            // shows the full profile history, not just the latest window.
            let keys = counts.keys().flatten().collect::<Vec<_>>();
            for k in keys {
                let _ = counts.remove(&k);
            }

            // Compute local_counting before the loop to avoid double-counting
            let local_counting = stream_mode == EVENT_TRACE_ALWAYS;

            // Process incoming events with timeout to update periodically
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(tui_refresh_ms);
            while std::time::Instant::now() < deadline {
                match perf_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(PerfWork::StackInfo(stack)) => {
                        if let Some(tx) = &tgid_request_tx {
                            if stack.tgid != 0 && known_tgids.insert(stack.tgid) {
                                let _ = tx.send(stack.tgid);
                            }
                        }

                        if local_counting {
                            let trace = trace_count.entry(stack).or_insert(0);
                            *trace += 1;

                            if *trace == 1 {
                                let _combined = profiler.get_exp_stacked_frames(
                                    &stack,
                                    &stack_traces,
                                    group_by_cpu,
                                    &stacked_pointers,
                                );
                            }
                        } else {
                            // Only prime symbol cache for non-local counting
                            let _combined = profiler.get_exp_stacked_frames(
                                &stack,
                                &stack_traces,
                                group_by_cpu,
                                &stacked_pointers,
                            );
                        }
                    }
                    Ok(PerfWork::DwarfRefresh(update)) => {
                        apply_dwarf_refresh(&mut bpf, update);
                    }
                    Ok(PerfWork::Stop) => return,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }

            // Generate flamegraph data
            let mut stacks = Vec::new();

            // Apply update mode logic
            let current_mode = update_mode_handle.lock().unwrap_or_else(|e| e.into_inner()).clone();
            match current_mode {
                profile_bee_tui::state::UpdateMode::Reset => {
                    // Reset mode: clear trace_count each interval
                    trace_count.clear();
                }
                profile_bee_tui::state::UpdateMode::Accumulate => {
                    // Accumulate mode: keep accumulating (existing behavior)
                    // No action needed
                }
                profile_bee_tui::state::UpdateMode::Decay => {
                    // Decay mode: apply decay factor to existing counts
                    const DECAY_FACTOR: f64 = 0.75; // Decay to 75% each interval
                    for count in trace_count.values_mut() {
                        *count = (*count as f64 * DECAY_FACTOR) as usize;
                    }
                    // Remove entries that have decayed to near zero
                    trace_count.retain(|_, &mut count| count > 0);
                }
            }

            if !local_counting {
                // Merge eBPF-side counts into trace_count so we accumulate
                // across refresh cycles instead of showing only the latest window.
                for (key, value) in counts.iter().flatten() {
                    let stack: StackInfo = key.0;
                    // Prime the symbol cache for new stacks
                    if !trace_count.contains_key(&stack) {
                        let _combined = profiler.get_exp_stacked_frames(
                            &stack,
                            &stack_traces,
                            group_by_cpu,
                            &stacked_pointers,
                        );
                    }
                    *trace_count.entry(stack).or_insert(0) += value as usize;
                }
            }

            for (stack, value) in trace_count.iter() {
                let combined = profiler.get_exp_stacked_frames(
                    stack,
                    &stack_traces,
                    group_by_cpu,
                    &stacked_pointers,
                );
                stacks.push(FrameCount {
                    frames: combined,
                    count: *value as u64,
                });
            }

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

            // Update TUI app with new flamegraph data
            let data = out.join("\n");
            let tic = std::time::Instant::now();
            let flamegraph =
                profile_bee_tui::flame::FlameGraph::from_string(data, true);
            let parsed = profile_bee_tui::app::ParsedFlameGraph {
                flamegraph,
                elapsed: tic.elapsed(),
            };
            *update_handle.lock().unwrap_or_else(|e| {
                eprintln!("Mutex poisoned: {}", e);
                e.into_inner()
            }) = Some(parsed);

            // Optionally feed the web server
            if let Some(ref tx) = web_tx {
                let json = collapse_to_json(
                    &out.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
                );
                let _ = tx.send(json);
            }
        }
    });
}

/// Runs the TUI event loop until the user quits.
#[cfg(feature = "tui")]
fn run_tui_event_loop(
    app: &mut profile_bee_tui::app::App,
) -> Result<(), anyhow::Error> {
    use profile_bee_tui::{
        event::{Event, EventHandler},
        handler::handle_key_events,
        tui::Tui,
    };
    use std::io;

    let backend =
        profile_bee_tui::ratatui::backend::CrosstermBackend::new(io::stderr());
    let terminal = profile_bee_tui::ratatui::Terminal::new(backend)?;
    let events = EventHandler::new(250);
    let mut tui = Tui::new(terminal, events);
    tui.init().map_err(|e| anyhow::anyhow!("{e}"))?;

    while app.running {
        if app.dirty {
            tui.draw(app).map_err(|e| anyhow::anyhow!("{e}"))?;
            app.dirty = false;
        }

        match tui.events.next().map_err(|e| anyhow::anyhow!("{e}"))? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => {
                handle_key_events(key_event, app)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                app.dirty = true;
            }
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {
                app.dirty = true;
            }
        }
    }

    tui.exit().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Runs combined TUI + serve mode with shared profiling pipeline
#[cfg(feature = "tui")]
async fn run_combined_mode(
    opt: Opt,
    web_tx: tokio::sync::broadcast::Sender<String>,
) -> std::result::Result<(), anyhow::Error> {
    use profile_bee_tui::app::App;

    println!("Starting combined TUI + serve mode...");

    // Start web server
    let web_rx = web_tx.subscribe();
    tokio::spawn(async move {
        profile_bee::html::start_server(web_rx).await;
    });

    // Process / PID setup
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command)?;
    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid.clone()
    };

    // Shared infrastructure
    let config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&config, &perf_tx, pid, opt.dwarf)?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = App::with_live_and_mode(update_mode);
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid.clone() } else { None };
    setup_stopping_mechanisms(
        opt.time,
        perf_tx.clone(),
        stopper.clone(),
        spawn,
        external_pid,
    );

    // Ring buffer collection task
    task::spawn(async move {
        if let Err(e) = setup_ring_buffer_task(ring_buf, perf_tx).await {
            eprintln!("Failed to set up ring buffer: {:?}", e);
        }
    });

    // Profiling thread (feeds both TUI and web server)
    spawn_profiling_thread(
        ebpf_profiler,
        perf_rx,
        tgid_request_tx,
        update_handle,
        update_mode_handle,
        Some(web_tx),
        opt.stream_mode,
        opt.group_by_cpu,
        opt.tui_refresh_ms,
    );

    // TUI event loop
    run_tui_event_loop(&mut app)?;

    drop(stopper);
    println!("\nExiting combined mode");
    Ok(())
}

/// Runs the interactive TUI flamegraph viewer mode
#[cfg(feature = "tui")]
async fn run_tui_mode(opt: Opt) -> std::result::Result<(), anyhow::Error> {
    use profile_bee_tui::app::App;

    println!("Starting TUI mode...");

    // Process / PID setup
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command)?;
    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid.clone()
    };

    // Shared infrastructure
    let config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&config, &perf_tx, pid, opt.dwarf)?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = App::with_live_and_mode(update_mode);
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid } else { None };
    setup_stopping_mechanisms(
        opt.time,
        perf_tx.clone(),
        stopper.clone(),
        spawn,
        external_pid,
    );

    // Ring buffer collection task
    task::spawn(async move {
        if let Err(e) = setup_ring_buffer_task(ring_buf, perf_tx).await {
            eprintln!("Failed to set up ring buffer: {:?}", e);
        }
    });

    // Profiling thread (TUI only, no web feed)
    spawn_profiling_thread(
        ebpf_profiler,
        perf_rx,
        tgid_request_tx,
        update_handle,
        update_mode_handle,
        None,
        opt.stream_mode,
        opt.group_by_cpu,
        opt.tui_refresh_ms,
    );

    // TUI event loop
    run_tui_event_loop(&mut app)?;

    drop(stopper);
    println!("\nExiting TUI mode");
    Ok(())
}
