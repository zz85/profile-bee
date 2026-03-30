use clap::Parser;
use profile_bee::dwarf_unwind::DwarfUnwindManager;
use profile_bee::ebpf::{
    apply_dwarf_refresh, attach_process_exit_tracepoint, setup_ebpf_with_tp_fallback,
    setup_process_exit_ring_buffer, setup_ring_buffer, EbpfProfiler, ProfilerConfig,
};
use profile_bee::event_loop::{EventLoopConfig, ProfilingEventLoop};
use profile_bee::html::collapse_to_json;
use profile_bee::output::{
    CodeGuruSink, CollapseSink, HtmlSink, JsonFileSink, MultiplexSink, OutputSink, PprofSink,
    SvgSink, WebBroadcastSink,
};
use profile_bee::pipeline::{
    dwarf_refresh_loop, setup_ctrlc_stop, setup_process_exit_ring_buffer_task,
    setup_ring_buffer_task, setup_timer_and_child_stop, DwarfThreadMsg, PerfWork,
};
use profile_bee::probe_resolver::{
    format_resolved_probes, resolve_uprobe_specs, uprobe_pid_as_u32, ProbeResolver,
};
use profile_bee::probe_spec::parse_probe_spec;
use profile_bee::spawn::setup_process_to_profile;
use profile_bee::TraceHandler;
use profile_bee_common::{StackInfo, EVENT_TRACE_ALWAYS};
use tokio::task;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use profile_bee::types::FrameCount;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "eBPF-based CPU profiler with flamegraph generation and interactive TUI.\n\
             Supports kprobe, uprobe (with glob/regex matching), and tracepoint probes.\n\
             Renders TUI, SVG, JSON, stackcollapse, HTML. Run --help for examples.",
    long_about = None,
    override_usage = "(sudo) probee [OPTIONS] [-- <COMMAND>...]",
    after_long_help = "\x1b[1mExamples:\x1b[0m
  # Interactive TUI flamegraph (live profiling)
  sudo probee --tui

  # TUI with a specific command
  sudo probee --tui --cmd \"my-application\"

  # Profile system-wide for 5s, generate SVG flamegraph
  sudo probee --svg flamegraph.svg --time 5000

  # Profile a command, writing output to SVG
  sudo probee --svg output.svg -- ./my-binary arg1 arg2

  # DWARF unwinding for binaries without frame pointers
  sudo probee --tui --dwarf --cmd \"./optimized-binary\"

  # Profile at high frequency, multiple output formats
  sudo probee --frequency 999 --time 5000 --svg out.svg --html out.html

  # Real-time flamegraphs via web server
  sudo probee --serve --skip-idle

  # Trace specific syscalls via kprobe/tracepoint/uprobe
  sudo probee --kprobe vfs_write --time 200 --svg kprobe.svg
  sudo probee --uprobe malloc --time 1000 --svg malloc.svg
  sudo probee --uprobe 'pthread_*' --time 1000 --svg pthread.svg

  # Discovery mode — list matching probe targets
  sudo probee --list-probes 'pthread_*'

  # Off-CPU profiling — measure blocked/waiting time
  sudo probee --off-cpu --svg offcpu.svg --time 5000
  sudo probee --off-cpu --tui --pid 1234
  sudo probee --off-cpu --min-block-time 100 --svg offcpu.svg -- ./my-app

\x1b[1mShort alias:\x1b[0m pbee (e.g., sudo pbee --tui)"
)]
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

    /// Filename for pprof protobuf output (gzip-compressed, .pb.gz).
    /// Compatible with `go tool pprof`, Grafana/Pyroscope, Speedscope, etc.
    #[arg(long)]
    pprof: Option<PathBuf>,

    /// Filename for AWS CodeGuru Profiler JSON output.
    /// Output can be uploaded via `aws codeguruprofiler post-agent-profile`.
    #[arg(long)]
    codeguru: Option<PathBuf>,

    /// Upload profile directly to AWS CodeGuru Profiler.
    /// Requires --profiling-group. Uses standard AWS credential chain.
    /// Build with `--features aws` to enable.
    #[cfg(feature = "aws")]
    #[arg(long)]
    codeguru_upload: bool,

    /// AWS CodeGuru profiling group name (required with --codeguru-upload).
    #[cfg(feature = "aws")]
    #[arg(long)]
    profiling_group: Option<String>,

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

    /// Disable mouse support for TUI flamegraph navigation
    #[cfg(feature = "tui")]
    #[arg(long)]
    no_tui_mouse: bool,

    /// Avoid profiling idle cpu cycles
    #[arg(long)]
    skip_idle: bool,

    /// Time to run CPU profiling in milliseconds (0 = run until Ctrl-C).
    /// Defaults to 10000 in CLI mode; defaults to 0 (unlimited) in --tui / --serve modes.
    #[arg(short, long)]
    time: Option<usize>,

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

    /// Group flamegraph by process name and PID. Each process gets its own
    /// sub-tree rooted at "process_name (pid)". Useful for system-wide profiling.
    #[arg(long, default_value_t = false)]
    group_by_process: bool,

    /// Enable DWARF-based stack unwinding (for binaries without frame pointers)
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    dwarf: Option<bool>,

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

    /// Enable off-CPU profiling mode. Measures blocked/waiting time instead of
    /// CPU samples by tracing context switches via kprobe on finish_task_switch.
    /// Output values represent microseconds of off-CPU (blocked) time.
    /// Mutually exclusive with --kprobe, --uprobe, --tracepoint.
    #[arg(long)]
    off_cpu: bool,

    /// Minimum off-CPU block time to record in microseconds (default 1).
    /// Context switches shorter than this are filtered out to reduce noise.
    /// Only effective with --off-cpu.
    #[arg(long, default_value_t = 1)]
    min_block_time: u64,

    /// Maximum off-CPU block time to record in microseconds (default unlimited).
    /// Context switches longer than this are filtered out.
    /// Only effective with --off-cpu.
    #[arg(long, default_value_t = u64::MAX)]
    max_block_time: u64,
}

impl Opt {
    /// Returns true if the user expressed any profiling intent via flags.
    /// When false, we show help instead of silently starting a system-wide profile.
    fn has_user_intent(&self) -> bool {
        // Any output format requested
        self.collapse.is_some()
            || self.svg.is_some()
            || self.html.is_some()
            || self.json.is_some()
            || self.pprof.is_some()
            || self.codeguru.is_some()
            || { #[cfg(feature = "aws")] { self.codeguru_upload } #[cfg(not(feature = "aws"))] { false } }
            // Interactive modes
            || self.serve
            || { #[cfg(feature = "tui")] { self.tui } #[cfg(not(feature = "tui"))] { false } }
            // Target selection
            || self.pid.is_some()
            || self.cmd.is_some()
            || !self.command.is_empty()
            || self.self_profile
            // Probe types
            || self.kprobe.is_some()
            || !self.uprobe.is_empty()
            || self.tracepoint.is_some()
            || self.list_probes.is_some()
            // Explicit time means the user wants to profile
            || self.time.is_some()
            // Off-CPU profiling mode
            || self.off_cpu
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // If no meaningful flags were provided, show help with examples and exit.
    if !opt.has_user_intent() {
        use clap::CommandFactory;
        let bin_name = std::env::args()
            .next()
            .unwrap_or_else(|| "probee".to_string());
        Opt::command().bin_name(bin_name).print_long_help()?;
        std::process::exit(0);
    }

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
        // Warn about output flags that TUI mode doesn't support
        let unsupported: Vec<&str> = [
            opt.pprof.as_ref().map(|_| "--pprof"),
            opt.codeguru.as_ref().map(|_| "--codeguru"),
            opt.svg.as_ref().map(|_| "--svg"),
            opt.html.as_ref().map(|_| "--html"),
            opt.json.as_ref().map(|_| "--json"),
            opt.collapse.as_ref().map(|_| "--collapse"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !unsupported.is_empty() {
            eprintln!(
                "Warning: {} ignored in TUI mode (TUI has its own output pipeline)",
                unsupported.join(", ")
            );
        }

        if opt.serve {
            // Combined TUI + serve mode
            return run_combined_mode(opt, tx).await;
        } else {
            // TUI only mode
            return run_tui_mode(opt).await;
        }
    }

    if opt.serve {
        tracing::info!("Spawning web server task on port 8000");
        tokio::spawn(async {
            profile_bee::html::start_server(rx).await;
        });
    }

    println!("Starting {:?}", opt);

    if opt.off_cpu {
        println!("Off-CPU profiling mode: tracing context switches via finish_task_switch");
        println!(
            "  Block time filter: {} - {} us",
            opt.min_block_time,
            if opt.max_block_time == u64::MAX {
                "unlimited".to_string()
            } else {
                opt.max_block_time.to_string()
            }
        );
    }

    // Handle --list-probes discovery mode (print and exit)
    if let Some(ref probe_str) = opt.list_probes {
        return handle_list_probes(probe_str, opt.pid, opt.uprobe_pid);
    }

    // profile_bee::load(&opt.cmd.unwrap()).unwrap();
    // return Ok(());

    // Validate mutually exclusive options
    if opt.off_cpu && (opt.kprobe.is_some() || !opt.uprobe.is_empty() || opt.tracepoint.is_some()) {
        return Err(anyhow::anyhow!(
            "--off-cpu is mutually exclusive with --kprobe, --uprobe, and --tracepoint"
        ));
    }

    // Resolve smart uprobe specs (if any)
    let smart_uprobe = if !opt.uprobe.is_empty() {
        Some(resolve_uprobe_specs(&opt.uprobe, opt.pid, opt.uprobe_pid)?)
    } else {
        None
    };

    // Create eBPF profiler configuration from command line options (without pid first)
    let mut config = ProfilerConfig {
        skip_idle: opt.skip_idle,
        stream_mode: opt.stream_mode,
        frequency: opt.frequency,
        kprobe: opt.kprobe.clone(),
        uprobe: None,
        smart_uprobe,
        tracepoint: opt.tracepoint.clone(),
        raw_tracepoint: None,
        raw_tracepoint_task_regs: None,
        raw_tracepoint_generic: None,
        target_syscall_nr: -1,
        pid: opt.pid,
        cpu: opt.cpu,
        self_profile: opt.self_profile,
        dwarf: opt.dwarf.unwrap_or(false),
        off_cpu: opt.off_cpu,
        min_block_us: opt.min_block_time,
        max_block_us: opt.max_block_time,
    };

    // Setup eBPF profiler first to ensure verification succeeds
    let verification_start = std::time::Instant::now();
    let mut ebpf_profiler = setup_ebpf_with_tp_fallback(&mut config)?;
    let verification_time = verification_start.elapsed();
    println!("eBPF verification completed in {:?}", verification_time);

    // Only spawn process after eBPF verification succeeds
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command, false)?;

    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid
    };

    // Set up communication channels (before DWARF block so refresh thread can use it)
    let (perf_tx, perf_rx) = mpsc::channel();

    // If DWARF unwinding is enabled, load unwind tables BEFORE setting TARGET_PID
    // This ensures unwind information is available from the first sample
    let tgid_request_tx = if opt.dwarf.unwrap_or(false) {
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
                        tracing::error!("Failed to load DWARF unwind tables into eBPF: {:?}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to load DWARF info: {}", e);
                }
            }
        }

        // Channel for DWARF thread messages (new process loads + exit cleanup)
        let (tgid_tx, tgid_rx) = mpsc::channel::<DwarfThreadMsg>();
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

    // Set up process exit monitoring:
    // - For external PIDs (--pid): detects when the target process exits to stop profiling.
    // - For DWARF mode: detects when any tracked process exits to clean up LPM trie entries.
    let external_pid = if spawn.is_none() { opt.pid } else { None };
    let dwarf_enabled = opt.dwarf.unwrap_or(false);
    let monitor_exit_pid: Option<u32> = external_pid;

    if external_pid.is_some() || dwarf_enabled {
        // Attach the sched_process_exit tracepoint
        attach_process_exit_tracepoint(&mut ebpf_profiler.bpf)?;

        // Set the PID to monitor for stop-on-exit (0 = don't stop, just DWARF cleanup)
        if let Some(pid_to_monitor) = external_pid {
            ebpf_profiler.set_monitor_exit_pid(pid_to_monitor)?;
        }

        // Set up the ring buffer for process exit events
        let exit_ring_buf = setup_process_exit_ring_buffer(&mut ebpf_profiler.bpf)?;
        let exit_perf_tx = perf_tx.clone();
        task::spawn(async move {
            if let Err(e) = setup_process_exit_ring_buffer_task(exit_ring_buf, exit_perf_tx).await {
                eprintln!("Failed to set up process exit ring buffer: {:?}", e);
            }
        });

        if let Some(pid_to_monitor) = external_pid {
            println!(
                "eBPF-based exit monitoring enabled for PID {}",
                pid_to_monitor
            );
        }
    }

    // Build the event loop from eBPF profiler parts
    let event_loop_config = EventLoopConfig {
        stream_mode: opt.stream_mode,
        group_by_cpu: opt.group_by_cpu,
        group_by_process: opt.group_by_process,
        monitor_exit_pid,
        tgid_request_tx,
    };
    let mut event_loop = ProfilingEventLoop::new(
        ebpf_profiler.counts,
        ebpf_profiler.stack_traces,
        ebpf_profiler.stacked_pointers,
        ebpf_profiler.bpf,
        event_loop_config,
    );

    // Set up stopping mechanisms
    // CLI defaults to 10s profiling windows;
    // serve mode defaults to unlimited (like TUI modes).
    let duration = opt.time.unwrap_or(if opt.serve { 0 } else { 10000 });
    setup_timer_and_child_stop(duration, perf_tx.clone(), spawn);
    setup_ctrlc_stop(perf_tx.clone(), stopper.clone());
    println!("Waiting for Ctrl-C...");

    task::spawn(async move {
        if let Err(e) = setup_ring_buffer_task(ring_buf, perf_tx).await {
            eprintln!("Failed to set up ring buffer: {:?}", e);
        }
    });

    let started = Instant::now();

    // Build output sink from CLI options
    let mut sinks: Vec<Box<dyn OutputSink>> = Vec::new();
    if let Some(svg_path) = &opt.svg {
        let title = if opt.off_cpu {
            format!(
                "Off-CPU Time Flame Graph ({}ms, finish_task_switch)",
                opt.time.unwrap_or(10000)
            )
        } else {
            format!(
                "Flamegraph profile generated from profile-bee ({}ms @ {}hz)",
                opt.time.unwrap_or(10000),
                opt.frequency
            )
        };
        sinks.push(Box::new(SvgSink::new(svg_path.clone(), title, opt.off_cpu)));
    }
    if let Some(html_path) = &opt.html {
        sinks.push(Box::new(HtmlSink::new(html_path.clone())));
    }
    if let Some(json_path) = &opt.json {
        sinks.push(Box::new(JsonFileSink::new(json_path.clone())));
    }
    if let Some(collapse_path) = &opt.collapse {
        sinks.push(Box::new(CollapseSink::new(collapse_path.clone())));
    }
    if let Some(pprof_path) = &opt.pprof {
        sinks.push(Box::new(PprofSink::new(
            pprof_path.clone(),
            opt.frequency,
            opt.time.unwrap_or(10000) as u64,
            opt.off_cpu,
        )));
    }
    if let Some(codeguru_path) = &opt.codeguru {
        sinks.push(Box::new(CodeGuruSink::new(
            codeguru_path.clone(),
            opt.frequency,
            opt.time.unwrap_or(10000) as u64,
            opt.off_cpu,
        )));
    }
    #[cfg(feature = "aws")]
    if opt.codeguru_upload {
        let group = opt
            .profiling_group
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--codeguru-upload requires --profiling-group"))?;
        let codeguru_opts = profile_bee::codeguru::CodeGuruOptions {
            frequency_hz: opt.frequency,
            duration_ms: opt.time.unwrap_or(10000) as u64,
            counter_type: if opt.off_cpu {
                profile_bee::codeguru::CounterType::Waiting
            } else {
                profile_bee::codeguru::CounterType::Runnable
            },
            ..Default::default()
        };
        sinks.push(Box::new(
            profile_bee::codeguru_upload::CodeGuruUploadSink::new(
                group.clone(),
                codeguru_opts,
                opt.codeguru.clone(), // also save locally if --codeguru was specified
                tokio::runtime::Handle::current(),
            ),
        ));
    }
    if opt.serve {
        sinks.push(Box::new(WebBroadcastSink::new(tx)));
    }
    let mut sink = MultiplexSink::new(sinks);

    if opt.serve {
        // Serve mode: periodically flush data to the web server
        let flush_interval = std::time::Duration::from_secs(2);
        let mut last_stacks = Vec::new();

        loop {
            tracing::debug!("serve loop: collecting samples for {:?}", flush_interval);
            let result = event_loop.collect(&perf_rx, Some(flush_interval));
            tracing::debug!(
                "serve loop: flushing {} stacks to web server (stopped={})",
                result.stacks.len(),
                result.stopped
            );
            sink.write_batch(&result.stacks)?;
            if !result.stacks.is_empty() {
                last_stacks = result.stacks;
            }
            if result.stopped {
                break;
            }
        }
        sink.set_actual_duration_ms(started.elapsed().as_millis() as u64);
        sink.finish(&last_stacks)?;
    } else {
        // Non-serve mode: block until Stop, output once, exit.
        tracing::debug!("batch mode: collecting samples (blocks until Stop)");
        let result = event_loop.collect(&perf_rx, None);
        tracing::debug!("batch mode: collected {} stacks", result.stacks.len());
        sink.write_batch(&result.stacks)?;
        sink.set_actual_duration_ms(started.elapsed().as_millis() as u64);
        sink.finish(&result.stacks)?;
    }

    drop(stopper);

    tracing::info!("Profiler ran for {:?}", started.elapsed());

    event_loop.print_stats();

    // Log DWARF tail-call fallback diagnostics if DWARF was enabled
    if opt.dwarf.unwrap_or(false) {
        use profile_bee::ebpf::EbpfProfiler;
        if let Some(fallback_count) = EbpfProfiler::read_dwarf_stats_from_bpf(event_loop.bpf_mut())
        {
            if fallback_count > 0 {
                eprintln!(
                    "DWARF tail-call fallback: {} samples used legacy {}-frame path",
                    fallback_count,
                    profile_bee_common::LEGACY_MAX_DWARF_STACK_DEPTH,
                );
            } else {
                tracing::info!(
                    "DWARF tail-call unwinding: all samples used tail-call path (165 frames)"
                );
            }
        }
    }

    Ok(())
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

// ---------------------------------------------------------------------------
// Shared helpers for TUI and combined (TUI + serve) modes
// ---------------------------------------------------------------------------

/// Builds a `ProfilerConfig` from CLI options, resolving smart uprobe specs.
#[cfg(feature = "tui")]
fn build_profiler_config(opt: &Opt, pid: Option<u32>) -> Result<ProfilerConfig, anyhow::Error> {
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
        raw_tracepoint: None,
        raw_tracepoint_task_regs: None,
        raw_tracepoint_generic: None,
        target_syscall_nr: -1,
        pid,
        cpu: opt.cpu,
        self_profile: opt.self_profile,
        dwarf: opt.dwarf.unwrap_or(false),
        off_cpu: opt.off_cpu,
        min_block_us: opt.min_block_time,
        max_block_us: opt.max_block_time,
    })
}

/// Sets up the eBPF profiler, ring buffer, DWARF unwinding (if enabled),
/// and target-PID filtering.  Returns everything the profiling thread needs.
#[cfg(feature = "tui")]
#[allow(clippy::type_complexity)]
fn setup_ebpf_and_dwarf(
    config: &mut ProfilerConfig,
    perf_tx: &mpsc::Sender<PerfWork>,
    pid: Option<u32>,
    dwarf: bool,
) -> Result<
    (
        EbpfProfiler,
        aya::maps::RingBuf<aya::maps::MapData>,
        Option<mpsc::Sender<DwarfThreadMsg>>,
    ),
    anyhow::Error,
> {
    let mut ebpf_profiler = setup_ebpf_with_tp_fallback(config)?;
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
                        tracing::error!("Failed to load DWARF unwind tables into eBPF: {:?}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to load DWARF info: {}", e);
                }
            }
        }

        let (tgid_tx, tgid_rx) = mpsc::channel::<DwarfThreadMsg>();
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
#[allow(clippy::too_many_arguments)]
fn spawn_profiling_thread(
    ebpf_profiler: EbpfProfiler,
    perf_rx: mpsc::Receiver<PerfWork>,
    tgid_request_tx: Option<mpsc::Sender<DwarfThreadMsg>>,
    update_handle: std::sync::Arc<std::sync::Mutex<Option<profile_bee_tui::app::ParsedFlameGraph>>>,
    update_mode_handle: std::sync::Arc<std::sync::Mutex<profile_bee_tui::state::UpdateMode>>,
    web_tx: Option<tokio::sync::broadcast::Sender<String>>,
    stream_mode: u8,
    group_by_cpu: bool,
    group_by_process: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tui_refresh_ms: u64,
    monitor_exit_pid: Option<u32>,
) {
    std::thread::spawn(move || {
        let mut profiler = TraceHandler::new();
        profiler.prewarm_kernel_symbols();
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
            let gbp = group_by_process.load(std::sync::atomic::Ordering::Relaxed);

            // Process incoming events until the refresh deadline, so we
            // batch samples over the full tui_refresh_ms window instead of
            // rebuilding the flamegraph on every brief gap in events.
            // Clamp to 1ms minimum to prevent hot-spinning when tui_refresh_ms == 0.
            let refresh_ms = tui_refresh_ms.max(1);
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(refresh_ms);
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match perf_rx.recv_timeout(remaining) {
                    Ok(PerfWork::StackInfo(stack)) => {
                        if let Some(tx) = &tgid_request_tx {
                            if stack.tgid != 0 && known_tgids.insert(stack.tgid) {
                                let _ = tx.send(DwarfThreadMsg::LoadProcess(stack.tgid));
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
                                    gbp,
                                    &stacked_pointers,
                                );
                            }
                        } else {
                            // Only prime symbol cache for non-local counting
                            let _combined = profiler.get_exp_stacked_frames(
                                &stack,
                                &stack_traces,
                                group_by_cpu,
                                gbp,
                                &stacked_pointers,
                            );
                        }
                    }
                    Ok(PerfWork::DwarfRefresh(update)) => {
                        if let Err(e) = apply_dwarf_refresh(&mut bpf, update) {
                            tracing::warn!("{:#}", e);
                        }
                    }
                    Ok(PerfWork::ProcessExit(exit_event)) => {
                        // Forward to DWARF thread for LPM trie cleanup
                        if let Some(tx) = &tgid_request_tx {
                            let _ = tx.send(DwarfThreadMsg::ProcessExited(exit_event.pid));
                        }
                        // Allow PID reuse to trigger a fresh LoadProcess
                        known_tgids.remove(&exit_event.pid);
                        // Only stop profiling if this is the monitored target process
                        if Some(exit_event.pid) == monitor_exit_pid {
                            tracing::info!(
                                "target process {} exited, stopping TUI",
                                exit_event.pid
                            );
                            return;
                        }
                    }
                    Ok(PerfWork::Stop) => return,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }

            // Generate flamegraph data
            let mut stacks = Vec::new();

            // Apply update mode logic
            let current_mode = *update_mode_handle.lock().unwrap_or_else(|e| e.into_inner());
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
                            gbp,
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
                    gbp,
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
            let flamegraph = profile_bee_tui::flame::FlameGraph::from_string(data, true);
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
                let json = collapse_to_json(&out.iter().map(|v| v.as_str()).collect::<Vec<_>>());
                let _ = tx.send(json);
            }
        }
    });
}

/// Runs the TUI event loop until the user quits.
#[cfg(feature = "tui")]
fn run_tui_event_loop(
    app: &mut profile_bee_tui::app::App,
    mouse_enabled: bool,
) -> Result<(), anyhow::Error> {
    use profile_bee_tui::{
        event::{Event, EventHandler},
        handler::{handle_key_events, handle_mouse_events},
        tui::Tui,
    };
    use std::io;

    let backend = profile_bee_tui::ratatui::backend::CrosstermBackend::new(io::stderr());
    let terminal = profile_bee_tui::ratatui::Terminal::new(backend)?;
    let events = EventHandler::new(250);
    let mut tui = Tui::new(terminal, events);
    tui.init(mouse_enabled)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    while app.running {
        if app.dirty {
            tui.draw(app).map_err(|e| anyhow::anyhow!("{e}"))?;
            app.dirty = false;
        }

        match tui.events.next().map_err(|e| anyhow::anyhow!("{e}"))? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => {
                handle_key_events(key_event, app).map_err(|e| anyhow::anyhow!("{e}"))?;
                app.dirty = true;
            }
            Event::Mouse(mouse_event) => {
                if mouse_enabled {
                    let changed = handle_mouse_events(mouse_event, app)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    if changed {
                        app.dirty = true;
                    }
                }
            }
            Event::Resize(_, _) => {
                app.dirty = true;
            }
        }
    }

    tui.exit().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Process output monitoring (TUI mode)
// ---------------------------------------------------------------------------

/// Reads lines from the child process's stdout and stderr and pushes them
/// into the shared [`ProcessOutputBuffer`] for display in the TUI.
///
/// ANSI escape codes are stripped so that ratatui can render cleanly.
#[cfg(feature = "tui")]
async fn monitor_child_output(
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    buf: profile_bee_tui::output::SharedOutputBuffer,
) {
    use profile_bee_tui::output::OutputStream;
    use tokio::io::{AsyncBufReadExt, BufReader};

    /// Strip ANSI escape sequences from a string.
    fn strip_ansi(s: &str) -> String {
        let stripped = strip_ansi_escapes::strip(s.as_bytes());
        String::from_utf8_lossy(&stripped).into_owned()
    }

    /// Read lines from a stream and push them into the shared buffer.
    /// After each awaited read, drains any additional complete lines
    /// already in the BufReader's internal buffer before releasing the
    /// mutex, reducing lock acquisitions under high output.
    async fn drain_stream<R: tokio::io::AsyncRead + Unpin>(
        reader: R,
        stream: OutputStream,
        buf: profile_bee_tui::output::SharedOutputBuffer,
    ) {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Collect this line plus any others already buffered.
                    let mut batch = vec![strip_ansi(
                        line.trim_end_matches('\n').trim_end_matches('\r'),
                    )];

                    // Drain additional complete lines from the internal buffer
                    // without awaiting (no yield = stays on this thread).
                    loop {
                        let available = reader.buffer();
                        if available.is_empty() || !available.contains(&b'\n') {
                            break;
                        }
                        line.clear();
                        // Data is already buffered — read_line resolves instantly.
                        match reader.read_line(&mut line).await {
                            Ok(0) => break,
                            Ok(_) => {
                                batch.push(strip_ansi(
                                    line.trim_end_matches('\n').trim_end_matches('\r'),
                                ));
                            }
                            Err(_) => break,
                        }
                    }

                    // Single lock acquisition for the whole batch.
                    match buf.lock() {
                        Ok(mut b) => {
                            for text in batch {
                                b.push(text, stream);
                            }
                        }
                        Err(_) => {
                            // Mutex poisoned — TUI thread panicked.
                            // Drop the batch and stop reading.
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }

    let stdout_task = async {
        if let Some(stdout) = stdout {
            drain_stream(stdout, OutputStream::Stdout, buf.clone()).await;
        }
    };

    let stderr_task = async {
        if let Some(stderr) = stderr {
            drain_stream(stderr, OutputStream::Stderr, buf.clone()).await;
        }
    };

    tokio::join!(stdout_task, stderr_task);

    // Mark that the process has exited
    if let Ok(mut b) = buf.lock() {
        b.push("[process exited]".to_string(), OutputStream::Stderr);
    }
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
    use profile_bee_tui::output::{ProcessOutputBuffer, SharedOutputBuffer};

    println!("Starting combined TUI + serve mode...");

    // Start web server
    let web_rx = web_tx.subscribe();
    tokio::spawn(async move {
        profile_bee::html::start_server(web_rx).await;
    });

    // Process / PID setup — capture output when a child is spawned
    let (stopper, mut spawn) = setup_process_to_profile(&opt.cmd, &opt.command, true)?;
    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid
    };

    // Set up process output capture before handing spawn to the child-stop task.
    let output_buffer: Option<SharedOutputBuffer> = if spawn.is_some() {
        Some(ProcessOutputBuffer::shared())
    } else {
        None
    };

    if let (Some(ref mut child), Some(ref buf)) = (&mut spawn, &output_buffer) {
        let stdout = child.take_stdout();
        let stderr = child.take_stderr();
        let buf_clone = buf.clone();
        task::spawn(async move {
            monitor_child_output(stdout, stderr, buf_clone).await;
        });
    }

    // Shared infrastructure
    let mut config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (mut ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&mut config, &perf_tx, pid, opt.dwarf.unwrap_or(false))?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = if let Some(buf) = output_buffer {
        App::with_live_and_output(update_mode, buf)
    } else {
        App::with_live_and_mode(update_mode)
    };
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();
    let pid_mode_handle = app.get_pid_mode_handle();
    pid_mode_handle.store(opt.group_by_process, std::sync::atomic::Ordering::Relaxed);

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid } else { None };

    // Process exit monitoring (same as main batch path)
    if external_pid.is_some() || opt.dwarf.unwrap_or(false) {
        attach_process_exit_tracepoint(&mut ebpf_profiler.bpf)?;
        if let Some(pid_to_monitor) = external_pid {
            ebpf_profiler.set_monitor_exit_pid(pid_to_monitor)?;
        }
        let exit_ring_buf = setup_process_exit_ring_buffer(&mut ebpf_profiler.bpf)?;
        let exit_perf_tx = perf_tx.clone();
        task::spawn(async move {
            if let Err(e) = setup_process_exit_ring_buffer_task(exit_ring_buf, exit_perf_tx).await {
                eprintln!("Failed to set up process exit ring buffer: {:?}", e);
            }
        });
    }

    setup_timer_and_child_stop(opt.time.unwrap_or(0), perf_tx.clone(), spawn);
    setup_ctrlc_stop(perf_tx.clone(), stopper.clone());

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
        pid_mode_handle.clone(),
        opt.tui_refresh_ms,
        external_pid,
    );

    // TUI event loop
    run_tui_event_loop(&mut app, !opt.no_tui_mouse)?;

    drop(stopper);
    println!("\nExiting combined mode");
    Ok(())
}

/// Runs the interactive TUI flamegraph viewer mode
#[cfg(feature = "tui")]
async fn run_tui_mode(opt: Opt) -> std::result::Result<(), anyhow::Error> {
    use profile_bee_tui::app::App;
    use profile_bee_tui::output::{ProcessOutputBuffer, SharedOutputBuffer};

    println!("Starting TUI mode...");

    // Process / PID setup — capture output when a child is spawned
    let (stopper, mut spawn) = setup_process_to_profile(&opt.cmd, &opt.command, true)?;
    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid
    };

    // Set up process output capture before handing spawn to the child-stop task.
    let output_buffer: Option<SharedOutputBuffer> = if spawn.is_some() {
        Some(ProcessOutputBuffer::shared())
    } else {
        None
    };

    if let (Some(ref mut child), Some(ref buf)) = (&mut spawn, &output_buffer) {
        let stdout = child.take_stdout();
        let stderr = child.take_stderr();
        let buf_clone = buf.clone();
        task::spawn(async move {
            monitor_child_output(stdout, stderr, buf_clone).await;
        });
    }

    // Shared infrastructure
    let mut config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (mut ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&mut config, &perf_tx, pid, opt.dwarf.unwrap_or(false))?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = if let Some(buf) = output_buffer {
        App::with_live_and_output(update_mode, buf)
    } else {
        App::with_live_and_mode(update_mode)
    };
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();
    let pid_mode_handle = app.get_pid_mode_handle();
    pid_mode_handle.store(opt.group_by_process, std::sync::atomic::Ordering::Relaxed);

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid } else { None };

    // Process exit monitoring (same as main batch path)
    if external_pid.is_some() || opt.dwarf.unwrap_or(false) {
        attach_process_exit_tracepoint(&mut ebpf_profiler.bpf)?;
        if let Some(pid_to_monitor) = external_pid {
            ebpf_profiler.set_monitor_exit_pid(pid_to_monitor)?;
        }
        let exit_ring_buf = setup_process_exit_ring_buffer(&mut ebpf_profiler.bpf)?;
        let exit_perf_tx = perf_tx.clone();
        task::spawn(async move {
            if let Err(e) = setup_process_exit_ring_buffer_task(exit_ring_buf, exit_perf_tx).await {
                eprintln!("Failed to set up process exit ring buffer: {:?}", e);
            }
        });
    }

    setup_timer_and_child_stop(opt.time.unwrap_or(0), perf_tx.clone(), spawn);
    setup_ctrlc_stop(perf_tx.clone(), stopper.clone());

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
        pid_mode_handle.clone(),
        opt.tui_refresh_ms,
        external_pid,
    );

    // TUI event loop
    run_tui_event_loop(&mut app, !opt.no_tui_mouse)?;

    drop(stopper);
    println!("\nExiting TUI mode");
    Ok(())
}
