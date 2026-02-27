use aya::maps::{MapData, RingBuf, StackTraceMap};
use aya::Ebpf;
use clap::Parser;
use inferno::flamegraph::{self, Options};
use profile_bee::dwarf_unwind::DwarfUnwindManager;
use profile_bee::ebpf::{
    apply_dwarf_refresh, setup_ebpf_profiler, setup_ring_buffer, EbpfProfiler, ProfilerConfig,
    SmartUProbeConfig, StackInfoPod,
};
use profile_bee::ebpf::{
    attach_process_exit_tracepoint, setup_process_exit_ring_buffer, FramePointersPod,
};
use profile_bee::html::{collapse_to_json, generate_html_file};
use profile_bee::pipeline::{dwarf_refresh_loop, DwarfThreadMsg, PerfWork};
use profile_bee::probe_resolver::{format_resolved_probes, ProbeResolver, ResolvedProbe};
use profile_bee::probe_spec::parse_probe_spec;
use profile_bee::spawn::{SpawnProcess, StopHandler};
use profile_bee::TraceHandler;
use profile_bee_common::{ProcessExitEvent, StackInfo, EVENT_TRACE_ALWAYS};
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
fn parse_syscall_tracepoint(tp: &str) -> Option<(&str, i64)> {
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
fn syscall_name_to_nr(name: &str) -> Option<i64> {
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
fn setup_ebpf_with_tp_fallback(config: &mut ProfilerConfig) -> Result<EbpfProfiler, anyhow::Error> {
    if let Some(tp) = config.tracepoint.clone() {
        // Determine the raw tracepoint name to use for fallback attempts.
        // For syscall tracepoints (e.g. "syscalls:sys_enter_write") we must
        // use the aggregate name ("sys_enter") — per-syscall names like
        // "sys_enter_write" don't exist as raw tracepoints.
        // For non-syscall tracepoints we use the event name after the colon.
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
        // (has pt_regs in args[0], syscall NR filtering via args[1])
        if let Some(syscall_nr) = syscall_info {
            let tp_saved = config.tracepoint.take();
            config.raw_tracepoint = Some(raw_tp_name.clone());
            config.target_syscall_nr = syscall_nr;

            match setup_ebpf_profiler(config) {
                Ok(profiler) => {
                    eprintln!(
                        "Attached via raw tracepoint '{}' (syscall nr={})",
                        raw_tp_name, syscall_nr
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    eprintln!(
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
                    eprintln!(
                        "Attached via raw tracepoint '{}' (task pt_regs, full unwinding)",
                        raw_tp_name
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    eprintln!(
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
                    eprintln!(
                        "Attached via generic raw tracepoint '{}' (stackid only)",
                        raw_tp_name
                    );
                    return Ok(profiler);
                }
                Err(e) => {
                    eprintln!(
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

/// Extract the tracepoint name from "category:name" format for raw_tp attachment.
/// For raw tracepoints, the name is just the event name without the category.
fn parse_tracepoint_name(tp: &str) -> Option<&str> {
    tp.split(':').nth(1)
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
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command)?;

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

    let counts = &mut ebpf_profiler.counts;
    let stack_traces = &ebpf_profiler.stack_traces;
    let stacked_pointers = &ebpf_profiler.stacked_pointers;

    let mut profiler = TraceHandler::new();
    profiler.prewarm_kernel_symbols();

    // Set up stopping mechanisms
    // CLI defaults to 10s profiling windows;
    // serve mode defaults to unlimited (like TUI modes).
    let duration = opt.time.unwrap_or(if opt.serve { 0 } else { 10000 });
    setup_stopping_mechanisms(
        duration,
        perf_tx.clone(),
        stopper.clone(),
        spawn,
        external_pid,
    );

    task::spawn(async move {
        if let Err(e) = setup_ring_buffer_task(ring_buf, perf_tx).await {
            eprintln!("Failed to set up ring buffer: {:?}", e);
        }
    });

    let started = Instant::now();

    if opt.serve {
        // Serve mode: periodically flush data to the web server instead of
        // blocking until Stop. This ensures the web UI gets live updates.
        // trace_count and known_tgids persist across flushes so data accumulates.
        let flush_interval = std::time::Duration::from_secs(2);
        let mut stopped = false;
        let mut trace_count = HashMap::<StackInfo, usize>::new();
        let mut known_tgids = std::collections::HashSet::<u32>::new();

        while !stopped {
            tracing::debug!("serve loop: collecting samples for {:?}", flush_interval);
            let stacks = process_profiling_data_streaming(
                counts,
                stack_traces,
                &perf_rx,
                &mut profiler,
                opt.stream_mode,
                opt.group_by_cpu,
                stacked_pointers,
                &mut ebpf_profiler.bpf,
                &tgid_request_tx,
                flush_interval,
                &mut stopped,
                monitor_exit_pid,
                &mut trace_count,
                &mut known_tgids,
            );
            tracing::debug!(
                "serve loop: flushing {} stacks to web server (stopped={})",
                stacks.len(),
                stopped
            );
            output_results(&opt, &stacks, &tx, stopped)?;
        }
    } else {
        // Non-serve mode: block until Stop, output once, exit.
        tracing::debug!("batch mode: calling process_profiling_data (blocks until Stop)");
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
            monitor_exit_pid,
        );
        tracing::debug!(
            "batch mode: process_profiling_data returned {} stacks",
            stacks.len()
        );
        output_results(&opt, &stacks, &tx, true)?;
    }

    drop(stopper);

    tracing::info!("Profiler ran for {:?}", started.elapsed());

    profiler.print_stats();

    // Log DWARF tail-call fallback diagnostics if DWARF was enabled
    if opt.dwarf.unwrap_or(false) {
        if let Some(fallback_count) = ebpf_profiler.read_dwarf_stats() {
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

/// Convert an optional i32 PID to u32, rejecting negative values.
fn uprobe_pid_as_u32(uprobe_pid: Option<i32>) -> Result<Option<u32>, anyhow::Error> {
    uprobe_pid
        .map(|p| {
            u32::try_from(p)
                .map_err(|_| anyhow::anyhow!("--uprobe-pid must be non-negative, got {}", p))
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
        let (child, stopper) = SpawnProcess::spawn(args[0], &args[1..])?;

        println!("Profiling PID {}..", child.pid());

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
    _target_pid: Option<u32>,
) {
    // 4 ways to stop
    // - 1. user defined duration
    // - 2. ctrl-c received
    // - 3. child process stops (when spawned with -- or --cmd)
    // - 4. target PID exits (when profiling with --pid) - now handled by eBPF tracepoint

    // Timer-based stopping (duration == 0 means run indefinitely)
    if duration > 0 {
        let time_stop_tx = perf_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(duration as _)).await;
            // Send Stop message to exit the profiling loop
            // NOTE: Don't kill the spawned process here — it must stay alive
            // for symbolization (reading /proc/<pid>/maps) after profiling stops.
            // The caller kills it after processing.
            time_stop_tx.send(PerfWork::Stop).unwrap_or_default();
        });
    }

    // Child process completion stopping (for spawned processes)
    if let Some(mut child) = spawn {
        let child_stopper_tx = perf_tx.clone();
        tokio::spawn(async move {
            child.work_done().await;
            child_stopper_tx.send(PerfWork::Stop).unwrap_or_default();
        });
    }

    // Note: Process exit monitoring for --pid is now handled by eBPF tracepoint
    // (sched_process_exit) instead of polling /proc. Events are delivered
    // through the process_exit_events ring buffer.

    // Ctrl-C stopping
    let stop_tx = perf_tx.clone();
    let stopping = stopping;
    tokio::spawn(async move {
        tracing::debug!("setup_stopping_mechanisms: waiting for Ctrl-C");
        println!("Waiting for Ctrl-C...");
        tokio::signal::ctrl_c().await.unwrap_or_default();
        tracing::info!("setup_stopping_mechanisms: Ctrl-C received, sending Stop");
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

/// Sets up the ring buffer task to collect process exit events
async fn setup_process_exit_ring_buffer_task(
    ring_buf: RingBuf<MapData>,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut fd = AsyncFd::new(ring_buf)?;

    while let Ok(mut guard) = fd.readable_mut().await {
        match guard.try_io(|inner| {
            let ring_buf = inner.get_mut();
            while let Some(item) = ring_buf.next() {
                let exit_event: ProcessExitEvent = unsafe { *item.as_ptr().cast() };
                tracing::debug!("eBPF detected: PID {} has exited", exit_event.pid);
                let _ = perf_tx.send(PerfWork::ProcessExit(exit_event));
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
#[allow(clippy::too_many_arguments)]
fn process_profiling_data(
    counts: &mut aya::maps::HashMap<MapData, StackInfoPod, u64>,
    stack_traces: &StackTraceMap<MapData>,
    perf_rx: &mpsc::Receiver<PerfWork>,
    profiler: &mut TraceHandler,
    stream_mode: u8,
    group_by_cpu: bool,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    bpf: &mut Ebpf,
    tgid_request_tx: &Option<mpsc::Sender<DwarfThreadMsg>>,
    monitor_exit_pid: Option<u32>,
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
                if queue_processed == 1 {
                    tracing::debug!("process_profiling_data: received first StackInfo event");
                }

                // Request DWARF loading for newly seen processes
                if let Some(tx) = tgid_request_tx {
                    if stack.tgid != 0 && known_tgids.insert(stack.tgid) {
                        let _ = tx.send(DwarfThreadMsg::LoadProcess(stack.tgid));
                    }
                }

                if local_counting {
                    // User space counting — accumulate into trace_count
                    let trace = trace_count.entry(stack).or_insert(0);
                    *trace += 1;

                    if *trace == 1 {
                        let _combined = profiler.get_exp_stacked_frames(
                            &stack,
                            stack_traces,
                            group_by_cpu,
                            stacked_pointers,
                        );
                    }
                } else {
                    // Kernel counts are authoritative; only prime symbol cache
                    let _combined = profiler.get_exp_stacked_frames(
                        &stack,
                        stack_traces,
                        group_by_cpu,
                        stacked_pointers,
                    );
                }
            }
            PerfWork::DwarfRefresh(update) => {
                apply_dwarf_refresh(bpf, update);
            }
            PerfWork::ProcessExit(exit_event) => {
                // Forward to DWARF thread for LPM trie cleanup
                if let Some(tx) = tgid_request_tx {
                    let _ = tx.send(DwarfThreadMsg::ProcessExited(exit_event.pid));
                }
                // Allow PID reuse to trigger a fresh LoadProcess
                known_tgids.remove(&exit_event.pid);
                // Only stop profiling if this is the monitored target process
                if Some(exit_event.pid) == monitor_exit_pid {
                    tracing::info!("target process {} exited, stopping", exit_event.pid);
                    break;
                }
                tracing::debug!("DWARF-tracked process {} exited", exit_event.pid);
            }
            PerfWork::Stop => {
                tracing::info!("process_profiling_data: received Stop, breaking recv loop");
                break;
            }
        }
    }

    println!("Processed {} queue events", queue_processed);
    println!("Processing stacks...");

    let mut stacks = Vec::new();

    if local_counting {
        process_local_counting(
            &trace_count,
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
    println!("Total value: {} (samples or us off-CPU time)", samples);

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

/// Streaming variant of process_profiling_data for --serve mode.
/// Collects samples for up to `timeout` then returns whatever has accumulated.
/// Sets `stopped = true` when a Stop/ProcessExit message is received.
#[allow(clippy::too_many_arguments)]
fn process_profiling_data_streaming(
    counts: &mut aya::maps::HashMap<MapData, StackInfoPod, u64>,
    stack_traces: &StackTraceMap<MapData>,
    perf_rx: &mpsc::Receiver<PerfWork>,
    profiler: &mut TraceHandler,
    stream_mode: u8,
    group_by_cpu: bool,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    bpf: &mut Ebpf,
    tgid_request_tx: &Option<mpsc::Sender<DwarfThreadMsg>>,
    timeout: std::time::Duration,
    stopped: &mut bool,
    monitor_exit_pid: Option<u32>,
    trace_count: &mut HashMap<StackInfo, usize>,
    known_tgids: &mut std::collections::HashSet<u32>,
) -> Vec<String> {
    let mut queue_processed = 0;
    let mut samples = 0;
    let local_counting = stream_mode == EVENT_TRACE_ALWAYS;

    let keys = counts.keys().flatten().collect::<Vec<_>>();
    for k in keys {
        let _ = counts.remove(&k);
    }

    let deadline = Instant::now() + timeout;

    // Drain events until timeout or Stop
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        match perf_rx.recv_timeout(remaining) {
            Ok(PerfWork::StackInfo(stack)) => {
                queue_processed += 1;
                if queue_processed == 1 {
                    tracing::debug!("process_profiling_data_streaming: received first StackInfo");
                }
                if let Some(tx) = tgid_request_tx {
                    if stack.tgid != 0 && known_tgids.insert(stack.tgid) {
                        let _ = tx.send(DwarfThreadMsg::LoadProcess(stack.tgid));
                    }
                }
                if local_counting {
                    let trace = trace_count.entry(stack).or_insert(0);
                    *trace += 1;
                    if *trace == 1 {
                        profiler.get_exp_stacked_frames(
                            &stack,
                            stack_traces,
                            group_by_cpu,
                            stacked_pointers,
                        );
                    }
                } else {
                    profiler.get_exp_stacked_frames(
                        &stack,
                        stack_traces,
                        group_by_cpu,
                        stacked_pointers,
                    );
                }
            }
            Ok(PerfWork::DwarfRefresh(update)) => {
                apply_dwarf_refresh(bpf, update);
            }
            Ok(PerfWork::ProcessExit(exit_event)) => {
                if let Some(tx) = tgid_request_tx {
                    let _ = tx.send(DwarfThreadMsg::ProcessExited(exit_event.pid));
                }
                known_tgids.remove(&exit_event.pid);
                if Some(exit_event.pid) == monitor_exit_pid {
                    tracing::info!("target process {} exited, stopping", exit_event.pid);
                    *stopped = true;
                    break;
                }
            }
            Ok(PerfWork::Stop) => {
                tracing::info!("process_profiling_data_streaming: Stop received");
                *stopped = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!("process_profiling_data_streaming: channel disconnected");
                *stopped = true;
                break;
            }
        }
    }

    tracing::debug!(
        "process_profiling_data_streaming: processed {} events",
        queue_processed
    );

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

    let mut out = stacks
        .into_iter()
        .map(|frames| {
            let key = frames
                .frames
                .iter()
                .map(|s| s.fmt_symbol())
                .collect::<Vec<_>>()
                .join(";");
            format!("{} {}", &key, frames.count)
        })
        .collect::<Vec<_>>();
    out.sort();
    out
}

/// Process stack traces counted in user space
fn process_local_counting(
    trace_count: &HashMap<StackInfo, usize>,
    profiler: &mut TraceHandler,
    stack_traces: &StackTraceMap<MapData>,
    group_by_cpu: bool,
    samples: &mut u64,
    stacks: &mut Vec<FrameCount>,
    stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
) {
    for (stack, value) in trace_count.iter() {
        let combined =
            profiler.get_exp_stacked_frames(stack, stack_traces, group_by_cpu, stacked_pointers);

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

        let combined =
            profiler.get_exp_stacked_frames(&stack, stack_traces, group_by_cpu, stacked_pointers);

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
    final_flush: bool,
) -> anyhow::Result<()> {
    // Generate SVG if requested (only on final flush)
    if final_flush {
        if let Some(svg) = &opt.svg {
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
            output_svg(svg, stacks, title, opt.off_cpu).map_err(|e| {
                println!("Failed to write svg file {:?} - {:?}", e, svg);
                e
            })?;
        }
    }

    // Generate HTML/JSON if requested
    if opt.html.is_some() || opt.json.is_some() || opt.serve {
        let json = collapse_to_json(&stacks.iter().map(|v| v.as_str()).collect::<Vec<_>>());
        tracing::debug!("output_results: generated JSON ({} bytes)", json.len());

        if final_flush {
            if let Some(json_path) = &opt.json {
                std::fs::write(json_path, &json)
                    .map_err(|e| anyhow::anyhow!("Unable to write JSON file: {}", e))?;
            }

            if let Some(html_path) = &opt.html {
                generate_html_file(html_path, &json);
            }
        }

        if let Err(e) = tx.send(json) {
            tracing::warn!(
                "output_results: broadcast send failed (no receivers?): {:?}",
                e
            );
        } else {
            tracing::debug!(
                "output_results: broadcast sent to {} receivers",
                tx.receiver_count()
            );
        }
    }

    // Write collapsed stacks if requested (only on final flush)
    if final_flush {
        if let Some(name) = &opt.collapse {
            println!("Writing to file: {}", name.display());
            std::fs::write(name, stacks.join("\n"))
                .map_err(|e| anyhow::anyhow!("Unable to write stack collapsed file: {}", e))?;
        }
    }

    Ok(())
}

/// Creates a flamegraph svg file using the inferno-flamegraph lib
fn output_svg(path: &PathBuf, str: &[String], title: String, off_cpu: bool) -> anyhow::Result<()> {
    let mut svg_opts = Options::default();
    svg_opts.title = title;
    if off_cpu {
        svg_opts.count_name = "us".to_string();
    }
    let mut svg_file = std::io::BufWriter::with_capacity(1024 * 1024, std::fs::File::create(path)?);
    flamegraph::from_lines(&mut svg_opts, str.iter().map(|v| v.as_str()), &mut svg_file)?;

    Ok(())
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
        opt.pid
    };

    // Shared infrastructure
    let mut config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&mut config, &perf_tx, pid, opt.dwarf.unwrap_or(false))?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = App::with_live_and_mode(update_mode);
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid } else { None };
    setup_stopping_mechanisms(
        opt.time.unwrap_or(0),
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

    println!("Starting TUI mode...");

    // Process / PID setup
    let (stopper, spawn) = setup_process_to_profile(&opt.cmd, &opt.command)?;
    let pid = if let Some(cmd) = &spawn {
        Some(cmd.pid())
    } else {
        opt.pid
    };

    // Shared infrastructure
    let mut config = build_profiler_config(&opt, pid)?;
    let (perf_tx, perf_rx) = mpsc::channel();
    let (ebpf_profiler, ring_buf, tgid_request_tx) =
        setup_ebpf_and_dwarf(&mut config, &perf_tx, pid, opt.dwarf.unwrap_or(false))?;

    // TUI app + update handle
    let update_mode = parse_update_mode(&opt.update_mode);
    let mut app = App::with_live_and_mode(update_mode);
    let update_handle = app.get_update_handle();
    let update_mode_handle = app.get_update_mode_handle();

    // Stopping mechanisms (timer, Ctrl-C, child exit, PID exit)
    let external_pid = if spawn.is_none() { opt.pid } else { None };
    setup_stopping_mechanisms(
        opt.time.unwrap_or(0),
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
        external_pid,
    );

    // TUI event loop
    run_tui_event_loop(&mut app, !opt.no_tui_mouse)?;

    drop(stopper);
    println!("\nExiting TUI mode");
    Ok(())
}
