//! High-level profiling session that manages the full lifecycle.
//!
//! `ProfilingSession` consolidates the duplicated eBPF + DWARF setup sequence
//! into a single API. Library consumers create a session, then call `run_batch`
//! or `run_streaming` without touching eBPF internals.

use std::sync::mpsc;
use std::time::Duration;

use anyhow::Result;
use tokio::task;

use crate::dwarf_unwind::DwarfUnwindManager;
use crate::ebpf::{
    attach_process_exit_tracepoint, setup_ebpf_with_tp_fallback, setup_process_exit_ring_buffer,
    setup_ring_buffer, ProfilerConfig,
};
use crate::event_loop::{EventLoopConfig, ProfilingEventLoop};
use crate::output::OutputSink;
use crate::pipeline::{
    dwarf_refresh_loop, setup_process_exit_ring_buffer_task, setup_ring_buffer_task,
    setup_timer_and_child_stop, DwarfThreadMsg, PerfWork,
};
use crate::spawn::{setup_process_to_profile, SpawnProcess, StopHandler};

/// Configuration for creating a `ProfilingSession`.
///
/// Combines the eBPF profiler configuration with session-level options
/// like process spawning and duration.
pub struct SessionConfig {
    /// Core eBPF profiler configuration.
    pub profiler: ProfilerConfig,
    /// Command to spawn and profile (deprecated format).
    pub cmd: Option<String>,
    /// Command and args to spawn (preferred format, `-- <args>`).
    pub command: Vec<String>,
    /// Duration in ms (0 = unlimited). Only used in batch/streaming mode.
    pub duration_ms: usize,
    /// Group samples by CPU core.
    pub group_by_cpu: bool,
    /// Whether to set up process-exit monitoring for external PIDs.
    pub monitor_exit: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            profiler: ProfilerConfig::default(),
            cmd: None,
            command: Vec::new(),
            duration_ms: 0,
            group_by_cpu: false,
            monitor_exit: true,
        }
    }
}

/// High-level profiling session that manages the full lifecycle.
///
/// Encapsulates eBPF loading, DWARF setup, ring buffer tasks, and the
/// profiling event loop. Library consumers use this instead of manually
/// wiring together the low-level components.
///
/// # Example (library usage)
///
/// ```rust,no_run
/// use profile_bee::session::{ProfilingSession, SessionConfig};
/// use profile_bee::ebpf::ProfilerConfig;
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = SessionConfig {
///     profiler: ProfilerConfig {
///         frequency: 99,
///         dwarf: true,
///         ..ProfilerConfig::default()
///     },
///     duration_ms: 10000,
///     ..SessionConfig::default()
/// };
///
/// let (mut session, perf_rx) = ProfilingSession::new(config).await?;
/// let result = session.event_loop.collect(&perf_rx, None);
/// println!("Collected {} stacks", result.stacks.len());
/// # Ok(())
/// # }
/// ```
pub struct ProfilingSession {
    /// The profiling event loop (owns eBPF maps, trace handler, state).
    pub event_loop: ProfilingEventLoop,
    /// Sender for injecting stop signals or other events.
    pub perf_tx: mpsc::Sender<PerfWork>,
    /// Spawned child process, if any.
    pub spawn: Option<SpawnProcess>,
    /// Stop handler for child process lifecycle.
    pub stopper: Option<StopHandler>,
    /// PID being monitored for exit (for external PIDs via --pid).
    pub monitor_exit_pid: Option<u32>,
}

impl ProfilingSession {
    /// Create and fully initialize a profiling session.
    ///
    /// This performs the entire setup sequence:
    /// 1. Load and verify eBPF programs
    /// 2. Spawn child process (if configured)
    /// 3. Load DWARF unwind tables and start background refresh thread
    /// 4. Set target PID filter
    /// 5. Set up ring buffer polling tasks
    /// 6. Set up process exit monitoring
    ///
    /// Returns the session and the receiver for the PerfWork channel.
    /// The receiver is returned separately because it must be passed to
    /// `event_loop.collect()` — it cannot be stored in the session due
    /// to borrow conflicts.
    pub async fn new(mut config: SessionConfig) -> Result<(Self, mpsc::Receiver<PerfWork>)> {
        // 1. Load eBPF
        let verification_start = std::time::Instant::now();
        let mut ebpf_profiler = setup_ebpf_with_tp_fallback(&mut config.profiler)?;
        let verification_time = verification_start.elapsed();
        tracing::info!("eBPF verification completed in {:?}", verification_time);

        // 2. Spawn child process (if configured)
        let (stopper, mut spawn) = setup_process_to_profile(&config.cmd, &config.command)?;
        let pid = if let Some(cmd) = &spawn {
            Some(cmd.pid())
        } else {
            config.profiler.pid
        };

        // 3. Set up communication channels
        let (perf_tx, perf_rx) = mpsc::channel();

        // 4. DWARF setup (before setting TARGET_PID)
        let tgid_request_tx = if config.profiler.dwarf {
            let mut dwarf_manager = DwarfUnwindManager::new();
            if let Some(target_pid) = pid {
                tracing::info!("Loading DWARF unwind tables for pid {}...", target_pid);
                match dwarf_manager.load_process(target_pid) {
                    Ok(()) => {
                        tracing::info!(
                            "Loaded {} unwind entries for pid {}",
                            dwarf_manager.total_entries(),
                            target_pid,
                        );
                        if let Err(e) = ebpf_profiler.load_dwarf_unwind_tables(&dwarf_manager) {
                            tracing::error!(
                                "Failed to load DWARF unwind tables into eBPF: {:?}",
                                e
                            );
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

        // 5. Set target PID (AFTER DWARF tables loaded)
        if let Some(target_pid) = pid {
            ebpf_profiler.set_target_pid(target_pid)?;
            tracing::info!("Profiling PID {}..", target_pid);
        }

        // 6. Ring buffer setup
        let ring_buf = setup_ring_buffer(&mut ebpf_profiler.bpf)?;

        // 7. Process exit monitoring
        let external_pid = if spawn.is_none() {
            config.profiler.pid
        } else {
            None
        };
        let monitor_exit_pid = external_pid;

        if (external_pid.is_some() || config.profiler.dwarf) && config.monitor_exit {
            attach_process_exit_tracepoint(&mut ebpf_profiler.bpf)?;
            if let Some(pid_to_monitor) = external_pid {
                ebpf_profiler.set_monitor_exit_pid(pid_to_monitor)?;
            }
            let exit_ring_buf = setup_process_exit_ring_buffer(&mut ebpf_profiler.bpf)?;
            let exit_perf_tx = perf_tx.clone();
            task::spawn(async move {
                if let Err(e) =
                    setup_process_exit_ring_buffer_task(exit_ring_buf, exit_perf_tx).await
                {
                    tracing::error!("Failed to set up process exit ring buffer: {:?}", e);
                }
            });
        }

        // 8. Start ring buffer polling task
        let rb_perf_tx = perf_tx.clone();
        task::spawn(async move {
            if let Err(e) = setup_ring_buffer_task(ring_buf, rb_perf_tx).await {
                tracing::error!("Failed to set up ring buffer: {:?}", e);
            }
        });

        // 9. Set up timer and child stop (consumes the SpawnProcess)
        setup_timer_and_child_stop(config.duration_ms, perf_tx.clone(), spawn.take());

        // 10. Build event loop
        let event_loop_config = EventLoopConfig {
            stream_mode: config.profiler.stream_mode,
            group_by_cpu: config.group_by_cpu,
            monitor_exit_pid,
            tgid_request_tx,
        };
        let event_loop = ProfilingEventLoop::new(
            ebpf_profiler.counts,
            ebpf_profiler.stack_traces,
            ebpf_profiler.stacked_pointers,
            ebpf_profiler.bpf,
            event_loop_config,
        );

        Ok((
            Self {
                event_loop,
                perf_tx,
                spawn: None, // consumed by timer_and_child_stop
                stopper,
                monitor_exit_pid,
            },
            perf_rx,
        ))
    }

    /// Run in batch mode: collect stacks until duration expires or stop signal.
    /// Returns collapsed stack strings.
    pub fn run_batch(&mut self, rx: &mpsc::Receiver<PerfWork>) -> Vec<String> {
        let result = self.event_loop.collect(rx, None);
        result.stacks
    }

    /// Run in streaming mode: periodically call sink with accumulated stacks.
    pub fn run_streaming(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        sink: &mut dyn OutputSink,
        flush_interval: Duration,
    ) -> Result<()> {
        let mut last_stacks = Vec::new();

        loop {
            let result = self.event_loop.collect(rx, Some(flush_interval));
            sink.write_batch(&result.stacks)?;
            if !result.stacks.is_empty() {
                last_stacks = result.stacks;
            }
            if result.stopped {
                break;
            }
        }

        sink.finish(&last_stacks)?;
        Ok(())
    }

    /// Send a stop signal to the profiling loop.
    pub fn stop(&self) {
        let _ = self.perf_tx.send(PerfWork::Stop);
    }

    /// Get a clone of the PerfWork sender for external use.
    pub fn stop_sender(&self) -> mpsc::Sender<PerfWork> {
        self.perf_tx.clone()
    }

    /// Get profiling statistics summary.
    pub fn stats_summary(&self) -> String {
        self.event_loop.stats_summary()
    }
}

// Add Default impl for ProfilerConfig
impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            skip_idle: false,
            stream_mode: 2,
            frequency: 99,
            kprobe: None,
            uprobe: None,
            smart_uprobe: None,
            tracepoint: None,
            raw_tracepoint: None,
            raw_tracepoint_task_regs: None,
            raw_tracepoint_generic: None,
            target_syscall_nr: -1,
            pid: None,
            cpu: None,
            self_profile: false,
            dwarf: false,
            off_cpu: false,
            min_block_us: 1,
            max_block_us: u64::MAX,
        }
    }
}
