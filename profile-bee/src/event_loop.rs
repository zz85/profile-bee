//! Profiling event loop that drains eBPF events and produces collapsed stacks.
//!
//! The `ProfilingEventLoop` owns the eBPF maps, trace handler, and persistent
//! state needed to process profiling events. It replaces the 14-parameter
//! `collect_and_format_stacks` function with a stateful struct.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use aya::maps::{MapData, StackTraceMap};
use aya::Ebpf;
use profile_bee_common::{StackInfo, EVENT_TRACE_ALWAYS};

use crate::ebpf::{apply_dwarf_refresh, FramePointersPod, StackInfoPod};
use crate::pipeline::{DwarfThreadMsg, PerfWork};
use crate::trace_handler::TraceHandler;
use crate::types::FrameCount;

/// Result of a single `collect` call.
pub struct CollectResult {
    /// Collapsed stack strings (sorted, `"stack;frames count"` format).
    pub stacks: Vec<String>,
    /// Whether the profiling loop received a Stop or exit event.
    pub stopped: bool,
}

/// Result of a single `collect_raw` call, returning structured frames.
///
/// Unlike [`CollectResult`] which provides pre-formatted collapse strings,
/// this gives callers the raw [`FrameCount`] data so they can inspect,
/// mutate, or re-format stacks before output.  This is the primary
/// extension point for custom profiling agents that need to enrich
/// stack data (e.g. annotating frames with deployment environment
/// information or reformatting process names).
pub struct RawCollectResult {
    /// Symbolized stack frames with sample counts.
    pub stacks: Vec<FrameCount>,
    /// Whether the profiling loop received a Stop or exit event.
    pub stopped: bool,
}

/// Configuration for the event loop.
pub struct EventLoopConfig {
    pub stream_mode: u8,
    pub group_by_cpu: bool,
    pub monitor_exit_pid: Option<u32>,
    pub tgid_request_tx: Option<mpsc::Sender<DwarfThreadMsg>>,
}

/// Owns the state needed to drain eBPF events and produce collapsed stacks.
///
/// This is the core profiling loop, extracted from the binary for library use.
/// It encapsulates the eBPF maps, trace handler, and persistent counting state.
pub struct ProfilingEventLoop {
    counts: aya::maps::HashMap<MapData, StackInfoPod, u64>,
    stack_traces: StackTraceMap<MapData>,
    stacked_pointers: aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    bpf: Ebpf,
    trace_handler: TraceHandler,
    tgid_request_tx: Option<mpsc::Sender<DwarfThreadMsg>>,
    stream_mode: u8,
    group_by_cpu: bool,
    monitor_exit_pid: Option<u32>,
    // Persistent state across calls
    trace_count: HashMap<StackInfo, usize>,
    known_tgids: HashSet<u32>,
}

impl ProfilingEventLoop {
    /// Create a new event loop from eBPF profiler parts and configuration.
    pub fn new(
        counts: aya::maps::HashMap<MapData, StackInfoPod, u64>,
        stack_traces: StackTraceMap<MapData>,
        stacked_pointers: aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
        bpf: Ebpf,
        config: EventLoopConfig,
    ) -> Self {
        let trace_handler = TraceHandler::new();
        trace_handler.prewarm_kernel_symbols();

        Self {
            counts,
            stack_traces,
            stacked_pointers,
            bpf,
            trace_handler,
            tgid_request_tx: config.tgid_request_tx,
            stream_mode: config.stream_mode,
            group_by_cpu: config.group_by_cpu,
            monitor_exit_pid: config.monitor_exit_pid,
            trace_count: HashMap::new(),
            known_tgids: HashSet::new(),
        }
    }

    /// Drain events from the channel, symbolize stacks, and return collapsed output.
    ///
    /// - `timeout = None` → blocks on `recv()` until Stop/exit (batch mode)
    /// - `timeout = Some(d)` → drains events for up to `d` then returns (streaming mode)
    pub fn collect(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        timeout: Option<Duration>,
    ) -> CollectResult {
        let (local_counting, stopped) = self.drain_events(rx, timeout);
        let stacks = self.build_collapse_output(local_counting);
        CollectResult { stacks, stopped }
    }

    /// Drain events and return structured [`FrameCount`] data.
    ///
    /// Identical to [`collect`](Self::collect) but returns raw symbolized
    /// frames instead of pre-formatted collapse strings.  This lets callers
    /// inspect, mutate, or re-format stacks before output — useful for
    /// custom profiling agents that enrich frames with external metadata.
    ///
    /// # Example: continuous profiling agent
    ///
    /// ```rust,ignore
    /// loop {
    ///     let result = event_loop.collect_raw(&rx, Some(Duration::from_secs(10)));
    ///
    ///     // Enrich stacks with deployment metadata, reformat process names, etc.
    ///     let enriched = post_process(result.stacks);
    ///
    ///     // Convert to your upload format and send
    ///     upload(enriched);
    ///
    ///     if result.stopped { break; }
    /// }
    /// ```
    pub fn collect_raw(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        timeout: Option<Duration>,
    ) -> RawCollectResult {
        let (local_counting, stopped) = self.drain_events(rx, timeout);
        let stacks = self.build_raw_stacks(local_counting);
        RawCollectResult { stacks, stopped }
    }

    /// Drain events from the PerfWork channel, symbolize stacks on the fly,
    /// and return `(local_counting, stopped)`.
    ///
    /// This is the shared event-draining loop used by both [`collect`] and
    /// [`collect_raw`].
    fn drain_events(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        timeout: Option<Duration>,
    ) -> (bool, bool) {
        let mut queue_processed = 0u64;
        let mut stopped = false;
        let local_counting = self.stream_mode == EVENT_TRACE_ALWAYS;

        // Drain the eBPF counts map so samples transfer into trace_count.
        let keys = self.counts.keys().flatten().collect::<Vec<_>>();
        for k in keys {
            let _ = self.counts.remove(&k);
        }

        let deadline = timeout.map(|d| Instant::now() + d);

        loop {
            let work = if let Some(dl) = deadline {
                let remaining = dl.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match rx.recv_timeout(remaining) {
                    Ok(w) => w,
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::warn!("drain_events: channel disconnected");
                        stopped = true;
                        break;
                    }
                }
            } else {
                match rx.recv() {
                    Ok(w) => w,
                    Err(_) => {
                        stopped = true;
                        break;
                    }
                }
            };

            match work {
                PerfWork::StackInfo(stack) => {
                    queue_processed += 1;
                    if queue_processed == 1 {
                        tracing::debug!("drain_events: received first StackInfo event");
                    }
                    if let Some(tx) = &self.tgid_request_tx {
                        if stack.tgid != 0 && self.known_tgids.insert(stack.tgid) {
                            let _ = tx.send(DwarfThreadMsg::LoadProcess(stack.tgid));
                        }
                    }
                    if local_counting {
                        let trace = self.trace_count.entry(stack).or_insert(0);
                        *trace += 1;
                        if *trace == 1 {
                            self.trace_handler.get_exp_stacked_frames(
                                &stack,
                                &self.stack_traces,
                                self.group_by_cpu,
                                &self.stacked_pointers,
                            );
                        }
                    } else {
                        self.trace_handler.get_exp_stacked_frames(
                            &stack,
                            &self.stack_traces,
                            self.group_by_cpu,
                            &self.stacked_pointers,
                        );
                    }
                }
                PerfWork::DwarfRefresh(update) => {
                    if let Err(e) = apply_dwarf_refresh(&mut self.bpf, update) {
                        tracing::warn!("{:#}", e);
                    }
                }
                PerfWork::ProcessExit(exit_event) => {
                    if let Some(tx) = &self.tgid_request_tx {
                        let _ = tx.send(DwarfThreadMsg::ProcessExited(exit_event.pid));
                    }
                    self.known_tgids.remove(&exit_event.pid);
                    if Some(exit_event.pid) == self.monitor_exit_pid {
                        tracing::info!("target process {} exited, stopping", exit_event.pid);
                        stopped = true;
                        break;
                    }
                    tracing::debug!("DWARF-tracked process {} exited", exit_event.pid);
                }
                PerfWork::Stop => {
                    tracing::info!("drain_events: received Stop");
                    stopped = true;
                    break;
                }
            }
        }

        tracing::debug!("drain_events: processed {} events", queue_processed);
        (local_counting, stopped)
    }

    /// Symbolize and return raw [`FrameCount`] data from the current trace counts.
    fn build_raw_stacks(&mut self, local_counting: bool) -> Vec<FrameCount> {
        let sources: Vec<(StackInfo, u64)> = if local_counting {
            self.trace_count
                .iter()
                .map(|(&s, &v)| (s, v as u64))
                .collect()
        } else {
            self.counts
                .iter()
                .flatten()
                .map(|(k, v)| (k.0, v))
                .collect()
        };

        let mut stacks = Vec::new();
        for (stack, count) in &sources {
            let combined = self.trace_handler.get_exp_stacked_frames(
                stack,
                &self.stack_traces,
                self.group_by_cpu,
                &self.stacked_pointers,
            );
            stacks.push(FrameCount {
                frames: combined,
                count: *count,
            });
        }

        stacks
    }

    /// Build collapse-format output from trace counts or kernel counts.
    fn build_collapse_output(&mut self, local_counting: bool) -> Vec<String> {
        let stacks = self.build_raw_stacks(local_counting);

        let mut out: Vec<String> = stacks
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
            .collect();
        out.sort();
        out
    }

    /// Get a summary of profiling statistics.
    pub fn stats_summary(&self) -> String {
        self.trace_handler.stats_summary()
    }

    /// Log profiling statistics via tracing.
    pub fn print_stats(&self) {
        self.trace_handler.print_stats();
    }

    /// Mutable access to the underlying `Ebpf` handle for advanced operations
    /// (e.g., reading DWARF stats maps).
    pub fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }

    /// Access trace counts for external inspection (e.g., TUI mode).
    pub fn trace_count(&self) -> &HashMap<StackInfo, usize> {
        &self.trace_count
    }

    /// Mutable access to trace counts (e.g., for decay/reset in TUI mode).
    pub fn trace_count_mut(&mut self) -> &mut HashMap<StackInfo, usize> {
        &mut self.trace_count
    }

    /// Access to the trace handler for external symbolization.
    pub fn trace_handler(&mut self) -> &mut TraceHandler {
        &mut self.trace_handler
    }

    /// Access to stacked_pointers map.
    pub fn stacked_pointers(&self) -> &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod> {
        &self.stacked_pointers
    }

    /// Access to stack_traces map.
    pub fn stack_traces(&self) -> &StackTraceMap<MapData> {
        &self.stack_traces
    }

    /// Access to counts map.
    pub fn counts(&mut self) -> &mut aya::maps::HashMap<MapData, StackInfoPod, u64> {
        &mut self.counts
    }

    /// Access stream_mode.
    pub fn stream_mode(&self) -> u8 {
        self.stream_mode
    }

    /// Access group_by_cpu.
    pub fn group_by_cpu(&self) -> bool {
        self.group_by_cpu
    }

    /// Access known_tgids set.
    pub fn known_tgids(&self) -> &HashSet<u32> {
        &self.known_tgids
    }

    /// Mutable access to known_tgids.
    pub fn known_tgids_mut(&mut self) -> &mut HashSet<u32> {
        &mut self.known_tgids
    }

    /// Access tgid_request_tx.
    pub fn tgid_request_tx(&self) -> &Option<mpsc::Sender<DwarfThreadMsg>> {
        &self.tgid_request_tx
    }

    /// Access monitor_exit_pid.
    pub fn monitor_exit_pid(&self) -> Option<u32> {
        self.monitor_exit_pid
    }
}

/// Convert structured [`FrameCount`] data into sorted collapse-format strings.
///
/// Each entry becomes `"frame1;frame2;...;frameN count\n"`.  This is the same
/// format produced by [`ProfilingEventLoop::collect`] and consumed by tools
/// like `inferno`, `flamegraph.pl`, and profile-bee's own SVG/HTML/TUI outputs.
///
/// Useful when you call [`ProfilingEventLoop::collect_raw`], enrich the stacks,
/// and then want collapse-format output.
pub fn collapse_raw(stacks: &[FrameCount]) -> Vec<String> {
    collapse_raw_with(stacks, |f| f.fmt_symbol())
}

/// Convert structured [`FrameCount`] data into sorted collapse-format strings,
/// using a custom frame formatter.
///
/// This is the customizable variant of [`collapse_raw`].  The `fmt` closure
/// controls how each [`StackFrameInfo`] becomes a string in the output.
///
/// # Example
///
/// ```rust,ignore
/// use profile_bee::event_loop::collapse_raw_with;
///
/// // Include the object (library) name in the output
/// let stacks = collapse_raw_with(&raw.stacks, |frame| {
///     let obj = frame.fmt_object();
///     let sym = frame.symbol.as_deref().unwrap_or("[unknown]");
///     format!("{}`{}", obj, sym)
/// });
/// ```
pub fn collapse_raw_with<F>(stacks: &[FrameCount], fmt: F) -> Vec<String>
where
    F: Fn(&crate::types::StackFrameInfo) -> String,
{
    let mut out: Vec<String> = stacks
        .iter()
        .map(|fc| {
            let key = fc.frames.iter().map(&fmt).collect::<Vec<_>>().join(";");
            format!("{} {}", &key, fc.count)
        })
        .collect();
    out.sort();
    out
}
