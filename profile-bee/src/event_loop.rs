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
use profile_bee_common::{StackInfo, EVENT_TRACE_ALWAYS, PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT};

use crate::ebpf::{apply_dwarf_refresh, FramePointersPod, StackInfoPod, V8ProcInfoPod};
use crate::pipeline::{DwarfThreadMsg, PerfWork};
use crate::process_metadata::ProcessMetadataCache;
use crate::trace_handler::TraceHandler;
use crate::types::{FrameCount, StackInfoExt};

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

/// A single unsymbolized stack sample with raw instruction pointer addresses.
///
/// Used by the raw/offline output mode to capture addresses for post-hoc
/// symbolization. Contains everything needed to re-symbolize the stack later:
/// PID (for `/proc/<pid>/maps`), process name, and raw kernel + user addresses.
pub struct RawAddressSample {
    pub tgid: u32,
    pub cmd: String,
    pub cpu: u32,
    pub kernel_addrs: Vec<u64>,
    pub user_addrs: Vec<u64>,
    pub count: u64,
}

/// Result of a single `collect_unsymbolized` call.
pub struct UnsymbolizedCollectResult {
    /// Raw address samples (not symbolized).
    pub samples: Vec<RawAddressSample>,
    /// Whether the profiling loop received a Stop or exit event.
    pub stopped: bool,
}

/// Configuration for the event loop.
pub struct EventLoopConfig {
    pub stream_mode: u8,
    pub group_by_cpu: bool,
    pub group_by_process: bool,
    pub monitor_exit_pid: Option<u32>,
    pub tgid_request_tx: Option<mpsc::Sender<DwarfThreadMsg>>,
    /// Whether to maintain a process metadata cache.
    /// When `true`, a `ProcessMetadataCache` is created and updated
    /// on exec/exit events. Library consumers can access it via
    /// `process_metadata()`.
    pub enable_process_metadata: bool,
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
    group_by_process: bool,
    monitor_exit_pid: Option<u32>,
    // Persistent state across calls
    trace_count: HashMap<StackInfo, usize>,
    known_tgids: HashSet<u32>,
    /// Optional process metadata cache, maintained via eBPF lifecycle events.
    process_metadata: Option<ProcessMetadataCache>,
    /// PIDs that exited during the current drain_events() call.
    /// Eviction from `process_metadata` is deferred until after
    /// `build_raw_stacks()` completes, so agents can still look up
    /// metadata for processes that exited within the collection window.
    pending_exit_pids: Vec<u32>,
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
            group_by_process: config.group_by_process,
            monitor_exit_pid: config.monitor_exit_pid,
            trace_count: HashMap::new(),
            known_tgids: HashSet::new(),
            process_metadata: if config.enable_process_metadata {
                Some(ProcessMetadataCache::new(4096))
            } else {
                None
            },
            pending_exit_pids: Vec::new(),
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
        let (local_counting, stopped) = self.drain_events(rx, timeout, true);
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
        let (local_counting, stopped) = self.drain_events(rx, timeout, true);
        let stacks = self.build_raw_stacks(local_counting);
        RawCollectResult { stacks, stopped }
    }

    /// Drain events and return unsymbolized raw address samples.
    ///
    /// Like [`collect`](Self::collect) but skips symbolization entirely,
    /// returning raw instruction pointer addresses for each stack sample.
    /// Use this for offline/post-hoc symbolization workflows where captures
    /// need to be fast and symbolization happens later.
    ///
    /// The returned [`UnsymbolizedCollectResult`] contains [`RawAddressSample`]
    /// values with kernel and user address vectors that can be serialized
    /// for later re-symbolization (e.g. with `probee symbolize`).
    pub fn collect_unsymbolized(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        timeout: Option<Duration>,
    ) -> UnsymbolizedCollectResult {
        let (local_counting, stopped) = self.drain_events(rx, timeout, false);
        let samples = self.build_raw_address_samples(local_counting);
        UnsymbolizedCollectResult { samples, stopped }
    }

    /// Immediately evict process metadata for PIDs that exited during
    /// previous `drain_events()` calls.
    ///
    /// Normally eviction is deferred automatically: exit PIDs from cycle N
    /// are evicted at the start of cycle N+1's `drain_events()` call,
    /// giving agents one full collection cycle to read metadata for
    /// processes that exited. Call this method only if you need to free
    /// cache entries sooner (e.g., memory pressure).
    pub fn evict_pending_exits(&mut self) {
        if let Some(ref mut cache) = self.process_metadata {
            for pid in self.pending_exit_pids.drain(..) {
                cache.remove(pid);
            }
        } else {
            self.pending_exit_pids.clear();
        }
    }

    /// Detect if a new PID is a Node.js/V8 process and set up V8 introspection.
    ///
    /// Reads `/proc/<pid>/exe` to find the binary, then reads `v8dbg_*` ELF
    /// symbols to discover V8's internal layout. If successful, loads
    /// `V8ProcInfo` into the eBPF `v8_proc_info` map (so the FP walker
    /// extracts JSFunction pointers) and registers a `V8HeapReader` in the
    /// trace handler (so userspace can resolve SFI → function name).
    fn try_setup_v8_for_pid(&mut self, tgid: u32) {
        // Read /proc/<pid>/exe to get the binary path
        let exe_link = format!("/proc/{}/exe", tgid);
        let exe_path = match std::fs::read_link(&exe_link) {
            Ok(p) => p,
            Err(_) => return,
        };

        if !crate::v8::is_nodejs_binary(&exe_path) {
            return;
        }

        tracing::info!(
            "detected Node.js process (pid {}): {}",
            tgid,
            exe_path.display()
        );

        // Read the ELF binary to extract v8dbg_* introspection symbols
        let elf_data = match std::fs::read(&exe_path) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!("cannot read {}: {}", exe_path.display(), e);
                return;
            }
        };

        let Some(data) = crate::v8::read_introspection_data(&elf_data) else {
            tracing::warn!(
                "failed to read V8 introspection data from {}",
                exe_path.display()
            );
            return;
        };

        // Build compact V8ProcInfo and load into eBPF map
        let Some(proc_info) = data.to_proc_info() else {
            tracing::warn!(
                "V8ProcInfo for pid {} has offsets out of u8 range, skipping",
                tgid
            );
            return;
        };
        match self.bpf.map_mut("v8_proc_info") {
            Some(map) => {
                match aya::maps::HashMap::<&mut MapData, u32, V8ProcInfoPod>::try_from(map) {
                    Ok(mut v8_map) => {
                        if let Err(e) = v8_map.insert(tgid, V8ProcInfoPod(proc_info), 0) {
                            tracing::warn!("failed to insert V8ProcInfo for pid {}: {}", tgid, e);
                        } else {
                            tracing::info!(
                                "loaded V8ProcInfo for pid {} (V8 {}.{}.{})",
                                tgid,
                                data.version.0,
                                data.version.1,
                                data.version.2,
                            );
                        }
                    }
                    Err(e) => tracing::warn!("v8_proc_info map error: {}", e),
                }
            }
            None => tracing::debug!("v8_proc_info map not found (older eBPF binary)"),
        }

        // Register V8HeapReader for userspace symbolization
        self.trace_handler.register_v8_reader(tgid, data);
    }

    /// Remove the V8ProcInfo entry from the eBPF map for a given PID.
    /// Called on process exit and exec to prevent the eBPF V8 SFI extraction
    /// from reading stale V8 layout data for a reused PID.
    fn remove_v8_proc_info_for_pid(&mut self, tgid: u32) {
        if let Some(map) = self.bpf.map_mut("v8_proc_info") {
            if let Ok(mut v8_map) =
                aya::maps::HashMap::<&mut MapData, u32, V8ProcInfoPod>::try_from(map)
            {
                let _ = v8_map.remove(&tgid);
            }
        }
    }

    /// Drain events from the PerfWork channel, optionally symbolize stacks
    /// on the fly, and return `(local_counting, stopped)`.
    ///
    /// When `symbolize` is true, `get_exp_stacked_frames` is called for each
    /// StackInfo event to prime the symbol cache and read frame pointers.
    /// When false (used by [`collect_unsymbolized`]), this work is skipped
    /// so the raw address pipeline runs without symbolization overhead.
    ///
    /// This is the shared event-draining loop used by [`collect`],
    /// [`collect_raw`], and [`collect_unsymbolized`].
    fn drain_events(
        &mut self,
        rx: &mpsc::Receiver<PerfWork>,
        timeout: Option<Duration>,
        symbolize: bool,
    ) -> (bool, bool) {
        // Evict metadata for PIDs that exited in the PREVIOUS cycle.
        // This gives agents one full collection cycle to read metadata
        // for processes that exited, covering async ring buffer delivery
        // where a sample may arrive after its process's exit event.
        self.evict_pending_exits();

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
                            // Check if this is a Node.js/V8 process and set up
                            // V8 introspection (eBPF FP context extraction +
                            // userspace heap reader for JS symbol resolution).
                            self.try_setup_v8_for_pid(stack.tgid);
                        }
                    } else if stack.tgid != 0 && self.known_tgids.insert(stack.tgid) {
                        // Even without DWARF thread, detect V8 processes
                        self.try_setup_v8_for_pid(stack.tgid);
                    }
                    if local_counting {
                        let trace = self.trace_count.entry(stack).or_insert(0);
                        *trace += 1;
                        if *trace == 1 && symbolize {
                            self.trace_handler.get_exp_stacked_frames(
                                &stack,
                                &self.stack_traces,
                                self.group_by_cpu,
                                self.group_by_process,
                                &self.stacked_pointers,
                            );
                        }
                    } else if symbolize {
                        self.trace_handler.get_exp_stacked_frames(
                            &stack,
                            &self.stack_traces,
                            self.group_by_cpu,
                            self.group_by_process,
                            &self.stacked_pointers,
                        );
                    }
                }
                PerfWork::DwarfRefresh(update) => {
                    if let Err(e) = apply_dwarf_refresh(&mut self.bpf, update) {
                        tracing::warn!("{:#}", e);
                    }
                }
                PerfWork::ProcessEvent(event) => {
                    match event.event_type {
                        PROCESS_EVENT_EXIT => {
                            if let Some(tx) = &self.tgid_request_tx {
                                let _ = tx.send(DwarfThreadMsg::ProcessExited(event.pid));
                            }
                            self.known_tgids.remove(&event.pid);
                            // Clean up V8 state for the exiting process to prevent
                            // stale readers from being used if the PID is reused.
                            self.trace_handler.invalidate_caches_for_pid(event.pid);
                            // Also remove the eBPF v8_proc_info entry so the FP walker
                            // won't try to extract V8 SFI for a reused PID.
                            self.remove_v8_proc_info_for_pid(event.pid);
                            // Defer metadata cache eviction until after build_raw_stacks()
                            // so agents can still look up metadata for processes that
                            // exited within the collection window.
                            if self.process_metadata.is_some() {
                                self.pending_exit_pids.push(event.pid);
                            }
                            if Some(event.pid) == self.monitor_exit_pid {
                                tracing::info!("target process {} exited, stopping", event.pid);
                                stopped = true;
                                break;
                            }
                            tracing::debug!("process {} exited", event.pid);
                        }
                        PROCESS_EVENT_EXEC => {
                            tracing::debug!("process {} called exec", event.pid);
                            if let Some(tx) = &self.tgid_request_tx {
                                let _ = tx.send(DwarfThreadMsg::ProcessExeced(event.pid));
                            }
                            // Flush pre-exec samples from trace_count before invalidating
                            // caches — otherwise build_raw_stacks() would try to symbolize
                            // old addresses against the new binary image.
                            self.trace_count.retain(|k, _| k.tgid != event.pid);
                            // The PID is still alive but with a new binary image.
                            // Remove from known_tgids so the next StackInfo for this
                            // PID triggers try_setup_v8_for_pid and DWARF reloading.
                            // Do NOT re-insert — let the StackInfo handler do it.
                            self.known_tgids.remove(&event.pid);
                            // Invalidate symbol caches for this PID
                            self.trace_handler.invalidate_caches_for_pid(event.pid);
                            // Remove eBPF v8_proc_info for the old binary
                            self.remove_v8_proc_info_for_pid(event.pid);
                            if let Some(ref mut cache) = self.process_metadata {
                                cache.invalidate(event.pid);
                            }
                        }
                        _ => {
                            tracing::warn!(
                                "unknown process event type {} for pid {}",
                                event.event_type,
                                event.pid
                            );
                        }
                    }
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
                self.group_by_process,
                &self.stacked_pointers,
            );
            stacks.push(FrameCount {
                frames: combined,
                count: *count,
            });
        }

        stacks
    }

    /// Extract raw address samples without symbolization.
    ///
    /// Same source iteration as [`build_raw_stacks`] but calls
    /// [`TraceHandler::get_raw_addresses`] instead of symbolization,
    /// producing [`RawAddressSample`] values with raw instruction pointers.
    fn build_raw_address_samples(&mut self, local_counting: bool) -> Vec<RawAddressSample> {
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

        let mut samples = Vec::new();
        for (stack, count) in &sources {
            let (kernel_addrs, user_addrs) = self.trace_handler.get_raw_addresses(
                stack,
                &self.stack_traces,
                &self.stacked_pointers,
            );
            samples.push(RawAddressSample {
                tgid: stack.tgid,
                cmd: stack.get_cmd(),
                cpu: stack.cpu,
                kernel_addrs,
                user_addrs,
                count: *count,
            });
        }

        samples
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

    /// Access the process metadata cache (if enabled).
    ///
    /// Returns `None` if lifecycle tracking was not enabled. Library consumers
    /// can use this to look up process metadata (cmdline, cwd, environ, etc.)
    /// between `collect_raw()` calls for stack enrichment.
    pub fn process_metadata(&mut self) -> Option<&mut ProcessMetadataCache> {
        self.process_metadata.as_mut()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StackFrameInfo;

    fn make_frame(symbol: &str) -> StackFrameInfo {
        StackFrameInfo {
            symbol: Some(symbol.to_string()),
            ..Default::default()
        }
    }

    fn sample_stacks() -> Vec<FrameCount> {
        vec![
            FrameCount {
                frames: vec![make_frame("main"), make_frame("compute")],
                count: 10,
            },
            FrameCount {
                frames: vec![make_frame("main"), make_frame("idle_loop")],
                count: 5,
            },
        ]
    }

    #[test]
    fn test_collapse_raw_produces_sorted_output() {
        let stacks = sample_stacks();
        let out = collapse_raw(&stacks);
        assert_eq!(out.len(), 2);
        // Output must be sorted lexicographically
        assert!(out[0] < out[1]);
        assert_eq!(out[0], "main;compute 10");
        assert_eq!(out[1], "main;idle_loop 5");
    }

    #[test]
    fn test_collapse_raw_empty() {
        let out = collapse_raw(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_collapse_raw_with_custom_formatter() {
        let stacks = sample_stacks();
        // Use a custom formatter that uppercases symbols
        let out = collapse_raw_with(&stacks, |f| {
            f.symbol.as_deref().unwrap_or("?").to_uppercase()
        });
        assert_eq!(out[0], "MAIN;COMPUTE 10");
        assert_eq!(out[1], "MAIN;IDLE_LOOP 5");
    }

    #[test]
    fn test_collapse_raw_with_object_prefix() {
        let stacks = vec![FrameCount {
            frames: vec![StackFrameInfo {
                symbol: Some("read".to_string()),
                cmd: "myapp".to_string(),
                ..Default::default()
            }],
            count: 42,
        }];
        // Perf-style "object`symbol" format
        let out = collapse_raw_with(&stacks, |f| {
            format!("{}`{}", f.fmt_object(), f.symbol.as_deref().unwrap_or("?"))
        });
        assert_eq!(out[0], "myapp`read 42");
    }
}
