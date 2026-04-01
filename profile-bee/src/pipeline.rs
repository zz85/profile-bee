//! Profiling pipeline coordination types and DWARF background management.
//!
//! Central types (`PerfWork`, `DwarfThreadMsg`) that define the communication
//! protocol between the profiling event loop, eBPF ring buffers, and the DWARF
//! background thread.

use std::collections::HashMap;
use std::sync::mpsc;

use aya::maps::{MapData, RingBuf};
use profile_bee_common::{
    ProcessEvent, ProcessExecEvent, ProcessExitEvent, StackInfo, PROCESS_EVENT_EXEC,
    PROCESS_EVENT_EXIT,
};

use crate::dwarf_unwind::{DwarfUnwindManager, MappingsDiff};
use crate::ebpf::{build_dwarf_refresh, DwarfRefreshUpdate};
use crate::spawn::{SpawnProcess, StopHandler};

/// Message type for the profiler's communication channel.
///
/// All stopping mechanisms, ring buffer tasks, and the DWARF background
/// thread communicate with the profiling loop through this enum.
pub enum PerfWork {
    /// New stack sample from eBPF ring buffer.
    StackInfo(StackInfo),
    /// Incremental DWARF table update from background thread.
    DwarfRefresh(DwarfRefreshUpdate),
    /// Process lifecycle event (exec or exit) detected by eBPF tracepoint.
    ProcessEvent(ProcessEvent),
    /// Signal to stop profiling.
    Stop,
}

/// Message type for the DWARF background thread.
pub enum DwarfThreadMsg {
    /// New process to load DWARF data for.
    LoadProcess(u32),
    /// Process exited — clean up mappings and LPM trie entries.
    ProcessExited(u32),
    /// Process called execve() — invalidate and reload DWARF tables.
    ProcessExeced(u32),
}

/// Build a `DwarfRefreshUpdate` and send it on the `PerfWork` channel.
///
/// Returns `true` if nothing changed or the update was sent successfully.
/// Returns `false` if the channel is disconnected.
pub fn send_refresh(
    manager: &DwarfUnwindManager,
    tx: &mpsc::Sender<PerfWork>,
    new_shard_ids: Vec<u16>,
    diff: MappingsDiff,
) -> bool {
    if let Some(update) = build_dwarf_refresh(manager, &new_shard_ids, diff) {
        tx.send(PerfWork::DwarfRefresh(update)).is_ok()
    } else {
        true
    }
}

/// Background thread: handles dlopen rescans and new process DWARF loading.
///
/// Runs in a dedicated `std::thread`. Drains `DwarfThreadMsg` messages for
/// new process loads and exit cleanup, then periodically rescans all tracked
/// processes' `/proc/[pid]/maps` mtime to detect dlopen'd libraries (~1s).
pub fn dwarf_refresh_loop(
    mut manager: DwarfUnwindManager,
    initial_pid: Option<u32>,
    tgid_rx: mpsc::Receiver<DwarfThreadMsg>,
    tx: mpsc::Sender<PerfWork>,
) {
    let mut tracked_pids: Vec<u32> = initial_pid.into_iter().collect();
    let mut last_maps_mtime: HashMap<u32, Option<std::time::SystemTime>> = HashMap::new();

    // Record initial mtime for pre-loaded PIDs so the first retain cycle
    // doesn't redundantly call refresh_process on them.
    for &pid in &tracked_pids {
        let maps_path = format!("/proc/{}/maps", pid);
        let mtime = std::fs::metadata(&maps_path)
            .ok()
            .and_then(|m| m.modified().ok());
        last_maps_mtime.insert(pid, mtime);
    }

    loop {
        // Drain all pending messages (non-blocking)
        while let Ok(msg) = tgid_rx.try_recv() {
            match msg {
                DwarfThreadMsg::LoadProcess(new_tgid) => {
                    if !tracked_pids.contains(&new_tgid) {
                        tracked_pids.push(new_tgid);
                        let maps_path = format!("/proc/{}/maps", new_tgid);
                        let pre_refresh_mtime = std::fs::metadata(&maps_path)
                            .ok()
                            .and_then(|m| m.modified().ok());
                        if let Ok((new_shard_ids, diff)) = manager.refresh_process(new_tgid) {
                            if !send_refresh(&manager, &tx, new_shard_ids, diff) {
                                return;
                            }
                            // Only record mtime after a successful refresh/send so
                            // failed refreshes will be retried when /proc/<pid>/maps
                            // mtime changes on the next periodic rescan.
                            last_maps_mtime.insert(new_tgid, pre_refresh_mtime);
                        }
                    }
                }
                DwarfThreadMsg::ProcessExited(tgid) => {
                    tracing::debug!("DWARF thread: process {} exited, cleaning up", tgid);
                    if let Some(removal_diff) = manager.remove_process(tgid) {
                        if !send_refresh(&manager, &tx, vec![], removal_diff) {
                            return;
                        }
                    }
                    tracked_pids.retain(|&p| p != tgid);
                    last_maps_mtime.remove(&tgid);
                }
                DwarfThreadMsg::ProcessExeced(tgid) => {
                    tracing::debug!(
                        "DWARF thread: process {} exec'd, invalidating and reloading",
                        tgid
                    );
                    // Remove old DWARF data (binary image has changed)
                    if let Some(removal_diff) = manager.remove_process(tgid) {
                        if !send_refresh(&manager, &tx, vec![], removal_diff) {
                            return;
                        }
                    }
                    tracked_pids.retain(|&p| p != tgid);
                    last_maps_mtime.remove(&tgid);

                    // Reload with the new binary
                    tracked_pids.push(tgid);
                    let maps_path = format!("/proc/{}/maps", tgid);
                    let pre_refresh_mtime = std::fs::metadata(&maps_path)
                        .ok()
                        .and_then(|m| m.modified().ok());
                    if let Ok((new_shard_ids, diff)) = manager.refresh_process(tgid) {
                        if !send_refresh(&manager, &tx, new_shard_ids, diff) {
                            return;
                        }
                        last_maps_mtime.insert(tgid, pre_refresh_mtime);
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));

        // Periodic rescan of all tracked processes for dlopen'd libraries.
        // Prune exited PIDs to avoid stat'ing non-existent /proc entries.
        let mut channel_closed = false;
        tracked_pids.retain(|&pid| {
            if channel_closed {
                return true; // stop processing, will exit after retain
            }

            let maps_path = format!("/proc/{}/maps", pid);
            let current_mtime = match std::fs::metadata(&maps_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Process exited — /proc/[pid]/maps no longer exists.
                    // Clean up DWARF/LPM state for this process.
                    if let Some(removal_diff) = manager.remove_process(pid) {
                        if !send_refresh(&manager, &tx, vec![], removal_diff) {
                            channel_closed = true;
                        }
                    }
                    last_maps_mtime.remove(&pid);
                    return false; // remove from tracked_pids
                }
                Err(_) => {
                    // Other I/O error (permission, etc.) — keep PID, skip this cycle
                    return true;
                }
                Ok(metadata) => metadata.modified().ok(),
            };

            // Skip rescan if /proc/[pid]/maps hasn't changed
            if let Some(Some(last_ts)) = last_maps_mtime.get(&pid) {
                if current_mtime.as_ref() == Some(last_ts) {
                    return true; // keep PID, skip rescan
                }
            }

            if let Ok((new_shard_ids, diff)) = manager.refresh_process(pid) {
                // Always send — mapping changes (e.g. dlopen of a cached
                // binary) need LPM trie updates even without new shards.
                if !send_refresh(&manager, &tx, new_shard_ids, diff) {
                    channel_closed = true;
                }
                // Only record mtime after a successful refresh so failed
                // refreshes are retried on the next cycle.
                last_maps_mtime.insert(pid, current_mtime);
            }
            true // keep PID
        });

        if channel_closed {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer tasks and stopping mechanisms
// ---------------------------------------------------------------------------

/// Async task that polls the eBPF ring buffer for stack trace events and
/// forwards them to the profiling event loop via the `PerfWork` channel.
pub async fn setup_ring_buffer_task(
    ring_buf: RingBuf<MapData>,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut fd = AsyncFd::new(ring_buf)?;

    while let Ok(mut guard) = fd.readable_mut().await {
        match guard.try_io(|inner| {
            let ring_buf = inner.get_mut();
            while let Some(item) = ring_buf.next() {
                if item.len() < StackInfo::STRUCT_SIZE {
                    tracing::warn!(
                        "Ring buffer item too small for StackInfo ({} < {}), skipping",
                        item.len(),
                        StackInfo::STRUCT_SIZE,
                    );
                    continue;
                }
                let stack: StackInfo = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                if perf_tx.send(PerfWork::StackInfo(stack)).is_err() {
                    // Receiver dropped — event loop is done, exit task
                    return Ok(());
                }
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

/// Async task that polls the eBPF ring buffer for process exit events and
/// forwards them to the profiling event loop via the `PerfWork` channel.
pub async fn setup_process_exit_ring_buffer_task(
    ring_buf: RingBuf<MapData>,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut fd = AsyncFd::new(ring_buf)?;

    while let Ok(mut guard) = fd.readable_mut().await {
        match guard.try_io(|inner| {
            let ring_buf = inner.get_mut();
            while let Some(item) = ring_buf.next() {
                if item.len() < ProcessExitEvent::STRUCT_SIZE {
                    tracing::warn!(
                        "Ring buffer item too small for ProcessExitEvent ({} < {}), skipping",
                        item.len(),
                        ProcessExitEvent::STRUCT_SIZE,
                    );
                    continue;
                }
                let exit_event: ProcessExitEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                let event = ProcessEvent {
                    event_type: PROCESS_EVENT_EXIT,
                    pid: exit_event.pid,
                    exit_code: exit_event.exit_code,
                    _pad: 0,
                };
                tracing::debug!("eBPF detected: PID {} has exited", event.pid);
                if perf_tx.send(PerfWork::ProcessEvent(event)).is_err() {
                    // Receiver dropped — event loop is done, exit task
                    return Ok(());
                }
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

/// Async task that polls the eBPF ring buffer for process exec events and
/// forwards them to the profiling event loop via the `PerfWork` channel.
pub async fn setup_process_exec_ring_buffer_task(
    ring_buf: RingBuf<MapData>,
    perf_tx: mpsc::Sender<PerfWork>,
) -> anyhow::Result<()> {
    use tokio::io::unix::AsyncFd;
    let mut fd = AsyncFd::new(ring_buf)?;

    while let Ok(mut guard) = fd.readable_mut().await {
        match guard.try_io(|inner| {
            let ring_buf = inner.get_mut();
            while let Some(item) = ring_buf.next() {
                if item.len() < ProcessExecEvent::STRUCT_SIZE {
                    tracing::warn!(
                        "Ring buffer item too small for ProcessExecEvent ({} < {}), skipping",
                        item.len(),
                        ProcessExecEvent::STRUCT_SIZE,
                    );
                    continue;
                }
                let exec_event: ProcessExecEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                let event = ProcessEvent {
                    event_type: PROCESS_EVENT_EXEC,
                    pid: exec_event.pid,
                    exit_code: 0,
                    _pad: 0,
                };
                tracing::debug!("eBPF detected: PID {} called exec", event.pid);
                if perf_tx.send(PerfWork::ProcessEvent(event)).is_err() {
                    return Ok(());
                }
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

/// Set up timer-based and child-process-based stopping mechanisms.
///
/// This wires the non-interactive stopping mechanisms:
/// - Timer expiry (`duration > 0` means stop after N ms; 0 = run indefinitely)
/// - Child process completion (for `-- <command>` spawned processes)
///
/// Both the timer and the child-exit task clone `perf_tx` and may each send
/// `PerfWork::Stop`. Receiving multiple Stops is intentional and benign —
/// the event loop in `ProfilingEventLoop::collect()` breaks on the first
/// Stop, and any extra Stop remains in the channel (dropped when the
/// receiver is dropped after `collect()` returns).
///
/// Note: Ctrl-C handling is left to the caller (typically the CLI binary)
/// since library consumers may want different signal handling.
pub fn setup_timer_and_child_stop(
    duration: usize,
    perf_tx: mpsc::Sender<PerfWork>,
    spawn: Option<SpawnProcess>,
) {
    // Timer-based stopping (duration == 0 means run indefinitely)
    if duration > 0 {
        let time_stop_tx = perf_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(duration as _)).await;
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
}

/// Set up a Ctrl-C handler that sends `PerfWork::Stop` on the channel.
///
/// Separated from `setup_timer_and_child_stop` because library consumers
/// may want their own signal handling.
pub fn setup_ctrlc_stop(perf_tx: mpsc::Sender<PerfWork>, stopper: Option<StopHandler>) {
    tokio::spawn(async move {
        tracing::debug!("Ctrl-C handler: waiting for signal");
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("Ctrl-C received, sending Stop");
                drop(stopper);
                perf_tx.send(PerfWork::Stop).unwrap_or_default();
            }
            Err(e) => {
                tracing::error!("Failed to listen for Ctrl-C signal: {}", e);
                // Don't send Stop or drop stopper — the signal handler
                // failed to install, so we shouldn't act as if Ctrl-C
                // was received. Other stop mechanisms (timer, child exit)
                // will still work.
            }
        }
    });
}
