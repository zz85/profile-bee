//! Profiling pipeline coordination types and DWARF background management.
//!
//! Central types (`PerfWork`, `DwarfThreadMsg`) that define the communication
//! protocol between the profiling event loop, eBPF ring buffers, and the DWARF
//! background thread.

use std::collections::HashMap;
use std::sync::mpsc;

use profile_bee_common::{ProcessExitEvent, StackInfo};

use crate::dwarf_unwind::{DwarfUnwindManager, MappingsDiff};
use crate::ebpf::{build_dwarf_refresh, DwarfRefreshUpdate};

/// Message type for the profiler's communication channel.
///
/// All stopping mechanisms, ring buffer tasks, and the DWARF background
/// thread communicate with the profiling loop through this enum.
pub enum PerfWork {
    /// New stack sample from eBPF ring buffer.
    StackInfo(StackInfo),
    /// Incremental DWARF table update from background thread.
    DwarfRefresh(DwarfRefreshUpdate),
    /// Process exit detected by eBPF tracepoint.
    ProcessExit(ProcessExitEvent),
    /// Signal to stop profiling.
    Stop,
}

/// Message type for the DWARF background thread.
pub enum DwarfThreadMsg {
    /// New process to load DWARF data for.
    LoadProcess(u32),
    /// Process exited — clean up mappings and LPM trie entries.
    ProcessExited(u32),
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
