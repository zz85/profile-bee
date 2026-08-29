//! HotSpot JVM detection and perf-map integration.
//!
//! A JVM can publish its JIT code cache through the standard
//! `/tmp/perf-<pid>.map` format. `blazesym` consumes that format through the
//! existing process symbolization path, so no special symbolizer is needed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Return whether a binary name identifies the HotSpot Java launcher.
///
/// This intentionally recognizes only launchers, not arbitrary binaries whose
/// name happens to contain "java".
pub fn is_hotspot_binary(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    matches!(name, "java" | "javaw" | "java.exe" | "javaw.exe")
        || (name.starts_with("java-")
            && name[5..]
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.'))
}

/// Return the conventional perf-map path for a process.
pub fn perf_map_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/perf-{pid}.map"))
}

/// Add `-XX:+PreserveFramePointer` unless it is already present.
pub fn java_tool_options_with_frame_pointers(existing: Option<String>) -> String {
    const FLAG: &str = "-XX:+PreserveFramePointer";

    match existing {
        Some(mut options) if !options.is_empty() => {
            if !options.split_whitespace().any(|option| option == FLAG) {
                options.push(' ');
                options.push_str(FLAG);
            }
            options
        }
        _ => FLAG.to_string(),
    }
}

/// Change observed in a JVM's perf-map availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfMapChange {
    /// The map was found for the first time.
    Available,
    /// The map was created, removed, or rewritten.
    Changed,
}

#[derive(Default)]
struct PerfMapState {
    modified: Option<SystemTime>,
    checked_at: Option<Instant>,
}

/// Tracks HotSpot perf maps discovered during system-wide profiling.
///
/// `blazesym` consumes perf maps through the ordinary process source. Whenever
/// a map changes, callers must invalidate cached process symbols so generated
/// code is symbolized against its current code-cache entries.
#[derive(Default)]
pub struct HotSpotPerfMapTracker {
    processes: HashMap<u32, PerfMapState>,
}

impl HotSpotPerfMapTracker {
    const CHECK_INTERVAL: Duration = Duration::from_secs(1);

    /// Inspect a sampled process and return a transition in its perf-map state.
    pub fn observe(&mut self, pid: u32) -> Option<PerfMapChange> {
        let state = self.processes.entry(pid).or_default();
        let now = Instant::now();
        if state
            .checked_at
            .is_some_and(|checked_at| now.duration_since(checked_at) < Self::CHECK_INTERVAL)
        {
            return None;
        }
        state.checked_at = Some(now);

        let modified = std::fs::metadata(perf_map_path(pid))
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        let was_available = state.modified.is_some();
        let changed = state.modified != modified;
        state.modified = modified;

        match (was_available, state.modified, changed) {
            (false, Some(_), _) => Some(PerfMapChange::Available),
            (_, _, true) => Some(PerfMapChange::Changed),
            _ => None,
        }
    }

    /// Stop tracking a process after exec or exit so a reused PID is rediscovered.
    pub fn remove(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hotspot_launchers_without_matching_unrelated_names() {
        assert!(is_hotspot_binary(Path::new("/usr/bin/java")));
        assert!(is_hotspot_binary(Path::new("/usr/bin/java-21")));
        assert!(is_hotspot_binary(Path::new("javaw")));
        assert!(!is_hotspot_binary(Path::new("/usr/bin/javascript")));
        assert!(!is_hotspot_binary(Path::new("/usr/bin/javac")));
    }

    #[test]
    fn adds_frame_pointer_flag_once() {
        assert_eq!(
            java_tool_options_with_frame_pointers(Some("-Xmx1g".to_string())),
            "-Xmx1g -XX:+PreserveFramePointer"
        );
        assert_eq!(
            java_tool_options_with_frame_pointers(Some(
                "-XX:+PreserveFramePointer -Xmx1g".to_string()
            )),
            "-XX:+PreserveFramePointer -Xmx1g"
        );
    }

    #[test]
    fn missing_perf_map_has_no_transition() {
        let mut tracker = HotSpotPerfMapTracker::default();
        assert_eq!(tracker.observe(u32::MAX), None);
    }
}
