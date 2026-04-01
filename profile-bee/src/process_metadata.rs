//! Process metadata cache for reading and caching `/proc/[pid]` information.
//!
//! Provides a lazy, capacity-bounded cache of process metadata that agents
//! can use to look up `cmdline`, `cwd`, `environ`, `exe`, and mount namespace
//! for any PID seen during profiling. Entries are invalidated on exec events
//! (same PID, new binary) and removed on exit events.
//!
//! # Example
//!
//! ```rust,ignore
//! use profile_bee::process_metadata::ProcessMetadataCache;
//!
//! let mut cache = ProcessMetadataCache::new(1024);
//!
//! // Lazily loads from /proc on first access
//! if let Some(meta) = cache.get_or_load(1234) {
//!     println!("exe: {:?}", meta.exe);
//!     println!("cwd: {:?}", meta.cwd);
//! }
//!
//! // On exec: invalidate (same PID, new binary)
//! cache.invalidate(1234);
//!
//! // On exit: remove entirely
//! cache.remove(1234);
//! ```

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

/// Cached metadata for a single process, read from `/proc/[pid]/`.
#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    /// The process ID.
    pub pid: u32,
    /// Parsed command line (`/proc/[pid]/cmdline`).
    pub cmdline: Option<Vec<String>>,
    /// Working directory (`/proc/[pid]/cwd`).
    pub cwd: Option<PathBuf>,
    /// Environment variables (`/proc/[pid]/environ`).
    pub environ: Option<HashMap<OsString, OsString>>,
    /// Executable path (`/proc/[pid]/exe` readlink).
    pub exe: Option<PathBuf>,
    /// Mount namespace inode (`/proc/[pid]/ns/mnt`).
    pub ns_mnt: Option<u64>,
    /// Process start time in clock ticks since boot (`/proc/[pid]/stat` field 22).
    /// Used to detect PID reuse — if a cached entry's start_time differs from
    /// the current `/proc/[pid]/stat` starttime, the PID was recycled.
    pub start_time: u64,
    /// When this entry was loaded.
    pub loaded_at: Instant,
}

impl ProcessMetadata {
    /// Load metadata for a PID from `/proc`.
    /// Returns `None` if the process doesn't exist or `/proc/[pid]/stat`
    /// can't be read (start_time is required for PID reuse detection).
    fn load(pid: u32) -> Option<Self> {
        let process = procfs::process::Process::new(pid as i32).ok()?;

        let stat = process.stat().ok()?;
        let start_time = stat.starttime;

        let cmdline = process.cmdline().ok();
        let cwd = process.cwd().ok();
        let environ = process.environ().ok();
        let exe = process.exe().ok();

        // Get mount namespace inode
        let ns_path = format!("/proc/{}/ns/mnt", pid);
        let ns_mnt = std::fs::metadata(&ns_path).ok().map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.ino()
        });

        Some(ProcessMetadata {
            pid,
            cmdline,
            cwd,
            environ,
            exe,
            ns_mnt,
            start_time,
            loaded_at: Instant::now(),
        })
    }

    /// Read the current start time for a PID from `/proc/[pid]/stat`.
    /// Returns 0 if the process doesn't exist or stat can't be read.
    fn current_start_time(pid: u32) -> u64 {
        procfs::process::Process::new(pid as i32)
            .ok()
            .and_then(|p| p.stat().ok())
            .map_or(0, |s| s.starttime)
    }

    /// Look up a specific environment variable by name.
    pub fn environ_var(&self, key: &str) -> Option<&str> {
        self.environ
            .as_ref()?
            .get(std::ffi::OsStr::new(key))?
            .to_str()
    }
}

/// Capacity-bounded cache of process metadata, read lazily from `/proc/[pid]/`.
///
/// Designed for profiling agents that need per-process context (cmdline, cwd,
/// environment variables) to enrich stack traces. Integrates with eBPF process
/// lifecycle events for cache invalidation (exec) and eviction (exit).
///
/// The cache does NOT implement LRU eviction — it relies on explicit `remove()`
/// calls driven by eBPF exit events. If the cache reaches capacity, new entries
/// are not inserted (the process is still profiled, just without cached metadata).
pub struct ProcessMetadataCache {
    cache: HashMap<u32, ProcessMetadata>,
    max_entries: usize,
}

impl ProcessMetadataCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_entries,
        }
    }

    /// Get or lazily load metadata for a PID.
    ///
    /// On first access for a given PID, reads from `/proc/[pid]/`. Subsequent
    /// calls return the cached entry unless the PID has been recycled (detected
    /// via `/proc/[pid]/stat` starttime mismatch). Returns `None` if the process
    /// doesn't exist (already exited) or the cache is at capacity.
    pub fn get_or_load(&mut self, pid: u32) -> Option<&ProcessMetadata> {
        if self.cache.contains_key(&pid) {
            // Validate against PID reuse and process exit: compare the cached
            // start_time against the current /proc/[pid]/stat starttime.
            let cached_start = self.cache[&pid].start_time;
            let current_start = ProcessMetadata::current_start_time(pid);
            if current_start == 0 {
                // Process is gone (/proc/[pid]/stat unreadable) — remove stale entry.
                self.cache.remove(&pid);
                return None;
            }
            if current_start != cached_start {
                tracing::debug!(
                    "PID {} recycled (starttime {} -> {}), reloading metadata",
                    pid,
                    cached_start,
                    current_start,
                );
                self.cache.remove(&pid);
                // Fall through to reload below
            } else {
                return self.cache.get(&pid);
            }
        }
        if self.cache.len() >= self.max_entries {
            tracing::warn!(
                "ProcessMetadataCache at capacity ({}), skipping pid {}",
                self.max_entries,
                pid
            );
            return None;
        }
        if let Some(meta) = ProcessMetadata::load(pid) {
            self.cache.insert(pid, meta);
            self.cache.get(&pid)
        } else {
            None
        }
    }

    /// Get cached metadata without loading. Returns `None` if not cached.
    pub fn get(&self, pid: u32) -> Option<&ProcessMetadata> {
        self.cache.get(&pid)
    }

    /// Invalidate the cached entry for a PID (e.g., on exec).
    ///
    /// The next `get_or_load()` call will re-read from `/proc`.
    pub fn invalidate(&mut self, pid: u32) {
        self.cache.remove(&pid);
    }

    /// Remove the cached entry for a PID (e.g., on exit).
    pub fn remove(&mut self, pid: u32) {
        self.cache.remove(&pid);
    }

    /// Look up a specific environment variable for a PID.
    ///
    /// Convenience method that combines `get_or_load` + `environ_var`.
    pub fn environ_var(&mut self, pid: u32, key: &str) -> Option<String> {
        self.get_or_load(pid)?
            .environ_var(key)
            .map(|s| s.to_string())
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Diagnostic summary string.
    pub fn stats(&self) -> String {
        format!(
            "ProcessMetadataCache: {}/{} entries",
            self.cache.len(),
            self.max_entries,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_new() {
        let cache = ProcessMetadataCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_load_current_process() {
        let mut cache = ProcessMetadataCache::new(100);
        let pid = std::process::id();
        let meta = cache.get_or_load(pid);
        assert!(meta.is_some(), "should be able to load current process");
        let meta = meta.unwrap();
        assert_eq!(meta.pid, pid);
        assert!(meta.exe.is_some());
        assert!(meta.cmdline.is_some());
        assert!(meta.cwd.is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_nonexistent_pid() {
        let mut cache = ProcessMetadataCache::new(100);
        // PID 0 is the kernel — /proc/0 may or may not exist depending on kernel.
        // Use a very high PID that almost certainly doesn't exist.
        let meta = cache.get_or_load(u32::MAX);
        assert!(meta.is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_invalidate() {
        let mut cache = ProcessMetadataCache::new(100);
        let pid = std::process::id();
        cache.get_or_load(pid);
        assert_eq!(cache.len(), 1);
        cache.invalidate(pid);
        assert!(cache.is_empty());
        // Re-load should work
        assert!(cache.get_or_load(pid).is_some());
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = ProcessMetadataCache::new(100);
        let pid = std::process::id();
        cache.get_or_load(pid);
        cache.remove(pid);
        assert!(cache.is_empty());
        assert!(cache.get(pid).is_none());
    }

    #[test]
    fn test_cache_capacity_limit() {
        let mut cache = ProcessMetadataCache::new(1);
        let pid = std::process::id();
        cache.get_or_load(pid);
        // Cache is full — next load should return None for a different PID
        // (but the PID probably doesn't exist anyway, so this is a bit indirect)
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_environ_var() {
        let mut cache = ProcessMetadataCache::new(100);
        let pid = std::process::id();
        // PATH should be set in any normal environment
        let path = cache.environ_var(pid, "PATH");
        assert!(path.is_some(), "PATH should be available");
    }

    #[test]
    fn test_get_without_load() {
        let cache = ProcessMetadataCache::new(100);
        let pid = std::process::id();
        // get() without get_or_load() should return None
        assert!(cache.get(pid).is_none());
    }

    #[test]
    fn test_stats() {
        let cache = ProcessMetadataCache::new(100);
        let stats = cache.stats();
        assert!(stats.contains("0/100"));
    }
}
