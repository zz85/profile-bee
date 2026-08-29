//! JIT symbol resolution via Linux perf map files.
//!
//! Runtimes such as the HotSpot JVM, Node.js/V8, and PyPy can emit
//! `/tmp/perf-<pid>.map` (and sometimes `/tmp/jitted-<pid>-*.map`) describing
//! dynamically generated code:
//!
//! ```text
//! <start_hex> <size_hex> <symbol name...>
//! 7f8a2c001000 240 Ljava/lang/String;equals
//! 7f8a2c001250 1a0 Interpreter
//! ```
//!
//! profile-bee watches these files per PID and uses them as a fallback when
//! blazesym cannot resolve an address (typical for JIT code in anonymous
//! mappings). Maps are reloaded when the file mtime/size changes.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One contiguous JIT code range and its display name.
#[derive(Debug, Clone)]
pub struct PerfMapEntry {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

/// Parsed, sorted perf-map for a single process.
#[derive(Debug, Default)]
pub struct PerfMap {
    /// Ranges sorted by `start` ascending (non-overlapping preferred).
    entries: Vec<PerfMapEntry>,
    /// Source path used for this map (for logging / reload).
    path: Option<PathBuf>,
    /// Last observed (mtime, length) so we can cheaply detect updates.
    fingerprint: Option<(SystemTime, u64)>,
}

impl PerfMap {
    /// Parse a perf-map file from disk. Returns an empty map if the file is
    /// missing or unreadable (callers treat that as "no JIT symbols yet").
    pub fn load(path: &Path) -> Self {
        let mut map = PerfMap {
            path: Some(path.to_path_buf()),
            ..Default::default()
        };
        map.reload();
        map
    }

    /// Parse from an in-memory string (tests / alternate sources).
    pub fn parse(contents: &str) -> Self {
        PerfMap {
            entries: parse_perf_map_contents(contents),
            ..Default::default()
        }
    }

    /// Number of symbol ranges currently loaded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a symbol name for `addr` (inclusive start, exclusive end).
    pub fn lookup(&self, addr: u64) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        // Binary search for the last entry with start <= addr.
        let idx = match self.entries.binary_search_by(|e| e.start.cmp(&addr)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let entry = &self.entries[idx];
        if addr >= entry.start && addr < entry.end {
            Some(entry.name.as_str())
        } else {
            None
        }
    }

    /// Re-read the backing file if mtime/size changed. Returns `true` if the
    /// in-memory table was replaced.
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            return false;
        };
        let Ok(meta) = fs::metadata(&path) else {
            // File vanished — clear entries so we stop resolving stale ranges.
            if !self.entries.is_empty() {
                self.entries.clear();
                self.fingerprint = None;
                return true;
            }
            return false;
        };
        let mtime = meta.modified().ok();
        let len = meta.len();
        let fp = mtime.map(|m| (m, len));
        if fp == self.fingerprint && self.fingerprint.is_some() {
            return false;
        }
        self.reload();
        true
    }

    fn reload(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        match fs::read_to_string(path) {
            Ok(contents) => {
                let meta = fs::metadata(path).ok();
                self.fingerprint = meta.and_then(|m| m.modified().ok().map(|t| (t, m.len())));
                self.entries = parse_perf_map_contents(&contents);
                tracing::debug!(
                    "loaded perf-map {} ({} entries)",
                    path.display(),
                    self.entries.len()
                );
            }
            Err(e) => {
                tracing::trace!("perf-map {}: {}", path.display(), e);
                self.entries.clear();
                self.fingerprint = None;
            }
        }
    }
}

/// Per-PID cache of perf maps with lazy load + periodic refresh.
#[derive(Debug, Default)]
pub struct PerfMapCache {
    maps: HashMap<u32, PerfMap>,
    /// How often to re-check mtime (wall clock). Checked on lookup.
    /// Using a simple call counter avoids needing Instant on every path.
    lookups_since_refresh: HashMap<u32, u32>,
    /// Refresh file metadata every N lookups per PID.
    refresh_every: u32,
}

impl PerfMapCache {
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
            lookups_since_refresh: HashMap::new(),
            refresh_every: 64,
        }
    }

    /// Drop cached state for a PID (process exit / exec).
    pub fn remove(&mut self, pid: u32) {
        self.maps.remove(&pid);
        self.lookups_since_refresh.remove(&pid);
    }

    /// Ensure a PID is tracked. Tries standard paths under `/tmp`.
    ///
    /// Safe to call repeatedly — no-op if already registered with a non-empty
    /// map; re-probes the filesystem if the map is still empty (JVM may create
    /// the file after the first samples).
    pub fn ensure_pid(&mut self, pid: u32) {
        if let Some(existing) = self.maps.get(&pid) {
            if !existing.is_empty() {
                return;
            }
            // Still empty — try again in case the runtime just wrote the file.
        }
        if let Some(path) = find_perf_map_path(pid) {
            let map = PerfMap::load(&path);
            if !map.is_empty() {
                tracing::info!(
                    "loaded JIT perf-map for pid {} from {} ({} symbols)",
                    pid,
                    path.display(),
                    map.len()
                );
            } else {
                tracing::debug!(
                    "perf-map for pid {} present but empty/unreadable: {}",
                    pid,
                    path.display()
                );
            }
            self.maps.insert(pid, map);
        } else {
            // Remember an empty placeholder so we can re-probe on lookup
            // without hammering the filesystem every sample — still re-probe
            // occasionally via ensure on new tgid only; callers also call
            // `try_discover` periodically.
            self.maps.entry(pid).or_default();
        }
    }

    /// Attempt discovery again for PIDs that have no symbols yet.
    pub fn try_discover(&mut self, pid: u32) {
        let needs = match self.maps.get(&pid) {
            None => true,
            Some(m) => m.is_empty(),
        };
        if needs {
            if let Some(path) = find_perf_map_path(pid) {
                let map = PerfMap::load(&path);
                if !map.is_empty() {
                    tracing::info!(
                        "discovered JIT perf-map for pid {} ({} symbols)",
                        pid,
                        map.len()
                    );
                    self.maps.insert(pid, map);
                }
            }
        }
    }

    /// Force-load a known map path (e.g. after auto-dump / container path).
    pub fn load_path(&mut self, pid: u32, path: &Path) {
        let map = PerfMap::load(path);
        if !map.is_empty() {
            tracing::info!(
                "loaded JIT perf-map for pid {} from {} ({} symbols)",
                pid,
                path.display(),
                map.len()
            );
        }
        self.maps.insert(pid, map);
        self.lookups_since_refresh.insert(pid, 0);
    }

    /// Force mtime reload for every tracked PID (periodic JIT refresh).
    pub fn reload_all(&mut self) {
        let pids: Vec<u32> = self.maps.keys().copied().collect();
        for pid in pids {
            if let Some(map) = self.maps.get_mut(&pid) {
                if map.reload_if_changed() {
                    tracing::debug!(
                        "reloaded JIT perf-map for pid {} ({} symbols)",
                        pid,
                        map.len()
                    );
                }
            }
            // Re-discover empty maps in case dump landed on an alternate path.
            self.try_discover(pid);
        }
    }

    /// Resolve `addr` for `pid`, refreshing the file periodically.
    pub fn lookup(&mut self, pid: u32, addr: u64) -> Option<String> {
        // Periodic reload for live JIT updates.
        let count = self.lookups_since_refresh.entry(pid).or_insert(0);
        *count = count.saturating_add(1);
        let should_refresh = *count >= self.refresh_every;
        if should_refresh {
            *count = 0;
        }

        if should_refresh {
            if let Some(map) = self.maps.get_mut(&pid) {
                let _ = map.reload_if_changed();
            } else {
                self.try_discover(pid);
            }
        }

        self.maps
            .get(&pid)
            .and_then(|m| m.lookup(addr).map(|s| s.to_string()))
    }

    /// Whether we currently have any symbols for this PID.
    pub fn has_symbols(&self, pid: u32) -> bool {
        self.maps.get(&pid).is_some_and(|m| !m.is_empty())
    }
}

/// Locate a perf-map file for `pid`.
///
/// Checks, in order:
/// 1. `/tmp/perf-<pid>.map` (kernel perf / JVM / V8 convention)
/// 2. `/tmp/perf-<nspid>.map` (container PID namespace ID)
/// 3. `/proc/<pid>/root/tmp/perf-*.map` (container host view of guest /tmp)
pub fn find_perf_map_path(pid: u32) -> Option<PathBuf> {
    let mut candidates = vec![
        PathBuf::from(format!("/tmp/perf-{pid}.map")),
        PathBuf::from(format!("/proc/{pid}/root/tmp/perf-{pid}.map")),
    ];
    // Nested PID namespaces: JVM often names the file with the innermost PID.
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("NSpid:") {
                for nspid in rest.split_whitespace().filter_map(|s| s.parse::<u32>().ok()) {
                    candidates.push(PathBuf::from(format!("/tmp/perf-{nspid}.map")));
                    candidates.push(PathBuf::from(format!(
                        "/proc/{pid}/root/tmp/perf-{nspid}.map"
                    )));
                }
                break;
            }
        }
    }
    candidates.into_iter().find(|path| path.is_file())
}

/// Parse perf-map text into sorted, non-empty entries.
fn parse_perf_map_contents(contents: &str) -> Vec<PerfMapEntry> {
    let mut entries = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: START SIZE NAME...  (hex start/size, rest is name)
        let mut parts = line.splitn(3, char::is_whitespace);
        let Some(start_s) = parts.next() else {
            continue;
        };
        // Skip additional whitespace between fields manually via splitn on
        // whitespace doesn't collapse runs — handle carefully.
        let rest_after_start = line[start_s.len()..].trim_start();
        let mut parts2 = rest_after_start.splitn(2, char::is_whitespace);
        let Some(size_s) = parts2.next() else {
            continue;
        };
        let name = parts2.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }

        let start = match u64::from_str_radix(start_s.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let size = match u64::from_str_radix(size_s.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if size == 0 {
            continue;
        }
        let end = start.saturating_add(size);
        entries.push(PerfMapEntry {
            start,
            end,
            name: name.to_string(),
        });
    }

    entries.sort_by_key(|e| e.start);
    // Drop exact duplicate starts, keeping the last (usually newer JIT tier).
    let mut deduped = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(last) = deduped.last_mut() {
            let last: &mut PerfMapEntry = last;
            if last.start == entry.start {
                *last = entry;
                continue;
            }
        }
        deduped.push(entry);
    }
    deduped
}

/// Format a raw perf-map symbol for flamegraph display.
///
/// HotSpot often emits names like:
/// - `Ljava/lang/String;equals`
/// - `Lorg/example/App;main`
/// - `Interpreter`
/// - `compile_id=42`
///
/// V8 names are left for the existing V8 formatter when those prefixes match.
pub fn format_jit_symbol(raw: &str) -> String {
    // HotSpot JNI-style: Lpkg/Class;method
    if let Some(formatted) = format_hotspot_method(raw) {
        return formatted;
    }
    raw.to_string()
}

/// Convert `Ljava/lang/String;equals` → `java.lang.String.equals`.
fn format_hotspot_method(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix('L')?;
    let (class, method) = rest.split_once(';')?;
    if class.is_empty() || method.is_empty() {
        return None;
    }
    // Drop signature if present: `method(Ljava/lang/Object;)Z`
    let method_name = method.split('(').next().unwrap_or(method);
    if method_name.is_empty() {
        return None;
    }
    let class_dot = class.replace('/', ".");
    Some(format!("{}.{}", class_dot, method_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_entries() {
        let text = "\
7f0000001000 100 Ljava/lang/String;equals
7f0000001100 200 Lorg/example/App;main([Ljava/lang/String;)V
7f0000001400 a0 Interpreter
";
        let map = PerfMap::parse(text);
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.lookup(0x7f0000001000 + 0x10),
            Some("Ljava/lang/String;equals")
        );
        assert_eq!(
            map.lookup(0x7f0000001100),
            Some("Lorg/example/App;main([Ljava/lang/String;)V")
        );
        assert_eq!(map.lookup(0x7f0000001400 + 0x20), Some("Interpreter"));
        assert_eq!(map.lookup(0x7f0000000fff), None);
        assert_eq!(map.lookup(0x7f0000001500), None);
    }

    #[test]
    fn parse_skips_junk() {
        let text = "\
# comment
not_hex 10 foo
7f00 0 empty_size_skipped
7abc 10
7abc 10 valid_name
";
        let map = PerfMap::parse(text);
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(0x7abc), Some("valid_name"));
    }

    #[test]
    fn format_hotspot_names() {
        assert_eq!(
            format_jit_symbol("Ljava/lang/String;equals"),
            "java.lang.String.equals"
        );
        assert_eq!(
            format_jit_symbol("Lorg/example/App;main([Ljava/lang/String;)V"),
            "org.example.App.main"
        );
        assert_eq!(format_jit_symbol("Interpreter"), "Interpreter");
        assert_eq!(format_jit_symbol("something_else"), "something_else");
    }

    #[test]
    fn cache_lookup_and_remove() {
        let mut cache = PerfMapCache::new();
        cache.maps.insert(
            42,
            PerfMap::parse("1000 10 Ljava/lang/Object;hashCode\n"),
        );
        assert!(cache.has_symbols(42));
        assert_eq!(
            cache.lookup(42, 0x1005).as_deref(),
            Some("Ljava/lang/Object;hashCode")
        );
        cache.remove(42);
        assert!(!cache.has_symbols(42));
        assert_eq!(cache.lookup(42, 0x1005), None);
    }

    #[test]
    fn overlapping_keeps_last_duplicate_start() {
        let map = PerfMap::parse(
            "\
1000 50 old_name
1000 80 new_name
",
        );
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(0x1000), Some("new_name"));
        // Size comes from the replacement entry.
        assert_eq!(map.lookup(0x1000 + 0x60), Some("new_name"));
    }
}
