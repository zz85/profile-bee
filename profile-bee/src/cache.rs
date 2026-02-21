use crate::legacy::process::ProcessInfo;
use std::collections::HashMap;

/// Process lookup cache
///
/// Caches process information to avoid repeated expensive lookups
/// of process details from the /proc filesystem.
#[derive(Default)]
pub struct ProcessCache {
    map: HashMap<usize, ProcessInfo>,
    total: usize,
    miss: usize,
}

impl ProcessCache {
    pub fn get(&mut self, pid: usize) -> Option<&ProcessInfo> {
        self.map.entry(pid).or_insert_with(|| {
            self.miss += 1;
            ProcessInfo::new(pid)
        });

        self.total += 1;
        self.map.get(&pid)
    }

    pub fn stats(&self) -> String {
        let hits = self.total - self.miss;
        format!(
            "Processes cache entries: {}, hits: {}, miss: {}, hit ratio: {:.2}",
            self.map.len(),
            hits,
            self.miss,
            hits as f64 / self.total as f64 * 100.0
        )
    }
}

/// Address to symbol resolution cache (legacy addr2line path)
///
/// Maps memory addresses to resolved stack frame information to avoid
/// expensive symbol resolution for addresses seen multiple times.
#[derive(Default)]
pub struct AddrCache {
    map: HashMap<(i32, u64), crate::legacy::symbols::StackFrameInfo>,
    total: usize,
    miss: usize,
}

impl AddrCache {
    pub fn get(
        &mut self,
        tgid: i32,
        address: u64,
    ) -> Option<crate::legacy::symbols::StackFrameInfo> {
        let key = (tgid, address);
        self.total += 1;

        if let Some(ok) = self.map.get(&key) {
            return Some(ok.clone());
        }

        self.miss += 1;

        None
    }

    pub fn insert(
        &mut self,
        tgid: i32,
        address: u64,
        info: &crate::legacy::symbols::StackFrameInfo,
    ) {
        self.map.insert((tgid, address), info.clone());
    }

    pub fn stats(&self) -> String {
        let hits = self.total - self.miss;
        format!(
            "AddrCache entries: {}, hits: {}, miss: {}, hit ratio: {:.2}",
            self.map.len(),
            hits,
            self.miss,
            hits as f64 / self.total as f64 * 100.0
        )
    }
}

/// Default maximum number of entries in the stack frame cache.
/// Bounded by the BPF stack_traces map size (16384). Using 16384 ensures
/// we can cache every unique stack the BPF side can track.
const DEFAULT_CACHE_CAPACITY: usize = 16384;

/// LRU cache for formatted stack traces.
///
/// Maps (tgid, kernel_stack_id, user_stack_id) to fully resolved stack frame
/// information to avoid repeated expensive symbol resolution, BPF map lookups,
/// and formatting operations.
///
/// The cache key includes `tgid` because symbolization is per-process (different
/// processes map different binaries at different addresses). The stack IDs come
/// from `bpf_get_stackid()` which hashes the raw instruction pointers — same ID
/// means same stack frames.
///
/// Uses an LRU eviction policy to bound memory for long-running sessions
/// (--serve, --tui) that profile many processes over time.
pub struct PointerStackFramesCache {
    map: lru::LruCache<(u32, i32, i32), Vec<crate::types::StackFrameInfo>>,
    total: usize,
    miss: usize,
}

impl Default for PointerStackFramesCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }
}

impl PointerStackFramesCache {
    pub fn new(capacity: usize) -> Self {
        // SAFETY: DEFAULT_CACHE_CAPACITY is a non-zero constant
        let cap = std::num::NonZeroUsize::new(capacity).unwrap_or(
            std::num::NonZeroUsize::new(DEFAULT_CACHE_CAPACITY)
                .expect("DEFAULT_CACHE_CAPACITY is non-zero"),
        );
        PointerStackFramesCache {
            map: lru::LruCache::new(cap),
            total: 0,
            miss: 0,
        }
    }

    pub fn get(
        &mut self,
        tgid: u32,
        ktrace_id: i32,
        utrace_id: i32,
    ) -> Option<&Vec<crate::types::StackFrameInfo>> {
        let key = (tgid, ktrace_id, utrace_id);
        self.total += 1;

        if let Some(hit) = self.map.get(&key) {
            return Some(hit);
        }

        self.miss += 1;

        None
    }

    pub fn insert(
        &mut self,
        tgid: u32,
        ktrace_id: i32,
        utrace_id: i32,
        stacks: Vec<crate::types::StackFrameInfo>,
    ) {
        self.map.put((tgid, ktrace_id, utrace_id), stacks);
    }

    pub fn stats(&self) -> String {
        let hits = self.total - self.miss;
        format!(
            "PointerStackFramesCache entries: {}/{}, hits: {}, miss: {}, hit ratio: {:.2}",
            self.map.len(),
            self.map.cap(),
            hits,
            self.miss,
            hits as f64 / self.total as f64 * 100.0
        )
    }
}
