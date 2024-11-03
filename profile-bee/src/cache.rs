use crate::{process::ProcessInfo, symbols::StackFrameInfo};
use std::collections::HashMap;

/// Process lookup
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

/// Address Cache
#[derive(Default)]
pub struct AddrCache {
    map: HashMap<(i32, u64), StackFrameInfo>,
    total: usize,
    miss: usize,
}

impl AddrCache {
    pub fn get(&mut self, tgid: i32, address: u64) -> Option<StackFrameInfo> {
        let key = (tgid, address);
        self.total += 1;

        if let Some(ok) = self.map.get(&key) {
            return Some(ok.clone());
        }

        self.miss += 1;

        None
    }

    pub fn insert(&mut self, tgid: i32, address: u64, info: &StackFrameInfo) {
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

/// Top level points to formatted stack trace format
#[derive(Default)]
pub struct PointerStackFramesCache {
    map: HashMap<(i32, i32), Vec<StackFrameInfo>>,
    total: usize,
    miss: usize,
}

impl PointerStackFramesCache {
    pub fn get(&mut self, ktrace_id: i32, utrace_id: i32) -> Option<Vec<StackFrameInfo>> {
        let key = (ktrace_id, utrace_id);
        self.total += 1;

        if let Some(ok) = self.map.get(&key) {
            return Some(ok.clone());
        }

        self.miss += 1;

        None
    }

    pub fn insert(&mut self, ktrace_id: i32, utrace_id: i32, stacks: Vec<StackFrameInfo>) {
        self.map.insert((ktrace_id, utrace_id), stacks);
    }

    pub fn stats(&self) -> String {
        let hits = self.total - self.miss;
        format!(
            "PointerStackFramesCache entries: {}, hits: {}, miss: {}, hit ratio: {:.2}",
            self.map.len(),
            hits,
            self.miss,
            hits as f64 / self.total as f64 * 100.0
        )
    }
}
