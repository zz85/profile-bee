use std::{collections::HashMap, ffi::OsString, fs, os::unix::fs::MetadataExt, path::PathBuf};

use proc_maps::{get_process_maps, MapRange};
use procfs::process::{Process, Stat};

use crate::symbols::{ObjItem, StackFrameInfo, SymbolError};

pub struct ProcessInfo {
    pub process: Option<Process>,
    pub environ: Option<HashMap<OsString, OsString>>,
    pub cmdline: Option<Vec<String>>,
    pub stat: Option<Stat>,
    pub cwd: Option<PathBuf>,
    pub ns: Option<u64>,
    pub mapper: Option<ProcessMapper>,
    pub exe_link: Option<PathBuf>,
    // pub obj: Option<ObjItem>,
}

impl ProcessInfo {
    fn new(pid: usize) -> Self {
        let process = Process::new(pid as i32).ok();

        let (environ, cmdline, stat, cwd) = process
            .as_ref()
            .map(|p| {
                (
                    p.environ().ok(),
                    p.cmdline().ok(),
                    p.stat().ok(),
                    p.cwd().ok(),
                )
            })
            .unwrap_or_default();

        let ns_mnt = &format!("/proc/{}/ns/mnt", pid);
        let ns = fs::metadata(ns_mnt).ok().map(|meta| meta.ino());
        let mapper = ProcessMapper::new(pid as i32).ok();

        let path = format!("/proc/{}/exe", pid);
        let exe_path = PathBuf::from(path);
        let exe_link = std::fs::read_link(&exe_path)
            .map_err(|_err| {
                println!(
                    "read_link err on {:?}. Cmd: {:?}, pid: {:?}",
                    exe_path, cmdline, pid
                );
            })
            .ok();

        Self {
            process,
            environ,
            cmdline,
            stat,
            cwd,
            ns,
            mapper,
            exe_link,
        }
    }

    pub fn environ(&self, key: &str) -> Option<&str> {
        let e = self.environ.as_ref()?;
        e.get(&OsString::from(key)).and_then(|s| s.to_str())
    }

    pub fn info(&self) -> bool {
        self.process.is_some()
    }

    pub fn process(&self) -> Option<&Process> {
        self.process.as_ref()
    }

    pub fn cmdline(&self) -> Option<&Vec<String>> {
        self.cmdline.as_ref()
    }
}

#[derive(Default)]
pub struct ProcessCache {
    map: HashMap<usize, ProcessInfo>,
}

impl ProcessCache {
    pub fn get(&mut self, pid: usize) -> Option<&ProcessInfo> {
        self.map.entry(pid).or_insert_with(|| ProcessInfo::new(pid));

        self.map.get(&pid)
    }
}

pub struct ProcessMapper {
    maps: Vec<MapRange>,
}

impl ProcessMapper {
    pub fn new(pid: i32) -> Result<Self, SymbolError> {
        let maps = get_process_maps(pid as _).map_err(|err| SymbolError::MapReadError { err })?;

        let maps = maps
            .into_iter()
            .filter(|r| r.is_exec() && !r.is_write() && r.is_read())
            .collect::<Vec<_>>();

        Ok(ProcessMapper { maps })
    }

    pub fn lookup(&self, address: usize, info: &mut StackFrameInfo) {
        for m in &self.maps {
            let start = m.start();

            if address >= start && address < (start + m.size()) {
                let translated = if m.filename().map(|f| f.ends_with(".so")).unwrap_or(false) {
                    address
                } else {
                    address - start
                };

                info.address = translated as _;
                info.object_path = m.filename().map(PathBuf::from);
            }
        }
        // we can't translate address, so keep things as they are
    }
}
