use std::{collections::HashMap, ffi::OsString, fs, os::unix::fs::MetadataExt, path::PathBuf};

use procfs::process::{MMPermissions, MMapPath, MemoryMap, MemoryMaps, Process, Stat};

use crate::legacy::symbols::StackFrameInfo;

/// Process information container
///
/// Holds metadata about a running process including environment variables,
/// command line, working directory, and memory mappings needed for stack trace resolution.
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
    pub fn new(pid: usize) -> Self {
        let process = Process::new(pid as i32).ok();

        let (environ, cmdline, stat, cwd, maps) = process
            .as_ref()
            .map(|p| {
                (
                    p.environ().ok(),
                    p.cmdline().ok(),
                    p.stat().ok(),
                    p.cwd().ok(),
                    p.maps().ok(),
                )
            })
            .unwrap_or_default();

        let ns_mnt = &format!("/proc/{}/ns/mnt", pid);
        let ns = fs::metadata(ns_mnt).ok().map(|meta| meta.ino());
        let mapper = ProcessMapper::new(maps);

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

/// Memory mapping resolver for processes
///
/// Maps virtual memory addresses to physical addresses and associated binary files
/// by analyzing the process memory maps from /proc/<pid>/maps.
pub struct ProcessMapper {
    maps: Vec<MemoryMap>,
}

impl ProcessMapper {
    pub fn new(maps: Option<MemoryMaps>) -> Option<Self> {
        let maps = maps?;
        let maps = maps
            .into_iter()
            .filter(|r| {
                let perms = &r.perms;
                ProcessMapper::is_exec(perms)
                    && !ProcessMapper::is_write(perms)
                    && ProcessMapper::is_read(perms)
            })
            .collect::<Vec<_>>();

        Some(ProcessMapper { maps })
    }

    fn is_exec(flags: &MMPermissions) -> bool {
        flags.contains(MMPermissions::EXECUTE)
    }
    fn is_write(flags: &MMPermissions) -> bool {
        flags.contains(MMPermissions::WRITE)
    }
    fn is_read(flags: &MMPermissions) -> bool {
        flags.contains(MMPermissions::READ)
    }

    pub fn lookup(&self, address: usize, info: &mut StackFrameInfo) {
        for m in &self.maps {
            let start = m.address.0 as usize;
            if address >= start && address < m.address.1 as usize {
                if let MMapPath::Path(path) = &m.pathname {
                    info.object_path = Some(path.clone());

                    let translated = if path.ends_with(".so") {
                        address
                    } else {
                        address - start
                    };

                    info.address = translated as _;
                }
            }
        }
        // we can't translate address, so keep things as they are
    }
}
