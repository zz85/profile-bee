use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

use addr2line::{
    demangle, gimli,
    object::{Object, ObjectSymbol},
    ObjectContext,
};
use aya::{maps::stack_trace::StackTrace, util::kernel_symbols};
use proc_maps::{get_process_maps, MapRange};
use profile_bee_common::StackInfo;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error("Failed to open proc maps")]
    MapReadError { err: std::io::Error },
}
pub trait StackInfoExt {
    fn get_cmd(&self) -> String;
    fn get_cpu_id(&self) -> Option<u32>;
}

impl StackInfoExt for StackInfo {
    fn get_cmd(&self) -> String {
        str_from_u8_nul_utf8(&self.cmd).unwrap().to_owned()
    }

    fn get_cpu_id(&self) -> Option<u32> {
        if self.cpu == u32::MAX {
            return None;
        }

        Some(self.cpu)
    }
}

pub fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> core::result::Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

pub struct FrameCount {
    pub frames: Vec<StackFrameInfo>,
    pub count: u64,
}

#[derive(Default)]
pub struct SymbolFinder {
    // kernel symbols
    ksyms: BTreeMap<u64, String>,
    // TODO we should store inode, exe and starttime as a way to check staleness
    proc_map_cache: HashMap<i32, ProcessMapper>,
    obj_cache: HashMap<PathBuf, ObjItem>,
    addr_cache: HashMap<(i32, u64), StackFrameInfo>,
}

struct ObjItem {
    ctx: ObjectContext,
    symbols: Vec<Symbol>,
}

struct Symbol {
    address: u64,
    size: u64,
    name: Option<String>,
}

impl SymbolFinder {
    pub fn new() -> Self {
        // load kernel symbols from /proc/kallsyms
        let ksyms = kernel_symbols().unwrap();
        Self {
            ksyms,
            ..Default::default()
        }
    }

    /// takes an Aya StackTrace contain StackFrames into our StackFrameInfo struct
    pub fn resolve_kernel_trace(
        &self,
        trace: &mut StackTrace,
        meta: &StackInfo,
    ) -> Vec<StackFrameInfo> {
        let kernel_stack = trace
            .resolve(&self.ksyms)
            .frames()
            .iter()
            .map(|frame| {
                let mut info = StackFrameInfo::prepare(meta);
                info.symbol = frame
                    .symbol_name
                    .as_deref()
                    .map(|name| format!("{}_k", name));

                info
            })
            .collect::<Vec<_>>();
        kernel_stack
    }

    /// Attempts to get from cache, otherwise load from procfs
    pub fn cache_get_process_mapper(&mut self, pid: i32) -> Option<&ProcessMapper> {
        let found = self.proc_map_cache.contains_key(&pid);

        if !found {
            let mapper = ProcessMapper::new(pid).ok()?;
            self.proc_map_cache.insert(pid, mapper);
        } else {
        }

        self.proc_map_cache.get(&pid)
    }

    /// Resolves user space stack trace
    pub fn resolve_user_trace(
        &mut self,
        trace: &StackTrace,
        meta: &StackInfo,
    ) -> Vec<StackFrameInfo> {
        let user_stack = trace
            .frames()
            .iter()
            .map(|frame| {
                let address = frame.ip;
                let mut info = StackFrameInfo::prepare(meta);

                let mapper = self.cache_get_process_mapper(meta.tgid as _);
                if mapper.is_none() {
                    return info;
                }
                mapper.unwrap().lookup(address as _, &mut info);

                let key = (meta.tgid as _, address);
                let found = self.addr_cache.contains_key(&key);

                if found {
                    let g = self.addr_cache.get(&key).cloned().unwrap_or_default();
                    return g;
                } else {
                }

                info.resolve(address, self, meta.tgid as usize);
                self.addr_cache.insert(key, info.clone());

                // println!("User Frame: {}", info.fmt());

                info
            })
            .collect::<Vec<_>>();
        user_stack
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

/// Struct to contain information about a userspace/kernel stack frame
#[derive(Debug, Default, Clone)]
pub struct StackFrameInfo {
    pub pid: usize,
    pub cmd: String,

    /// Physical memory address
    address: u64,
    /// Shared Object / Module
    object_path: Option<PathBuf>,

    /// Source file and location
    pub symbol: Option<String>,

    /// Source file and location
    pub source: Option<String>,

    pub cpu_id: Option<u32>,
}

impl StackFrameInfo {
    /// Creates an empty/default StackFrameInfo
    pub fn prepare(meta: &StackInfo) -> Self {
        Self {
            pid: meta.tgid as usize,
            cmd: meta.get_cmd(),
            // "".to_string(), // don't really need meta.get_cmd(),
            ..Default::default()
        }
    }

    /// Creates an StackFrameInfo placeholder for process name
    pub fn process_only(meta: &StackInfo) -> Self {
        let cmd = meta.get_cmd();
        let sym = format!("{} ({})", cmd, meta.tgid);

        Self {
            pid: meta.tgid as usize,
            cmd,
            symbol: Some(sym),
            ..Default::default()
        }
    }

    pub fn new(address: u64, object_path: Option<PathBuf>) -> Self {
        Self {
            address,
            object_path,
            ..Default::default()
        }
    }

    /// Physical memory address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }

    /// Based on virtual address calculated from proc maps, resolve symbols
    pub fn resolve(&mut self, virtual_address: u64, finder: &mut SymbolFinder, id: usize) {
        if self.object_path().is_none() {
            println!(
                "[frame] [unknown] {:#16x} {} ({:#16x})",
                self.address, self.cmd, virtual_address
            );

            let r = std::fs::read_link(format!("/proc/{}/exe", id));
            if r.is_err() {
                return;
            }

            self.object_path = r.ok();
        }

        // println!("{:#x} -> obj physical address {:#x}", f.ip, info.address());
        let object_path = self.object_path().unwrap();

        let obj = {
            let find = finder.obj_cache.get(object_path);

            match find {
                Some(item) => item,
                None => {
                    let data = std::fs::read(object_path);
                    if data.is_err() {
                        println!("Can't read {:?} {:?}", object_path, data.err());
                        return;
                    }

                    let data = data.unwrap();

                    let object: addr2line::object::File<_> =
                        addr2line::object::File::parse(&data[..]).unwrap();

                    // TODO binary search tree
                    let symbols = object
                        .symbols()
                        .chain(object.dynamic_symbols())
                        .map(|s| Symbol {
                            address: s.address(),
                            size: s.size(),
                            name: s.name().map(|v| v.to_owned()).ok(),
                        })
                        .collect();

                    let ctx = ObjectContext::new(&object).unwrap();

                    let item = ObjItem { ctx, symbols };

                    finder.obj_cache.insert(PathBuf::from(object_path), item);

                    finder.obj_cache.get(object_path).unwrap()
                }
            }
        };

        let dwarf = true;

        let mut found_frames = 0;

        if dwarf {
            let mut frames = obj.ctx.find_frames(self.address()).expect("find frames");

            while let Ok(Some(frame)) = frames.next() {
                found_frames += 1;
                self.symbol = frame.function.and_then(|function_name| {
                    function_name
                        .demangle()
                        .map(|demangled_name| demangled_name.to_string())
                        .ok()
                });

                self.source = frame.location.map(|loc| {
                    format!(
                        "{}:{}:{}",
                        loc.file.unwrap_or("-"),
                        loc.line.unwrap_or(0),
                        loc.column.unwrap_or(0)
                    )
                });
            }
        }

        if found_frames > 1 {
            // TODO
            // this is due to inlining, decide how to collapse these frames
        }

        if found_frames == 0 {
            let addr2 = self.address();

            // println!("Relative {:#x}", object.relative_address_base());
            // TODO get stats on % of lookups via dwarf vs symbols

            // TODO use binary search
            for s in &obj.symbols {
                if addr2 >= s.address && addr2 < (s.address + s.size) {
                    self.symbol = s.name.as_ref().map(|v| {
                        if v.starts_with("_Z") || v.starts_with("__Z") {
                            demangle(v, gimli::DW_LANG_Rust)
                                .or_else(|| demangle(v, gimli::DW_LANG_C_plus_plus))
                                .unwrap_or_else(|| v.to_string())
                        } else {
                            v.to_owned()
                        }
                    });

                    // TODO we could attempt to get dwarf info again
                    // let offset = addr2 - s.address();
                    // let mut frames = ctx.find_frames(offset).expect("find frames");
                    // while let Ok(Some(frame)) = frames.next() {
                    //     println!("BBB Found frame...");
                    //     break;
                    // }
                }
            }
        }
    }

    pub fn fmt(&self) -> String {
        format!(
            "{:#x}\t{}\t{}\t{}",
            self.address(),
            self.cmd,
            self.fmt_object(),
            self.fmt_symbol()
        )
    }

    pub fn fmt_symbol(&self) -> String {
        format!(
            "{}{}",
            self.symbol.as_deref().unwrap_or(
                //"[unknown]"
                format!("{}+{:#x}", self.fmt_object(), self.address).as_str()
            ),
            self.fmt_source()
        )
    }

    pub fn fmt_object(&self) -> &str {
        self.object_path()
            .and_then(|v| v.file_name())
            .and_then(|v| v.to_str())
            .unwrap_or(&self.cmd)
    }

    pub fn fmt_source(&self) -> String {
        let short = self.source.as_deref().and_then(|v| {
            let s = v.split('/');
            s.last()
        });

        if short.is_some() {
            format!(" ({})", short.unwrap())
        } else {
            "".to_string()
        }
    }
}
