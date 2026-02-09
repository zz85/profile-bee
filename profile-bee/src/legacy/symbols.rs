use std::{
    collections::{BTreeMap, HashMap},
    fs::read_link,
    path::{Path, PathBuf},
};

use addr2line::{demangle, gimli, Loader};

use aya::{maps::stack_trace::StackTrace, util::kernel_symbols};
use profile_bee_common::StackInfo;
use thiserror::Error;

use crate::cache::{AddrCache, ProcessCache};

/// Build ID for uniquely identifying ELF binaries
pub type BuildId = Vec<u8>;

/// Extracts the GNU build ID from an ELF binary file
fn extract_build_id_from_file(path: &Path) -> Option<BuildId> {
    let data = std::fs::read(path).ok()?;
    extract_build_id(&data)
}

/// Extracts the GNU build ID from an ELF binary in memory
fn extract_build_id(data: &[u8]) -> Option<BuildId> {
    use object::{Object, ObjectSection};

    let obj = object::File::parse(data).ok()?;
    let section = obj.section_by_name(".note.gnu.build-id")?;
    let note_data = section.data().ok()?;

    if note_data.len() < 16 {
        return None;
    }

    let namesz =
        u32::from_ne_bytes([note_data[0], note_data[1], note_data[2], note_data[3]]) as usize;
    let descsz =
        u32::from_ne_bytes([note_data[4], note_data[5], note_data[6], note_data[7]]) as usize;
    let note_type = u32::from_ne_bytes([note_data[8], note_data[9], note_data[10], note_data[11]]);

    // NT_GNU_BUILD_ID = 3
    if note_type != 3 {
        return None;
    }

    if namesz < 4 || note_data.len() < 12 + namesz {
        return None;
    }

    let name_aligned = (namesz + 3) & !3;
    let desc_offset = 12 + name_aligned;

    if note_data.len() < desc_offset + descsz {
        return None;
    }

    let build_id = note_data[desc_offset..desc_offset + descsz].to_vec();
    Some(build_id)
}

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

/// Symbol finder and resolver for stack traces
///
/// Handles resolving memory addresses to human-readable symbols and source locations
/// using kernel symbols, debug information, and binary analysis.
/// Maintains caches to improve performance for repeated lookups.
#[derive(Default)]
pub struct SymbolFinder {
    // kernel symbols
    ksyms: BTreeMap<u64, String>,
    // Build-ID based cache for object files (preferred)
    obj_cache: HashMap<BuildId, Option<ObjItem>>,
    // Fallback cache for binaries without build IDs (keyed by namespace + path)
    obj_path_cache: HashMap<(u64, PathBuf), Option<ObjItem>>,
    pub addr_cache: AddrCache,
    pub process_cache: ProcessCache,
}

pub struct ObjItem {
    ctx: Option<Loader>,
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
        trace: &StackTrace,
        meta: &StackInfo,
    ) -> Vec<StackFrameInfo> {
        let kernel_stack = trace
            .frames()
            .iter()
            .map(|frame| {
                let mut info = StackFrameInfo::prepare(meta);
                if let Some(sym) = self.ksyms.range(..=frame.ip).next_back().map(|(_, s)| s) {
                    info.symbol = Some(format!("{sym}_[k]"));
                    // println!("{:#x} {}", frame.ip, sym);
                } else {
                    // println!("{:#x}", frame.ip);
                }

                info
            })
            .collect::<Vec<_>>();
        kernel_stack
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
                // instruction pointer
                let address = frame.ip;

                if let Some(info) = self.addr_cache.get(meta.tgid as _, address) {
                    return info;
                }

                let mut info = StackFrameInfo::prepare(meta);

                let process = self.process_cache.get(meta.tgid as usize);
                if process.is_none() {
                    println!("Empty process cache entry shouldn't happen");
                    return info;
                }

                let mapper = &process.unwrap().mapper;
                if mapper.is_none() {
                    return info;
                }
                mapper.as_ref().unwrap().lookup(address as _, &mut info);

                info.resolve(address, self, meta.tgid as _);

                self.addr_cache.insert(meta.tgid as _, address, &info);

                info
            })
            .collect::<Vec<_>>();
        user_stack
    }

    pub fn resolve_stack_trace(
        &mut self,
        kernel_stack: Option<StackTrace>,
        user_stack: Option<StackTrace>,
        meta: &StackInfo,
    ) -> Vec<StackFrameInfo> {
        let kernel_stacks = kernel_stack.map(|trace| self.resolve_kernel_trace(&trace, meta));
        let user_stacks = user_stack.map(|trace| self.resolve_user_trace(&trace, meta));

        let combined = match (kernel_stacks, user_stacks) {
            (Some(kernel_stacks), None) => kernel_stacks,
            (None, Some(user_stacks)) => user_stacks,
            (Some(kernel_stacks), Some(user_stacks)) => kernel_stacks
                .into_iter()
                .chain(user_stacks.into_iter())
                .collect::<Vec<_>>(),
            _ => Default::default(),
        };
        combined
    }
}

/// Struct to contain information about a userspace/kernel stack frame
///
/// Represents a single frame in a stack trace with information about its
/// memory address, associated binary, symbol name, and source location.
/// Used for generating human-readable stack traces in flamegraphs.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct StackFrameInfo {
    pub pid: usize,
    pub cmd: String,

    /// Physical memory address
    pub address: u64,
    /// Shared Object / Module
    pub object_path: Option<PathBuf>,

    /// Source file and location
    pub symbol: Option<String>,

    /// Source file and location
    pub source: Option<String>,

    pub cpu_id: Option<u32>,

    /// namespace
    pub ns: Option<u64>,
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
        let with_pid = false;

        let sym = if with_pid {
            format!("{} ({})", cmd, meta.tgid)
        } else {
            cmd.to_owned()
        };

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
            // println!(
            //     "[frame] [unknown] {:#16x} {} ({:#16x})",
            //     self.address, self.cmd, virtual_address
            // );

            let path = finder
                .process_cache
                .get(id)
                .and_then(|p| p.exe_link.as_ref());

            if path.is_none() {
                // uhoh, this means link isn't there, but there might be a way to
                // read the process in memory
                return;
            }

            self.object_path = path.map(ToOwned::to_owned);
        }

        // println!("{:#x} -> obj physical address {:#x}", f.ip, info.address());
        let object_path = self.object_path().unwrap();

        // Build the full target path first
        let path = object_path.to_str().unwrap_or_default();
        if path == "[vdso]" || path.starts_with('[') {
            // Skip special mappings like vdso
            return;
        }

        // try best if meet a deleted dso
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);

        let root_link = format!("/proc/{}/root", id);
        let base = Path::new(&root_link);
        let mut target = match read_link(&base) {
            Ok(link) => link,
            Err(_e) => {
                // Best attempt, use root
                PathBuf::new()
            }
        };

        target.push(path);

        // Try to get build ID and use it for caching
        let build_id = extract_build_id_from_file(&target);

        // Look up in cache: prefer build-ID based cache, fall back to path-based
        let obj_cache = if let Some(bid) = build_id {
            finder.obj_cache.entry(bid).or_insert_with(|| {
                let loader = match Loader::new(&target) {
                    Err(e) => {
                        println!("Error while loading target {target:?} : {e:?}");
                        return None;
                    }
                    Ok(loader) => loader,
                };

                Some(ObjItem {
                    ctx: Some(loader),
                    symbols: vec![],
                })
            })
        } else {
            // Fall back to path-based cache for binaries without build IDs
            let object_key = (self.ns.unwrap_or(self.pid as u64), object_path.into());
            finder.obj_path_cache.entry(object_key).or_insert_with(|| {
                let loader = match Loader::new(&target) {
                    Err(e) => {
                        println!("Error while loading target {target:?} : {e:?}");
                        return None;
                    }
                    Ok(loader) => loader,
                };

                Some(ObjItem {
                    ctx: Some(loader),
                    symbols: vec![],
                })
            })
        };

        let obj = match obj_cache {
            Some(obj) => obj,
            None => {
                // because this failed to load before, it's been negatively cached
                return;
            }
        };

        let mut found_frames = 0;

        if obj.ctx.is_some() {
            let mut frames = obj
                .ctx
                .as_ref()
                .unwrap()
                .find_frames(self.address())
                .expect("find frames");

            while let Ok(Some(frame)) = frames.next() {
                found_frames += 1;

                let loc = frame.location.map(|loc| {
                    format!(
                        "{}:{}:{}",
                        loc.file.unwrap_or("-"),
                        loc.line.unwrap_or(0),
                        loc.column.unwrap_or(0)
                    )
                });

                if let Some(source) = &mut self.source {
                    source.insert(0, ';');
                    source.insert_str(0, &loc.unwrap_or_default())
                } else {
                    self.source = loc;
                }

                let sym = frame.function.and_then(|function_name| {
                    function_name
                        .demangle()
                        .map(|demangled_name| demangled_name.to_string())
                        .map(remove_generics)
                        .ok()
                });

                if let Some(symbol) = &mut self.symbol {
                    symbol.insert(0, ';');
                    symbol.insert_str(0, &sym.unwrap_or_default())
                } else {
                    self.symbol = sym;
                }
            }
        }

        if found_frames > 1 {
            // Inlined frames were found
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

    fn fmt_shorter_source(&self, count: usize) -> Option<String> {
        StackFrameInfo::fmt_shorter(self.source.as_deref(), count)
    }

    /// instead of bla/meh/mah/test.c
    /// returns mah/test.c for example
    fn fmt_shorter(op: Option<&str>, count: usize) -> Option<String> {
        op.map(|v| {
            v.split('/')
                .rev()
                .take(count)
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .into_iter()
                .rev()
                .collect::<Vec<String>>()
                .join("/")
        })
    }

    pub fn fmt_source(&self) -> String {
        // let short = self.source.as_deref();
        // .and_then(|v| {
        //     let s = v.split('/');
        //     s.last()
        // });

        let short = self.fmt_shorter_source(4);

        if short.is_some() {
            format!(" ({})", short.unwrap())
        } else {
            "".to_string()
        }
    }
}

fn remove_generics(mut func: String) -> String {
    func = func.replace(';', ":");
    let mut bracket_depth = 0;

    let mut new_str = String::with_capacity(func.len());
    let mut continous_seperator = 0;
    let mut running = false;

    for (_idx, c) in func.char_indices() {
        match c {
            '<' => {
                bracket_depth += 1;
            }
            '>' => {
                bracket_depth -= 1;
            }
            ':' => {
                if bracket_depth > 0 {
                    continue;
                }

                continous_seperator += 1;

                if continous_seperator <= 2 && running {
                    new_str.push(c);
                }
            }
            _ => {
                if bracket_depth > 0 {
                    continue;
                }
                continous_seperator = 0;
                new_str.push(c);
                running = true;
            }
        };
    }

    new_str
}

#[test]
fn test_clean() {
    let tests = [
        "<<lock_api::rwlock::RwLock<R,T> as core::fmt::Debug>::fmt::LockedPlaceholder as core::fmt::Debug>::fmt",
        "core::array::<impl core::ops::index::IndexMut<I> for [T: N]>::index_mut",
        "alloc::collections::btree::search::<impl alloc::collections::btree::node::NodeRef<BorrowType,K,V,alloc::collections::btree::node::marker::LeafOrInternal>>::search_tree",
        "alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<BorrowType,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::descend",
        "alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Immut,K,V,Type>::keys",
        "core::ptr::drop_in_place<gimli::read::line::LineInstruction<gimli::read::endian_reader::EndianReader<gimli::endianity::RunTimeEndian,alloc::rc::Rc<[u8]>>,usize>>",
        "<core::iter::adapters::enumerate::Enumerate<I> as core::iter::traits::iterator::Iterator>::next",
    ];

    let expected = [
        "fmt",
        "core::array::index_mut",
        "alloc::collections::btree::search::search_tree",
        "alloc::collections::btree::node::Handle::descend",
        "alloc::collections::btree::node::NodeRef::keys",
        "core::ptr::drop_in_place",
        "next",
    ];

    for no in 0..tests.len() {
        assert_eq!(remove_generics(tests[no].to_string()), expected[no]);
    }
}
