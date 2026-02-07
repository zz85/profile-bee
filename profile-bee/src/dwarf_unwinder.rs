use framehop::{CacheNative, MayAllocateDuringUnwind, Module, UnwindRegsNative};
use framehop::{ModuleSectionInfo, Unwinder, UnwinderNative};
use object::{Object, ObjectSection, ObjectSegment};
use procfs::process::{MMPermissions, MMapPath, Process};
use profile_bee_common::{FramePointers, StackInfo};
use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

const STACK_WORD_BYTES: u64 = core::mem::size_of::<u64>() as u64;
const PROC_ROOT: &str = "/proc";

pub struct DwarfUnwinder {
    processes: HashMap<u32, ProcessUnwinder>,
}

impl DwarfUnwinder {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn unwind_stack(
        &mut self,
        stack_info: &StackInfo,
        pointers: &FramePointers,
    ) -> Option<Vec<u64>> {
        if stack_info.tgid == 0 {
            // Kernel threads do not have user stacks to unwind.
            return None;
        }

        let stack_len = pointers.len;
        if stack_len == 0 || pointers.stack_pointer == 0 {
            return None;
        }
        let unwinder = self.get_or_insert_process(stack_info.tgid)?;
        let stack_start = pointers.stack_pointer;
        let stack_bytes = (stack_len as u64).checked_mul(STACK_WORD_BYTES)?;
        let stack_end = stack_start.checked_add(stack_bytes)?;
        let stack_words = &pointers.pointers[..stack_len];

        let mut read_stack = |addr: u64| -> Result<u64, ()> {
            if addr < stack_start || addr + STACK_WORD_BYTES > stack_end {
                return Err(());
            }

            let index = ((addr - stack_start) / STACK_WORD_BYTES) as usize;
            stack_words.get(index).copied().ok_or(())
        };

        let regs = UnwindRegsNative::new(
            stack_info.ip, // instruction pointer
            stack_start,   // stack pointer
            stack_info.bp, // base pointer
        );
        let mut iter = unwinder.unwinder.iter_frames(
            stack_info.ip,
            regs,
            &mut unwinder.cache,
            &mut read_stack,
        );

        let mut frames = Vec::new();
        loop {
            match iter.next() {
                Ok(Some(frame)) => frames.push(frame.address()),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        if frames.is_empty() {
            None
        } else {
            Some(frames)
        }
    }

    fn get_or_insert_process(&mut self, pid: u32) -> Option<&mut ProcessUnwinder> {
        if !self.processes.contains_key(&pid) {
            let unwinder = ProcessUnwinder::new(pid)?;
            self.processes.insert(pid, unwinder);
        }

        self.processes.get_mut(&pid)
    }
}

struct ProcessUnwinder {
    unwinder: UnwinderNative<Vec<u8>, MayAllocateDuringUnwind>,
    cache: CacheNative<MayAllocateDuringUnwind>,
}

impl ProcessUnwinder {
    fn new(pid: u32) -> Option<Self> {
        let modules = load_modules(pid)?;
        let mut unwinder = UnwinderNative::new();
        for module in modules {
            unwinder.add_module(module);
        }

        Some(Self {
            unwinder,
            cache: CacheNative::new(),
        })
    }
}

fn load_modules(pid: u32) -> Option<Vec<Module<Vec<u8>>>> {
    let process = Process::new(pid as i32).ok()?;
    let maps = process.maps().ok()?;
    let mut modules = Vec::new();

    for map in maps.iter() {
        if !is_executable(map) {
            continue;
        }

        let path = match &map.pathname {
            MMapPath::Path(path) => path,
            _ => continue,
        };

        if path.to_string_lossy().starts_with('[') {
            continue;
        }

        if let Some(module) = load_module(pid, path, map) {
            modules.push(module);
        }
    }

    if modules.is_empty() {
        None
    } else {
        Some(modules)
    }
}

fn is_executable(map: &procfs::process::MemoryMap) -> bool {
    let perms = map.perms;
    perms.contains(MMPermissions::EXECUTE)
        && perms.contains(MMPermissions::READ)
        && !perms.contains(MMPermissions::WRITE)
}

fn load_module(
    pid: u32,
    path: &PathBuf,
    map: &procfs::process::MemoryMap,
) -> Option<Module<Vec<u8>>> {
    let path = strip_deleted_suffix(path)?;
    let data = read_module_bytes(pid, path.as_path())?;
    let file = object::File::parse(&*data).ok()?;
    let base_svma = base_svma_from_segments(&file);
    let base_avma = compute_base_avma(&file, base_svma, map)?;
    let section_info = ElfModuleSectionInfo::from_object(&file, base_svma);

    Some(Module::new(
        path.to_string_lossy().into_owned(),
        map.address.0..map.address.1,
        base_avma,
        section_info,
    ))
}

fn strip_deleted_suffix(path: &Path) -> Option<PathBuf> {
    let path_str = path.to_string_lossy();
    let trimmed = path_str.strip_suffix(" (deleted)").unwrap_or(&path_str);
    Some(PathBuf::from(trimmed))
}

fn read_module_bytes(pid: u32, path: &Path) -> Option<Vec<u8>> {
    if let Ok(data) = fs::read(path) {
        return Some(data);
    }

    let root = Path::new(PROC_ROOT).join(pid.to_string()).join("root");
    let relative = path.strip_prefix(Path::new("/")).unwrap_or(path);
    fs::read(root.join(relative)).ok()
}

fn base_svma_from_segments(file: &object::File<'_>) -> u64 {
    file.segments()
        .map(|segment| segment.address())
        .min()
        .unwrap_or(0)
}

fn compute_base_avma(
    file: &object::File<'_>,
    base_svma: u64,
    map: &procfs::process::MemoryMap,
) -> Option<u64> {
    let map_start = map.address.0;
    let map_offset = map.offset;

    for segment in file.segments() {
        let (offset, size) = segment.file_range();
        if map_offset >= offset && map_offset < offset + size {
            let seg_svma = segment.address();
            let svma_offset = seg_svma.checked_sub(base_svma)?;
            return map_start.checked_sub(svma_offset);
        }
    }

    map_start.checked_sub(map_offset)
}

struct SectionSnapshot {
    range: Range<u64>,
    data: Option<Vec<u8>>,
}

struct ElfModuleSectionInfo {
    base_svma: u64,
    eh_frame: Option<SectionSnapshot>,
    eh_frame_hdr: Option<SectionSnapshot>,
    debug_frame: Option<SectionSnapshot>,
    text: Option<SectionSnapshot>,
}

impl ElfModuleSectionInfo {
    fn from_object(file: &object::File<'_>, base_svma: u64) -> Self {
        let eh_frame = section_snapshot(file, ".eh_frame");
        let eh_frame_hdr = section_snapshot(file, ".eh_frame_hdr");
        let debug_frame = section_snapshot(file, ".debug_frame");
        let text = section_snapshot(file, ".text");

        Self {
            base_svma,
            eh_frame,
            eh_frame_hdr,
            debug_frame,
            text,
        }
    }
}

impl ModuleSectionInfo<Vec<u8>> for ElfModuleSectionInfo {
    fn base_svma(&self) -> u64 {
        self.base_svma
    }

    fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
        match name {
            b".eh_frame" | b"__eh_frame" => {
                self.eh_frame.as_ref().map(|section| section.range.clone())
            }
            b".eh_frame_hdr" | b"__eh_frame_hdr" => self
                .eh_frame_hdr
                .as_ref()
                .map(|section| section.range.clone()),
            b".debug_frame" | b"__debug_frame" => self
                .debug_frame
                .as_ref()
                .map(|section| section.range.clone()),
            b".text" | b"__text" => self.text.as_ref().map(|section| section.range.clone()),
            _ => None,
        }
    }

    fn section_data(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        match name {
            b".eh_frame" | b"__eh_frame" => self.eh_frame.as_mut()?.data.take(),
            b".eh_frame_hdr" | b"__eh_frame_hdr" => self.eh_frame_hdr.as_mut()?.data.take(),
            b".debug_frame" | b"__debug_frame" => self.debug_frame.as_mut()?.data.take(),
            b".text" | b"__text" => self.text.as_mut()?.data.take(),
            _ => None,
        }
    }
}

fn section_snapshot(file: &object::File<'_>, name: &str) -> Option<SectionSnapshot> {
    let section = file.section_by_name(name)?;
    let start = section.address();
    let size = section.size();
    let data = section.data().ok()?.to_vec();
    Some(SectionSnapshot {
        range: start..start + size,
        data: Some(data),
    })
}
