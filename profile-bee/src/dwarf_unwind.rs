//! DWARF-based unwind table generation
//!
//! Parses `.eh_frame` sections from ELF binaries to generate compact unwind
//! tables that can be loaded into eBPF maps for kernel-side stack unwinding
//! without requiring frame pointers.

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;

use gimli::{BaseAddresses, CfaRule, EhFrame, NativeEndian, Register, RegisterRule, UnwindSection};
use object::{Object, ObjectSection};
use procfs::process::{MMapPath, Process};
use profile_bee_common::{
    ExecMapping, ProcInfo, UnwindEntry, CFA_REG_DEREF_RSP, CFA_REG_EXPRESSION, CFA_REG_PLT,
    CFA_REG_RBP, CFA_REG_RSP, MAX_PROC_MAPS, MAX_SHARD_ENTRIES, MAX_UNWIND_SHARDS, REG_RULE_OFFSET,
    REG_RULE_SAME_VALUE, REG_RULE_UNDEFINED, SHARD_NONE,
};

/// Holds binary data either as a memory-mapped file or a heap-allocated buffer (for vdso).
/// Using mmap avoids copying the entire ELF binary into userspace heap memory,
/// eliminating page fault storms from anonymous page allocation + zeroing.
enum BinaryData {
    Mmap(Mmap),
    Vec(Vec<u8>),
}

impl std::ops::Deref for BinaryData {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            BinaryData::Mmap(m) => m,
            BinaryData::Vec(v) => v,
        }
    }
}

/// Build ID for uniquely identifying ELF binaries
pub type BuildId = Vec<u8>;

/// File metadata for cache lookups (avoids reading full binary)
/// Uses (dev, ino, size, mtime) as composite key for identifying binaries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileMetadata {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

impl FileMetadata {
    /// Extract metadata from a file path using stat()
    fn from_path(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            fs::metadata(path).map_err(|e| format!("Failed to stat {}: {}", path.display(), e))?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        })
    }
}

// x86_64 register numbers in DWARF
const X86_64_RSP: Register = Register(7);
const X86_64_RBP: Register = Register(6);
const X86_64_RA: Register = Register(16);

/// Generates a compact unwind table from an ELF binary's .eh_frame section
pub fn generate_unwind_table(
    elf_path: &Path,
) -> Result<(Vec<UnwindEntry>, Option<BuildId>), String> {
    let data =
        fs::read(elf_path).map_err(|e| format!("Failed to read {}: {}", elf_path.display(), e))?;
    generate_unwind_table_from_bytes(&data)
}

/// Generates a compact unwind table from ELF binary bytes
/// Classify a DWARF CFA expression into a known pattern.
///
/// Recognizes two common expressions found in glibc/ld-linux:
/// 1. PLT stub: `breg7(rsp)+8; breg16(rip)+0; lit15; and; lit11; ge; lit3; shl; plus`
///    → CFA = RSP + 8 + ((RIP & 15) >= 11 ? 8 : 0)
/// 2. Signal frame: `breg7(rsp)+N; deref`
///    → CFA = *(RSP + N)
fn classify_cfa_expression(
    unwind_expr: &gimli::UnwindExpression<usize>,
    eh_frame_data: &[u8],
) -> (u8, i16) {
    use gimli::Operation;

    // Extract expression bytes from the section
    let start = unwind_expr.offset;
    let end = start + unwind_expr.length;
    if end > eh_frame_data.len() {
        return (CFA_REG_EXPRESSION, 0);
    }
    let expr_bytes = &eh_frame_data[start..end];
    let expr = gimli::Expression(gimli::EndianSlice::new(expr_bytes, NativeEndian));

    let mut ops = expr.operations(gimli::Encoding {
        address_size: 8,
        format: gimli::Format::Dwarf32,
        version: 4,
    });

    // First op should be RegisterOffset { register: RSP, offset: N } (DW_OP_breg7)
    let Ok(Some(Operation::RegisterOffset {
        register, offset, ..
    })) = ops.next()
    else {
        return (CFA_REG_EXPRESSION, 0);
    };
    if register != X86_64_RSP {
        return (CFA_REG_EXPRESSION, 0);
    }
    let base_offset = offset;

    match ops.next() {
        // Signal frame: breg7(rsp)+N; deref → CFA = *(RSP + N)
        Ok(Some(Operation::Deref { .. })) => {
            let Ok(off) = i16::try_from(base_offset) else {
                return (CFA_REG_EXPRESSION, 0);
            };
            (CFA_REG_DEREF_RSP, off)
        }
        // PLT stub: breg7(rsp)+N; breg16(rip)+0; ... → CFA = RSP + N + ((RIP&15)>=11 ? 8 : 0)
        Ok(Some(Operation::RegisterOffset {
            register: reg2,
            offset: 0,
            ..
        })) if reg2 == X86_64_RA => {
            let Ok(off) = i16::try_from(base_offset) else {
                return (CFA_REG_EXPRESSION, 0);
            };
            (CFA_REG_PLT, off)
        }
        _ => (CFA_REG_EXPRESSION, 0),
    }
}

fn read_vdso(tgid: u32, start: u64, end: u64) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    if end <= start {
        return Err("Invalid vDSO address range".to_string());
    }
    let mut f = std::fs::File::open(format!("/proc/{}/mem", tgid))
        .map_err(|e| format!("Failed to open /proc/{}/mem: {}", tgid, e))?;
    f.seek(SeekFrom::Start(start))
        .map_err(|e| format!("Failed to seek to vDSO: {}", e))?;
    let len = (end - start) as usize;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read vDSO: {}", e))?;
    Ok(buf)
}

/// Extracts the GNU build ID from an ELF binary
///
/// The build ID is a unique identifier embedded in the `.note.gnu.build-id` section
/// of ELF binaries. It's typically a 20-byte SHA1 hash but can be other lengths.
/// Returns None if no build ID is found.
fn extract_build_id(data: &[u8]) -> Option<BuildId> {
    let obj = object::File::parse(data).ok()?;
    let section = obj.section_by_name(".note.gnu.build-id")?;
    let note_data = section.data().ok()?;

    // Parse ELF note format:
    // struct {
    //     u32 namesz;  // length of name (including null terminator)
    //     u32 descsz;  // length of descriptor (the actual build ID)
    //     u32 type;    // note type (3 = NT_GNU_BUILD_ID)
    //     char name[namesz];   // "GNU\0" (aligned to 4 bytes)
    //     char desc[descsz];   // the build ID bytes (aligned to 4 bytes)
    // }

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

    // Verify we have "GNU\0" name
    if namesz < 4 || note_data.len() < 12 + namesz {
        return None;
    }

    // Name is aligned to 4 bytes
    let name_aligned = (namesz + 3) & !3;
    let desc_offset = 12 + name_aligned;

    if note_data.len() < desc_offset + descsz {
        return None;
    }

    let build_id = note_data[desc_offset..desc_offset + descsz].to_vec();
    Some(build_id)
}

pub fn generate_unwind_table_from_bytes(
    data: &[u8],
) -> Result<(Vec<UnwindEntry>, Option<BuildId>), String> {
    use object::ObjectSegment;

    let obj = object::File::parse(data).map_err(|e| format!("Failed to parse ELF: {}", e))?;

    // Extract build ID first
    let build_id = extract_build_id(data);

    // Find the base virtual address (first PT_LOAD segment with file offset 0)
    // For non-PIE executables this is typically 0x400000, for PIE/shared libs it's 0.
    // We subtract this from .eh_frame PCs to make entries file-relative.
    let base_vaddr = obj
        .segments()
        .find(|s| s.file_range().0 == 0)
        .map(|s| s.address())
        .unwrap_or(0);

    let eh_frame_section = obj
        .section_by_name(".eh_frame")
        .ok_or_else(|| "No .eh_frame section found".to_string())?;

    let eh_frame_data = eh_frame_section
        .data()
        .map_err(|e| format!("Failed to read .eh_frame data: {}", e))?;

    let eh_frame_addr = eh_frame_section.address();

    let eh_frame = EhFrame::new(eh_frame_data, NativeEndian);

    let bases = BaseAddresses::default().set_eh_frame(eh_frame_addr);

    // Pre-allocate: ~1 unwind entry per 24 bytes of .eh_frame (approximate FDE size)
    let estimated_entries = eh_frame_data.len() / 24;
    let mut entries = Vec::with_capacity(estimated_entries);
    let mut ctx = gimli::UnwindContext::new();
    let mut cies = HashMap::new();

    let mut iter = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = iter.next() {
        match entry {
            gimli::CieOrFde::Cie(cie) => {
                let offset = cie.offset();
                cies.insert(offset, cie);
            }
            gimli::CieOrFde::Fde(partial_fde) => {
                let fde = match partial_fde.parse(|_, bases, offset| {
                    if let Some(cie) = cies.get(&offset.0) {
                        Ok(cie.clone())
                    } else {
                        eh_frame.cie_from_offset(bases, offset)
                    }
                }) {
                    Ok(fde) => fde,
                    Err(_) => continue,
                };

                let mut table = match fde.rows(&eh_frame, &bases, &mut ctx) {
                    Ok(table) => table,
                    Err(_) => continue,
                };

                while let Ok(Some(row)) = table.next_row() {
                    let pc = row.start_address();
                    let cfa = row.cfa();

                    let (cfa_type, cfa_offset) = match cfa {
                        CfaRule::RegisterAndOffset { register, offset } => {
                            let reg_type = if *register == X86_64_RSP {
                                CFA_REG_RSP
                            } else if *register == X86_64_RBP {
                                CFA_REG_RBP
                            } else {
                                // Unsupported register for CFA
                                continue;
                            };
                            // Skip entries with offsets that don't fit in i16
                            let Ok(offset_i16) = i16::try_from(*offset) else {
                                continue;
                            };
                            (reg_type, offset_i16)
                        }
                        CfaRule::Expression(expr) => classify_cfa_expression(expr, eh_frame_data),
                    };

                    // Skip DWARF expression-based CFA (too complex for eBPF)
                    if cfa_type == CFA_REG_EXPRESSION {
                        continue;
                    }

                    // Get return address rule — on x86_64 it's always CFA-8 for
                    // normal frames. Signal frames use expression-based rules
                    // (DW_OP_breg7+offset) which we handle specially.
                    let ra_rule = row.register(X86_64_RA);
                    let is_signal_frame = cfa_type == CFA_REG_DEREF_RSP;
                    match ra_rule {
                        RegisterRule::Offset(-8) => {}
                        // Signal frames: RA is an expression (breg7+168).
                        // We hardcode the ucontext_t offsets in eBPF.
                        RegisterRule::Expression(_) if is_signal_frame => {}
                        RegisterRule::Undefined => continue,
                        _ => continue,
                    };

                    // Get RBP rule (important for restoring frame pointer)
                    let rbp_rule = row.register(X86_64_RBP);
                    let (rbp_type, rbp_offset) = match rbp_rule {
                        RegisterRule::Offset(offset) => {
                            let Ok(offset_i16) = i16::try_from(offset) else {
                                continue;
                            };
                            (REG_RULE_OFFSET, offset_i16)
                        }
                        RegisterRule::SameValue => (REG_RULE_SAME_VALUE, 0i16),
                        RegisterRule::Undefined => (REG_RULE_UNDEFINED, 0i16),
                        _ => (REG_RULE_UNDEFINED, 0i16),
                    };

                    let relative_pc = pc - base_vaddr;
                    // Skip entries with PC > u32::MAX (shouldn't happen for
                    // file-relative addresses, but be safe)
                    let Ok(pc32) = u32::try_from(relative_pc) else {
                        continue;
                    };

                    entries.push(UnwindEntry {
                        pc: pc32,
                        cfa_offset,
                        rbp_offset,
                        cfa_type,
                        rbp_type,
                        _pad: [0; 2],
                    });
                }
            }
        }
    }

    // Sort by PC address for binary search
    entries.sort_by_key(|e| e.pc);

    // Deduplicate consecutive entries with identical unwind rules.
    // The binary search finds the last entry with pc <= target, so keeping
    // only the first entry of a run with identical rules is correct.
    let before = entries.len();
    entries.dedup_by(|b, a| {
        a.cfa_type == b.cfa_type
            && a.cfa_offset == b.cfa_offset
            && a.rbp_type == b.rbp_type
            && a.rbp_offset == b.rbp_offset
    });
    let after = entries.len();
    if before != after {
        tracing::debug!(
            "Dedup: {} -> {} entries ({:.1}% reduction)",
            before,
            after,
            (1.0 - after as f64 / before as f64) * 100.0
        );
    }

    Ok((entries, build_id))
}

/// Holds the unwind tables for all currently profiled processes
pub struct DwarfUnwindManager {
    /// Per-binary unwind tables: array of maps pattern (Vec<Vec<UnwindEntry>>)
    /// Each index represents a shard_id (0..MAX_UNWIND_SHARDS-1).
    /// Using an array instead of HashMap provides:
    /// - Faster lookups via direct indexing (O(1) vs hash computation)
    /// - Better cache locality for sequential access
    /// - Natural enforcement of MAX_UNWIND_SHARDS limit
    ///   Each Vec<UnwindEntry> is the unwind table for one binary/shard.
    pub binary_tables: Vec<Arc<Vec<UnwindEntry>>>,
    /// Per-process mapping information
    pub proc_info: HashMap<u32, ProcInfo>,
    /// Next shard_id to assign to a new binary
    next_shard_id: u16,
    /// Fast metadata-based cache for hot path lookups (stat-based)
    metadata_cache: HashMap<FileMetadata, u16>, // metadata -> shard_id
    /// Cache of parsed ELF binary shard IDs, keyed by build ID
    /// Falls back to path-based caching for binaries without build IDs
    binary_cache: HashMap<BuildId, u16>, // build_id -> shard_id
    /// Fallback cache for binaries without build IDs (keyed by path)
    path_cache: HashMap<std::path::PathBuf, u16>, // path -> shard_id
}

impl Default for DwarfUnwindManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DwarfUnwindManager {
    pub fn new() -> Self {
        Self {
            // Initialize as empty Vec with capacity for MAX_UNWIND_SHARDS
            // Using Vec instead of HashMap for the "array of maps" pattern
            binary_tables: Vec::with_capacity(MAX_UNWIND_SHARDS),
            proc_info: HashMap::new(),
            next_shard_id: 0,
            metadata_cache: HashMap::new(),
            binary_cache: HashMap::new(),
            path_cache: HashMap::new(),
        }
    }

    /// Load unwind information for a process by scanning its memory mappings.
    /// Returns Ok(()) if the process was loaded (or already loaded).
    pub fn load_process(&mut self, tgid: u32) -> Result<(), String> {
        if self.proc_info.contains_key(&tgid) {
            return Ok(());
        }
        // Wait for the dynamic linker to finish mapping shared libraries.
        // After fork+exec, /proc/PID/maps may not yet reflect all mappings.
        // Poll until the mapping count stabilizes (typically <100ms).
        let mut prev_count = 0usize;
        for _ in 0..20 {
            let count = Self::count_exec_maps(tgid);
            if count > 0 && count == prev_count {
                break;
            }
            prev_count = count;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.scan_and_update(tgid)
    }

    /// Rescan a process's memory mappings and load any new ones.
    /// Returns the list of new shard IDs added (for incremental eBPF updates).
    pub fn refresh_process(&mut self, tgid: u32) -> Result<Vec<u16>, String> {
        // Track number of shards before update
        let old_len = self.binary_tables.len();
        self.scan_and_update(tgid)?;
        // Find new shards: those added after old_len
        let new_shard_ids: Vec<u16> = (old_len as u16..self.binary_tables.len() as u16).collect();
        Ok(new_shard_ids)
    }

    /// Count executable memory mappings for a process (fast, no file I/O).
    fn count_exec_maps(tgid: u32) -> usize {
        let Ok(process) = Process::new(tgid as i32) else {
            return 0;
        };
        let Ok(maps) = process.maps() else {
            return 0;
        };
        use procfs::process::MMPermissions;
        maps.iter()
            .filter(|m| {
                m.perms.contains(MMPermissions::EXECUTE)
                    && m.perms.contains(MMPermissions::READ)
                    && matches!(m.pathname, MMapPath::Path(_) | MMapPath::Vdso)
            })
            .count()
    }

    fn scan_and_update(&mut self, tgid: u32) -> Result<(), String> {
        let process = Process::new(tgid as i32)
            .map_err(|e| format!("Failed to open process {}: {}", tgid, e))?;

        let maps = process
            .maps()
            .map_err(|e| format!("Failed to read maps for {}: {}", tgid, e))?;

        // Collect existing mapping addresses so we can skip them
        let existing = self.proc_info.get(&tgid);
        let existing_ranges: Vec<(u64, u64)> = existing
            .map(|pi| {
                (0..pi.mapping_count as usize)
                    .map(|i| (pi.mappings[i].begin, pi.mappings[i].end))
                    .collect()
            })
            .unwrap_or_default();

        let mut proc_info = existing.copied().unwrap_or(ProcInfo {
            mapping_count: 0,
            _pad: 0,
            mappings: [ExecMapping {
                begin: 0,
                end: 0,
                load_bias: 0,
                shard_id: SHARD_NONE,
                _pad1: [0; 2],
                table_count: 0,
            }; MAX_PROC_MAPS],
        });

        let root_path = format!("/proc/{}/root", tgid);

        for map in maps.iter() {
            if proc_info.mapping_count as usize >= MAX_PROC_MAPS {
                break;
            }

            let perms = &map.perms;
            use procfs::process::MMPermissions;
            if !perms.contains(MMPermissions::EXECUTE) || !perms.contains(MMPermissions::READ) {
                continue;
            }

            let file_path = match &map.pathname {
                MMapPath::Path(p) => p.to_path_buf(),
                MMapPath::Vdso => std::path::PathBuf::from("[vdso]"),
                _ => continue,
            };

            let start_addr = map.address.0;
            let end_addr = map.address.1;
            let file_offset = map.offset;
            let is_vdso = matches!(&map.pathname, MMapPath::Vdso);

            // Skip mappings we already have
            if existing_ranges
                .iter()
                .any(|&(b, e)| b == start_addr && e == end_addr)
            {
                continue;
            }

            let resolved_path = if is_vdso {
                file_path.clone()
            } else {
                let mut p = std::path::PathBuf::from(&root_path);
                p.push(file_path.strip_prefix("/").unwrap_or(&file_path));
                if p.exists() {
                    p
                } else {
                    file_path.clone()
                }
            };

            if !is_vdso && !resolved_path.exists() {
                continue;
            }

            let load_bias = start_addr.wrapping_sub(file_offset);

            // Two-tier cache lookup:
            // 1. Hot path: stat-based metadata lookup (single syscall, no file read)
            // 2. Cold path: full file read + build-ID extraction (cache miss only)
            let (shard_id, table_count) = {
                // Try fast metadata-based cache lookup first (for non-vdso files)
                let metadata_cache_hit = if !is_vdso {
                    FileMetadata::from_path(&resolved_path)
                        .ok()
                        .and_then(|meta| self.metadata_cache.get(&meta).copied())
                } else {
                    None
                };

                if let Some(sid) = metadata_cache_hit {
                    // Hot path: metadata cache hit - no file read needed!
                    // Array access pattern: check if shard_id is within bounds
                    let tc = if (sid as usize) < self.binary_tables.len() {
                        self.binary_tables[sid as usize].len() as u32
                    } else {
                        0
                    };
                    (sid, tc)
                } else {
                    // Cold path: metadata cache miss - need to read binary
                    let binary_data: Option<BinaryData> = if is_vdso {
                        read_vdso(tgid, start_addr, end_addr)
                            .ok()
                            .map(BinaryData::Vec)
                    } else {
                        File::open(&resolved_path)
                            .ok()
                            .and_then(|f| unsafe { Mmap::map(&f) }.ok())
                            .map(BinaryData::Mmap)
                    };

                    let cache_hit = if let Some(ref data) = binary_data {
                        // Try build-ID based cache lookup
                        if let Some(build_id) = extract_build_id(data) {
                            self.binary_cache.get(&build_id).copied()
                        } else {
                            // Fall back to path-based cache for binaries without build ID
                            self.path_cache.get(&resolved_path).copied()
                        }
                    } else {
                        None
                    };

                    if let Some(sid) = cache_hit {
                        // Build-ID or path cache hit - store metadata mapping for next time
                        if !is_vdso {
                            if let Ok(meta) = FileMetadata::from_path(&resolved_path) {
                                self.metadata_cache.insert(meta, sid);
                            }
                        }
                        // Array access pattern: check if shard_id is within bounds
                        let tc = if (sid as usize) < self.binary_tables.len() {
                            self.binary_tables[sid as usize].len() as u32
                        } else {
                            0
                        };
                        (sid, tc)
                    } else {
                        // Cache miss - need to parse the binary
                        let (mut unwind_entries, build_id_opt) = if let Some(data) = binary_data {
                            match generate_unwind_table_from_bytes(&data) {
                                Ok(result) => result,
                                Err(e) => {
                                    let name = if is_vdso {
                                        "[vdso]".to_string()
                                    } else {
                                        resolved_path.display().to_string()
                                    };
                                    tracing::debug!("Skipping {} for pid {}: {}", name, tgid, e);
                                    continue;
                                }
                            }
                        } else {
                            let name = if is_vdso {
                                "[vdso]".to_string()
                            } else {
                                resolved_path.display().to_string()
                            };
                            tracing::debug!("Failed to read binary {} for pid {}", name, tgid);
                            continue;
                        };

                        if unwind_entries.is_empty() {
                            continue;
                        }

                        let tc = match u32::try_from(unwind_entries.len()) {
                            Ok(v) => v,
                            Err(_) => {
                                let name = if is_vdso {
                                    "[vdso]".to_string()
                                } else {
                                    resolved_path.display().to_string()
                                };
                                tracing::warn!(
                                    "Unwind table too large for {}: {} entries",
                                    name,
                                    unwind_entries.len(),
                                );
                                continue;
                            }
                        };

                        if tc > MAX_SHARD_ENTRIES {
                            tracing::debug!(
                                "Binary unwind table very large: {} entries (max supported by binary search: {}), truncating",
                                tc,
                                MAX_SHARD_ENTRIES,
                            );
                            unwind_entries.truncate(MAX_SHARD_ENTRIES as usize);
                        }

                        let tc = unwind_entries.len() as u32;

                        if self.next_shard_id as usize >= MAX_UNWIND_SHARDS {
                            tracing::warn!(
                                "All {} shard slots used, skipping remaining binaries for pid {}",
                                MAX_UNWIND_SHARDS,
                                tgid,
                            );
                            break;
                        }

                        let sid = self.next_shard_id;
                        self.next_shard_id += 1;

                        // Array of maps pattern: push the new unwind table as a new element
                        // The index of this element will be the shard_id
                        // Invariant: next_shard_id always equals binary_tables.len() before push
                        debug_assert_eq!(sid as usize, self.binary_tables.len());
                        self.binary_tables.push(Arc::new(unwind_entries));

                        // Cache using build ID if available, otherwise use path
                        if let Some(build_id) = build_id_opt {
                            self.binary_cache.insert(build_id, sid);
                        } else {
                            self.path_cache.insert(resolved_path.clone(), sid);
                        }

                        // Also cache by metadata for fast future lookups
                        if !is_vdso {
                            if let Ok(meta) = FileMetadata::from_path(&resolved_path) {
                                self.metadata_cache.insert(meta, sid);
                            }
                        }

                        (sid, tc)
                    }
                }
            };

            let idx = proc_info.mapping_count as usize;
            proc_info.mappings[idx] = ExecMapping {
                begin: start_addr,
                end: end_addr,
                load_bias,
                shard_id,
                _pad1: [0; 2],
                table_count,
            };
            proc_info.mapping_count += 1;
        }

        self.proc_info.insert(tgid, proc_info);

        Ok(())
    }

    /// Returns the total number of table entries across all binaries
    pub fn total_entries(&self) -> usize {
        // Array of maps pattern: iterate over all elements in the Vec
        self.binary_tables.iter().map(|t| t.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unwind_table_self() {
        // Parse the current test binary's .eh_frame
        let exe = std::env::current_exe().unwrap();
        let (entries, build_id) = generate_unwind_table(&exe).unwrap();
        assert!(
            !entries.is_empty(),
            "Expected non-empty unwind table for test binary"
        );

        // Check that build ID was extracted
        assert!(build_id.is_some(), "Expected build ID for test binary");

        // Entries should be sorted by PC
        for w in entries.windows(2) {
            assert!(
                w[0].pc <= w[1].pc,
                "Unwind entries not sorted: {} > {}",
                w[0].pc,
                w[1].pc
            );
        }

        // All entries should have valid CFA types
        for entry in &entries {
            assert!(
                matches!(
                    entry.cfa_type,
                    CFA_REG_RSP | CFA_REG_RBP | CFA_REG_PLT | CFA_REG_DEREF_RSP
                ),
                "Unexpected CFA type: {}",
                entry.cfa_type
            );
            // CFA offset should be non-zero for typical x86_64 code
            // (at minimum RSP+8 for the return address push)
        }
    }

    #[test]
    fn test_generate_unwind_table_missing_file() {
        let result = generate_unwind_table(Path::new("/nonexistent/binary"));
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_unwind_table_invalid_elf() {
        let result = generate_unwind_table_from_bytes(b"not an elf file");
        assert!(result.is_err());
    }

    #[test]
    fn test_dwarf_manager_new() {
        let manager = DwarfUnwindManager::new();
        assert_eq!(manager.total_entries(), 0);
        assert!(manager.proc_info.is_empty());
    }

    #[test]
    fn test_unwind_entry_sizes() {
        // Verify the struct sizes are what we expect for eBPF compatibility
        assert_eq!(std::mem::size_of::<UnwindEntry>(), UnwindEntry::STRUCT_SIZE);
        // Should be 12 bytes (compact format)
        assert_eq!(std::mem::size_of::<UnwindEntry>(), 12);
    }

    #[test]
    fn test_unwind_table_return_address_convention() {
        // On x86_64, return address is always at CFA-8.
        // The compact format hardcodes this, so we just verify the entries
        // are generated (RA rule filtering happens during generation).
        let exe = std::env::current_exe().unwrap();
        let (entries, _) = generate_unwind_table(&exe).unwrap();
        assert!(!entries.is_empty(), "Expected non-empty unwind table");
    }

    #[test]
    fn test_load_current_process() {
        let pid = std::process::id();
        let mut manager = DwarfUnwindManager::new();
        let result = manager.load_process(pid);
        assert!(
            result.is_ok(),
            "Failed to load current process: {:?}",
            result
        );
        assert!(
            manager.total_entries() > 0,
            "Expected non-empty unwind table for current process"
        );
        assert!(
            manager.proc_info.contains_key(&pid),
            "Expected proc_info entry for current process"
        );
        let info = &manager.proc_info[&pid];
        assert!(
            info.mapping_count > 0,
            "Expected at least one executable mapping"
        );
    }

    #[test]
    fn test_libc_unwind_table() {
        // Parse libc's .eh_frame to verify we can handle shared libraries
        let libc_paths = [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
        ];

        let libc_path = libc_paths.iter().find(|p| Path::new(p).exists());
        if let Some(path) = libc_path {
            let (entries, build_id) = generate_unwind_table(Path::new(path)).unwrap();
            assert!(
                !entries.is_empty(),
                "Expected non-empty unwind table for libc"
            );
            // libc should have many unwind entries
            assert!(
                entries.len() > 100,
                "Expected >100 entries for libc, got {}",
                entries.len()
            );
            // libc should have a build ID
            assert!(build_id.is_some(), "Expected build ID for libc");
        }
    }

    #[test]
    fn test_build_id_extraction() {
        // Test that build ID extraction works on the test binary
        let exe = std::env::current_exe().unwrap();
        let data = fs::read(&exe).unwrap();
        let build_id = extract_build_id(&data);
        assert!(build_id.is_some(), "Expected build ID in test binary");

        // Build IDs are typically 20 bytes (SHA1) but can vary
        let id = build_id.unwrap();
        assert!(!id.is_empty(), "Build ID should not be empty");
        assert!(id.len() >= 8, "Build ID should be at least 8 bytes");
    }

    #[test]
    fn test_build_id_caching() {
        // Test that the same library loaded by multiple "processes" uses cached entries
        let mut manager = DwarfUnwindManager::new();
        let pid = std::process::id();

        // Load current process
        let result = manager.load_process(pid);
        assert!(result.is_ok(), "Failed to load process: {:?}", result);

        let initial_cache_size = manager.binary_cache.len() + manager.path_cache.len();
        let initial_table_size = manager.total_entries();

        assert!(initial_cache_size > 0, "Expected some cached binaries");
        assert!(initial_table_size > 0, "Expected non-empty unwind table");

        // In a real scenario with multiple processes sharing libraries,
        // we would see cache hits here. For this test, we just verify
        // the caching mechanism is set up correctly.
    }

    #[test]
    fn test_metadata_based_caching() {
        // Test that metadata cache is used for fast lookups
        let mut manager = DwarfUnwindManager::new();
        let pid = std::process::id();

        // Load current process - this should populate metadata cache
        let result = manager.load_process(pid);
        assert!(result.is_ok(), "Failed to load process: {:?}", result);

        let metadata_cache_size = manager.metadata_cache.len();
        assert!(
            metadata_cache_size > 0,
            "Expected metadata cache to be populated"
        );

        // Refresh the same process - should use metadata cache for fast lookups
        let new_shards = manager.refresh_process(pid).unwrap();

        // Since the binaries haven't changed, we shouldn't have new shards
        assert_eq!(new_shards.len(), 0, "Expected no new shards on refresh");

        // Metadata cache size should remain the same or grow slightly
        let new_metadata_cache_size = manager.metadata_cache.len();
        assert!(
            new_metadata_cache_size >= metadata_cache_size,
            "Metadata cache should not shrink"
        );
    }

    #[test]
    fn test_array_of_maps_pattern() {
        // Test that validates the "array of maps" pattern implementation
        // The binary_tables field is now Vec<Vec<UnwindEntry>> instead of HashMap<u8, Vec<UnwindEntry>>
        let mut manager = DwarfUnwindManager::new();

        // Verify initialization creates empty Vec with proper capacity
        assert_eq!(
            manager.binary_tables.len(),
            0,
            "Should start with no shards"
        );
        assert!(
            manager.binary_tables.capacity() >= MAX_UNWIND_SHARDS,
            "Should allocate capacity for at least MAX_UNWIND_SHARDS"
        );

        // Load current process to populate binary_tables
        let pid = std::process::id();
        let result = manager.load_process(pid);
        assert!(result.is_ok(), "Failed to load process: {:?}", result);

        // Verify array of maps pattern: Vec indexed by shard_id
        let num_shards = manager.binary_tables.len();
        assert!(
            num_shards > 0,
            "Expected at least one shard after loading process"
        );
        assert!(
            num_shards <= MAX_UNWIND_SHARDS,
            "Should not exceed MAX_UNWIND_SHARDS ({})",
            MAX_UNWIND_SHARDS
        );

        // Verify each shard contains unwind entries
        for (shard_id, entries) in manager.binary_tables.iter().enumerate() {
            assert!(
                !entries.is_empty(),
                "Shard {} should contain entries after loading",
                shard_id
            );

            // Verify entries are sorted by PC (required for binary search in eBPF)
            for window in entries.windows(2) {
                assert!(
                    window[0].pc <= window[1].pc,
                    "Entries in shard {} not sorted: {} > {}",
                    shard_id,
                    window[0].pc,
                    window[1].pc
                );
            }
        }

        // Test direct array access pattern (what makes this faster than HashMap)
        for shard_id in 0..manager.binary_tables.len() {
            let entries = &manager.binary_tables[shard_id];
            assert!(
                !entries.is_empty(),
                "Direct access to shard {} should work",
                shard_id
            );
        }

        // Verify total_entries uses the array iterator correctly
        let total: usize = manager.binary_tables.iter().map(|t| t.len()).sum();
        assert_eq!(
            manager.total_entries(),
            total,
            "total_entries() should match sum of all shard entry counts"
        );

        // Test refresh_process returns correct new shard IDs
        let old_len = manager.binary_tables.len();
        let new_shards = manager.refresh_process(pid).unwrap();

        // On refresh without new libraries, should have no new shards
        assert_eq!(new_shards.len(), 0, "Expected no new shards on refresh");
        assert_eq!(
            manager.binary_tables.len(),
            old_len,
            "binary_tables length should not change on refresh without new libs"
        );
    }
}
