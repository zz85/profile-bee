//! DWARF-based unwind table generation
//!
//! Parses `.eh_frame` sections from ELF binaries to generate compact unwind
//! tables that can be loaded into eBPF maps for kernel-side stack unwinding
//! without requiring frame pointers.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use gimli::{
    BaseAddresses, CfaRule, EhFrame, NativeEndian, Register, RegisterRule,
    UnwindSection,
};
use object::{Object, ObjectSection};
use profile_bee_common::{
    UnwindEntry, ExecMapping, ProcInfo,
    CFA_REG_EXPRESSION, CFA_REG_RBP, CFA_REG_RSP, CFA_REG_PLT, CFA_REG_DEREF_RSP,
    REG_RULE_OFFSET, REG_RULE_SAME_VALUE, REG_RULE_UNDEFINED,
    MAX_PROC_MAPS, MAX_UNWIND_TABLE_SIZE,
};
use procfs::process::{MMapPath, Process};

// x86_64 register numbers in DWARF
const X86_64_RSP: Register = Register(7);
const X86_64_RBP: Register = Register(6);
const X86_64_RA: Register = Register(16);

/// Generates a compact unwind table from an ELF binary's .eh_frame section
pub fn generate_unwind_table(elf_path: &Path) -> Result<Vec<UnwindEntry>, String> {
    let data = fs::read(elf_path).map_err(|e| format!("Failed to read {}: {}", elf_path.display(), e))?;
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
    let Ok(Some(Operation::RegisterOffset { register, offset, .. })) = ops.next() else {
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
        Ok(Some(Operation::RegisterOffset { register: reg2, offset: 0, .. })) if reg2 == X86_64_RA => {
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

pub fn generate_unwind_table_from_bytes(data: &[u8]) -> Result<Vec<UnwindEntry>, String> {
    use object::ObjectSegment;

    let obj = object::File::parse(data)
        .map_err(|e| format!("Failed to parse ELF: {}", e))?;

    // Find the base virtual address (first PT_LOAD segment with file offset 0)
    // For non-PIE executables this is typically 0x400000, for PIE/shared libs it's 0.
    // We subtract this from .eh_frame PCs to make entries file-relative.
    let base_vaddr = obj.segments()
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

    let bases = BaseAddresses::default()
        .set_eh_frame(eh_frame_addr);

    let mut entries = Vec::new();
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
                        CfaRule::Expression(expr) => {
                            classify_cfa_expression(expr, eh_frame_data)
                        }
                    };

                    // Skip DWARF expression-based CFA (too complex for eBPF)
                    if cfa_type == CFA_REG_EXPRESSION {
                        continue;
                    }

                    // Get return address rule — on x86_64 it's always CFA-8.
                    // Skip entries where RA is not a simple CFA offset of -8.
                    let ra_rule = row.register(X86_64_RA);
                    match ra_rule {
                        RegisterRule::Offset(offset) if offset == -8 => {}
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
                        cfa_offset: cfa_offset as i16,
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
            before, after, (1.0 - after as f64 / before as f64) * 100.0
        );
    }

    Ok(entries)
}

/// Holds the unwind tables for all currently profiled processes
pub struct DwarfUnwindManager {
    /// Global unwind table (shared eBPF array)
    pub global_table: Vec<UnwindEntry>,
    /// Per-process mapping information
    pub proc_info: HashMap<u32, ProcInfo>,
    /// Next free index in the global unwind table
    next_table_index: u32,
    /// Cache of parsed ELF binary unwind entries, keyed by resolved path
    binary_cache: HashMap<std::path::PathBuf, (u32, u32)>, // (table_start, table_count)
}

impl DwarfUnwindManager {
    pub fn new() -> Self {
        Self {
            global_table: Vec::new(),
            proc_info: HashMap::new(),
            next_table_index: 0,
            binary_cache: HashMap::new(),
        }
    }

    /// Load unwind information for a process by scanning its memory mappings
    pub fn load_process(&mut self, tgid: u32) -> Result<(), String> {
        if self.proc_info.contains_key(&tgid) {
            return Ok(());
        }

        let process = Process::new(tgid as i32)
            .map_err(|e| format!("Failed to open process {}: {}", tgid, e))?;

        let maps = process
            .maps()
            .map_err(|e| format!("Failed to read maps for {}: {}", tgid, e))?;

        let mut proc_info = ProcInfo {
            mapping_count: 0,
            _pad: 0,
            mappings: [ExecMapping {
                begin: 0,
                end: 0,
                load_bias: 0,
                table_start: 0,
                table_count: 0,
            }; MAX_PROC_MAPS],
        };

        let root_path = format!("/proc/{}/root", tgid);

        for map in maps.iter() {
            if proc_info.mapping_count as usize >= MAX_PROC_MAPS {
                break;
            }

            // Only process executable mappings that map to files
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

            // Construct the actual path (may be in a container namespace)
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

            // Calculate load bias (use wrapping to handle edge cases)
            let load_bias = start_addr.wrapping_sub(file_offset);

            // Check if we've already parsed this binary
            let (table_start, table_count) = if let Some(&(ts, tc)) = self.binary_cache.get(&resolved_path) {
                (ts, tc)
            } else {
                // Generate unwind table for this binary
                let unwind_entries = if is_vdso {
                    // Read vDSO from process memory
                    match read_vdso(tgid, start_addr, end_addr) {
                        Ok(data) => match generate_unwind_table_from_bytes(&data) {
                            Ok(entries) => entries,
                            Err(e) => {
                                tracing::debug!("Skipping [vdso] for pid {}: {}", tgid, e);
                                continue;
                            }
                        },
                        Err(e) => {
                            tracing::debug!("Skipping [vdso] for pid {}: {}", tgid, e);
                            continue;
                        }
                    }
                } else {
                    match generate_unwind_table(&resolved_path) {
                        Ok(entries) => entries,
                        Err(e) => {
                            tracing::debug!(
                                "Skipping {} for pid {}: {}",
                                resolved_path.display(),
                                tgid,
                                e
                            );
                            continue;
                        }
                    }
                };

                if unwind_entries.is_empty() {
                    continue;
                }

                let ts = self.next_table_index;
                let tc = match u32::try_from(unwind_entries.len()) {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(
                            "Unwind table too large for {}: {} entries",
                            resolved_path.display(),
                            unwind_entries.len(),
                        );
                        continue;
                    }
                };

                if self.next_table_index + tc > MAX_UNWIND_TABLE_SIZE {
                    tracing::warn!(
                        "Global unwind table full ({}/{} entries used), skipping remaining mappings for pid {}",
                        self.next_table_index, MAX_UNWIND_TABLE_SIZE, tgid,
                    );
                    break;
                }

                self.global_table.extend_from_slice(&unwind_entries);
                self.next_table_index += tc;

                self.binary_cache.insert(resolved_path.clone(), (ts, tc));

                (ts, tc)
            };

            let idx = proc_info.mapping_count as usize;
            proc_info.mappings[idx] = ExecMapping {
                begin: start_addr,
                end: end_addr,
                load_bias,
                table_start,
                table_count,
            };
            proc_info.mapping_count += 1;
        }

        self.proc_info.insert(tgid, proc_info);

        Ok(())
    }

    /// Returns the current total number of entries in the global table
    pub fn table_size(&self) -> usize {
        self.global_table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unwind_table_self() {
        // Parse the current test binary's .eh_frame
        let exe = std::env::current_exe().unwrap();
        let entries = generate_unwind_table(&exe).unwrap();
        assert!(
            !entries.is_empty(),
            "Expected non-empty unwind table for test binary"
        );

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
                matches!(entry.cfa_type, CFA_REG_RSP | CFA_REG_RBP | CFA_REG_PLT | CFA_REG_DEREF_RSP),
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
        assert_eq!(manager.table_size(), 0);
        assert!(manager.proc_info.is_empty());
    }

    #[test]
    fn test_unwind_entry_sizes() {
        // Verify the struct sizes are what we expect for eBPF compatibility
        assert_eq!(
            std::mem::size_of::<UnwindEntry>(),
            UnwindEntry::STRUCT_SIZE
        );
        // Should be 12 bytes (compact format)
        assert_eq!(std::mem::size_of::<UnwindEntry>(), 12);
    }

    #[test]
    fn test_unwind_table_return_address_convention() {
        // On x86_64, return address is always at CFA-8.
        // The compact format hardcodes this, so we just verify the entries
        // are generated (RA rule filtering happens during generation).
        let exe = std::env::current_exe().unwrap();
        let entries = generate_unwind_table(&exe).unwrap();
        assert!(
            !entries.is_empty(),
            "Expected non-empty unwind table"
        );
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
            manager.table_size() > 0,
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
            let entries = generate_unwind_table(Path::new(path)).unwrap();
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
        }
    }
}
