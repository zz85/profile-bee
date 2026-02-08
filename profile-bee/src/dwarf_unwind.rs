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
    CFA_REG_EXPRESSION, CFA_REG_RBP, CFA_REG_RSP,
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
pub fn generate_unwind_table_from_bytes(data: &[u8]) -> Result<Vec<UnwindEntry>, String> {
    let obj = object::File::parse(data)
        .map_err(|e| format!("Failed to parse ELF: {}", e))?;

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
                            // Skip entries with offsets that don't fit in i32
                            let Ok(offset_i32) = i32::try_from(*offset) else {
                                continue;
                            };
                            (reg_type, offset_i32)
                        }
                        CfaRule::Expression(_) => {
                            (CFA_REG_EXPRESSION, 0)
                        }
                    };

                    // Skip DWARF expression-based CFA (too complex for eBPF)
                    if cfa_type == CFA_REG_EXPRESSION {
                        continue;
                    }

                    // Get return address rule
                    let ra_rule = row.register(X86_64_RA);
                    let (ra_type, ra_offset) = match ra_rule {
                        RegisterRule::Offset(offset) => {
                            let Ok(offset_i32) = i32::try_from(offset) else {
                                continue;
                            };
                            (REG_RULE_OFFSET, offset_i32)
                        }
                        RegisterRule::SameValue => (REG_RULE_SAME_VALUE, 0),
                        RegisterRule::Undefined => (REG_RULE_UNDEFINED, 0),
                        _ => continue, // Skip complex rules
                    };

                    // Get RBP rule (important for restoring frame pointer)
                    let rbp_rule = row.register(X86_64_RBP);
                    let (rbp_type, rbp_offset) = match rbp_rule {
                        RegisterRule::Offset(offset) => {
                            let Ok(offset_i32) = i32::try_from(offset) else {
                                continue;
                            };
                            (REG_RULE_OFFSET, offset_i32)
                        }
                        RegisterRule::SameValue => (REG_RULE_SAME_VALUE, 0),
                        RegisterRule::Undefined => (REG_RULE_UNDEFINED, 0),
                        _ => (REG_RULE_UNDEFINED, 0),
                    };

                    entries.push(UnwindEntry {
                        pc,
                        cfa_type,
                        _pad1: [0; 3],
                        cfa_offset,
                        ra_type,
                        _pad2: [0; 3],
                        ra_offset,
                        rbp_type,
                        _pad3: [0; 3],
                        rbp_offset,
                    });
                }
            }
        }
    }

    // Sort by PC address for binary search
    entries.sort_by_key(|e| e.pc);

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
                MMapPath::Path(p) => p,
                _ => continue,
            };

            // Construct the actual path (may be in a container namespace)
            let resolved_path = {
                let mut p = std::path::PathBuf::from(&root_path);
                p.push(file_path.strip_prefix("/").unwrap_or(file_path));
                if p.exists() {
                    p
                } else {
                    file_path.to_path_buf()
                }
            };

            if !resolved_path.exists() {
                continue;
            }

            let start_addr = map.address.0;
            let end_addr = map.address.1;
            let file_offset = map.offset;

            // Calculate load bias (use wrapping to handle edge cases)
            let load_bias = start_addr.wrapping_sub(file_offset);

            // Check if we've already parsed this binary
            let (table_start, table_count) = if let Some(&(ts, tc)) = self.binary_cache.get(&resolved_path) {
                (ts, tc)
            } else {
                // Generate unwind table for this binary
                let unwind_entries = match generate_unwind_table(&resolved_path) {
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
                entry.cfa_type == CFA_REG_RSP || entry.cfa_type == CFA_REG_RBP,
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
        // Should be 32 bytes
        assert_eq!(std::mem::size_of::<UnwindEntry>(), 32);
    }

    #[test]
    fn test_unwind_table_return_address_rules() {
        // Parse the current test binary and verify return address rules are sensible
        let exe = std::env::current_exe().unwrap();
        let entries = generate_unwind_table(&exe).unwrap();

        let mut offset_count = 0;
        for entry in &entries {
            if entry.ra_type == REG_RULE_OFFSET {
                offset_count += 1;
                // For x86_64, return address is typically at CFA-8
                assert_eq!(
                    entry.ra_offset, -8,
                    "Return address offset should be -8 for x86_64, got {}",
                    entry.ra_offset
                );
            }
        }
        assert!(
            offset_count > 0,
            "Expected at least some entries with CFA-relative return address"
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
