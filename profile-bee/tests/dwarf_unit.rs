//! Integration tests for DWARF unwind table generation.
//!
//! These tests validate that the `dwarf_unwind` module can parse binaries
//! and produce sensible unwind tables for eBPF map loading.

use profile_bee::dwarf_unwind::{generate_unwind_table, DwarfUnwindManager};
use profile_bee_common::*;
use std::path::Path;

#[test]
fn test_both_parsers_handle_self_binary() {
    let exe = std::env::current_exe().unwrap();

    // dwarf_unwind.rs parser (for eBPF)
    let entries = generate_unwind_table(&exe).unwrap();
    assert!(!entries.is_empty(), "dwarf_unwind should produce entries");

    // Entries should be sorted by PC
    for w in entries.windows(2) {
        assert!(w[0].pc <= w[1].pc, "dwarf_unwind entries not sorted");
    }

    // Most entries should have CFA from RSP (x86_64 convention)
    let rsp_count = entries.iter().filter(|e| e.cfa_type == CFA_REG_RSP).count();
    assert!(
        rsp_count > entries.len() / 2,
        "Expected majority RSP-based CFA, got {}/{}",
        rsp_count,
        entries.len()
    );
}

#[test]
fn test_dwarf_manager_loads_current_process() {
    let pid = std::process::id();
    let mut manager = DwarfUnwindManager::new();
    manager.load_process(pid).unwrap();

    assert!(manager.table_size() > 0, "Should have unwind entries");
    assert!(
        manager.proc_info.contains_key(&pid),
        "Should have proc_info for current PID"
    );

    let info = &manager.proc_info[&pid];
    assert!(
        info.mapping_count > 0,
        "Should have at least one executable mapping"
    );

    // Verify mappings have valid address ranges
    for i in 0..info.mapping_count as usize {
        let m = &info.mappings[i];
        assert!(m.begin < m.end, "Mapping begin >= end");
        assert!(m.table_count > 0, "Mapping should have unwind entries");
    }
}

#[test]
fn test_unwind_entry_struct_size() {
    // eBPF requires predictable struct layout
    assert_eq!(
        std::mem::size_of::<UnwindEntry>(),
        16,
        "UnwindEntry must be 16 bytes for eBPF compatibility"
    );
}

#[test]
fn test_libc_has_unwind_info() {
    let libc_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
    ];

    let Some(path) = libc_paths.iter().find(|p| Path::new(p).exists()) else {
        eprintln!("Skipping: libc not found at known paths");
        return;
    };

    let entries = generate_unwind_table(Path::new(path)).unwrap();
    assert!(
        entries.len() > 100,
        "libc should have many unwind entries, got {}",
        entries.len()
    );
}

#[test]
fn dump_callstack_no_fp_entries() {
    use profile_bee::dwarf_unwind::generate_unwind_table;
    use std::path::Path;
    // Try both relative paths (depends on cargo test working dir)
    let candidates = ["tests/fixtures/bin/callstack-no-fp", "../tests/fixtures/bin/callstack-no-fp"];
    let p = candidates.iter().map(Path::new).find(|p| p.exists());
    let Some(p) = p else { eprintln!("callstack-no-fp not found, skipping"); return; };
    let entries = generate_unwind_table(p).unwrap();
    eprintln!("Total entries: {}", entries.len());
    // hot=0x400527, function_c=0x400534, function_b=0x40053b, function_a=0x400542, main=0x400549
    for e in &entries {
        if e.pc >= 0x500 && e.pc <= 0x700 {
            eprintln!("pc={:#010x} cfa_type={} cfa_off={:4} rbp_type={} rbp_off={:4}",
                e.pc, e.cfa_type, e.cfa_offset, e.rbp_type, e.rbp_offset);
        }
    }
}
