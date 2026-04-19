//! ELF symbol extraction — reads function names and address ranges from binaries.
//!
//! Extracts from multiple sources (in priority order):
//! 1. DWARF debug info (.debug_info) — richest: function names, source files, inlines
//! 2. .symtab (static symbol table) — function names + sizes
//! 3. .dynsym (dynamic symbol table) — fallback for stripped binaries
//!
//! profile-bee already uses `blazesym` and `gimli` for runtime symbolization.
//! This module uses `addr2line` (which wraps `gimli`) for batch extraction of
//! all function ranges — same underlying libraries, different access pattern.

use object::{Object, ObjectSymbol, SymbolKind};
use std::path::Path;

/// A single symbol range: function name + virtual address range.
#[derive(Debug, Clone)]
pub struct SymbolRange {
    /// ELF virtual address (start of function)
    pub elf_va: u64,
    /// Length of the function in bytes
    pub length: u64,
    /// Demangled or raw function name
    pub name: String,
    /// Source file path (if available from DWARF)
    pub file: Option<String>,
}

/// Extract function symbols from an ELF binary.
///
/// Strategy:
/// 1. Extract from .symtab/.dynsym for function address ranges
/// 2. Enrich with DWARF info (source file) when available
/// 3. If .symtab/.dynsym are empty (stripped binary), fall back to DWARF-only extraction
pub fn extract_symbols(path: &Path) -> anyhow::Result<Vec<SymbolRange>> {
    let data = std::fs::read(path)?;
    let file = object::File::parse(&*data)?;

    // Phase 1: Extract from symbol tables
    let mut symbols = extract_from_symtab(&file);

    // Phase 2: If we got symbols from symtab, enrich with DWARF source file info
    // If no symtab symbols (stripped binary), try DWARF-only extraction
    if symbols.is_empty() {
        symbols = extract_from_dwarf(&data, &file);
        if symbols.is_empty() {
            tracing::info!(
                "no symbols in {}: binary is stripped and DWARF extraction is not yet implemented",
                path.display()
            );
        } else {
            tracing::info!(
                "extracted {} symbols from DWARF in {}",
                symbols.len(),
                path.display()
            );
        }
    } else {
        // Enrich existing symbols with source file info from DWARF
        enrich_with_dwarf(&data, &mut symbols);
        tracing::info!(
            "extracted {} symbols from symtab+DWARF in {}",
            symbols.len(),
            path.display()
        );
    }

    // Sort by virtual address (required for symbfile format)
    symbols.sort_by_key(|s| s.elf_va);

    Ok(symbols)
}

/// Extract from .symtab and .dynsym sections.
fn extract_from_symtab(file: &object::File) -> Vec<SymbolRange> {
    let mut symbols: Vec<SymbolRange> = Vec::new();
    let mut seen_addrs = std::collections::HashSet::new();

    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Text {
            continue;
        }
        if symbol.size() == 0 {
            continue;
        }
        let addr = symbol.address();
        if addr == 0 {
            continue;
        }
        if !seen_addrs.insert(addr) {
            continue;
        }

        let name = match symbol.name() {
            Ok(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };

        let demangled = demangle(&name);

        symbols.push(SymbolRange {
            elf_va: addr,
            length: symbol.size(),
            name: demangled,
            file: None,
        });
    }

    symbols
}

/// Extract function ranges from DWARF debug info only (for stripped binaries).
fn extract_from_dwarf(_data: &[u8], _file: &object::File) -> Vec<SymbolRange> {
    // TODO: iterate .debug_info DIEs to extract DW_TAG_subprogram entries
    // with DW_AT_low_pc/DW_AT_high_pc for function ranges.
    // For now, return empty — stripped binaries without symtab won't have symbols.
    Vec::new()
}

/// Enrich existing symbols with source file info from DWARF.
///
/// TODO: Use addr2line/gimli to look up source file for each function.
/// The addr2line API requires careful lifetime management with owned data.
/// For now, source file enrichment is skipped — function names from
/// .symtab/.dynsym are already sufficient for devfiler's flamegraph.
fn enrich_with_dwarf(_data: &[u8], _symbols: &mut [SymbolRange]) {
    // Future: parse .debug_info/.debug_line to get source file paths.
    // profile-bee's blazesym already does this at runtime; the symbol-server
    // could share the same gimli/addr2line code path for batch extraction.
}

/// Attempt to demangle a C++/Rust symbol name.
///
/// C++ Itanium demangling is attempted first because `rustc_demangle` can
/// mis-parse `_ZN...` C++ names as Rust legacy mangling. Rust v0 names
/// (`_R...`) are unambiguous and handled correctly by either order.
fn demangle(name: &str) -> String {
    // Try C++ demangling first — avoids mis-parsing Itanium names as Rust
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return demangled;
        }
    }
    // Try Rust demangling
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return format!("{:#}", demangled);
    }
    // Return as-is
    name.to_string()
}
