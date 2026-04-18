//! ELF symbol extraction — reads function names and address ranges from binaries.
//!
//! Extracts from .symtab (static symbols), .dynsym (dynamic symbols), and
//! optionally DWARF debug info for source file/line information.

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
/// Reads symbols from .symtab and .dynsym sections. Returns ranges sorted
/// by virtual address. Deduplicates by address (prefers .symtab over .dynsym).
pub fn extract_symbols(path: &Path) -> anyhow::Result<Vec<SymbolRange>> {
    let data = std::fs::read(path)?;
    let file = object::File::parse(&*data)?;

    let mut symbols: Vec<SymbolRange> = Vec::new();
    let mut seen_addrs = std::collections::HashSet::new();

    // Extract from all symbol tables (symtab first, then dynsym)
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
            continue; // deduplicate by address
        }

        let name = match symbol.name() {
            Ok(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };

        // Try to demangle C++/Rust symbols
        let demangled = demangle(&name);

        symbols.push(SymbolRange {
            elf_va: addr,
            length: symbol.size(),
            name: demangled,
            file: None,
        });
    }

    // Sort by virtual address (required for symbfile format)
    symbols.sort_by_key(|s| s.elf_va);

    tracing::info!(
        "extracted {} symbols from {}",
        symbols.len(),
        path.display()
    );
    Ok(symbols)
}

/// Attempt to demangle a C++/Rust symbol name.
fn demangle(name: &str) -> String {
    // Try Rust demangling
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return format!("{:#}", demangled);
    }
    // Try C++ demangling
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return demangled;
        }
    }
    // Return as-is
    name.to_string()
}
