//! Symbol discovery engine for resolving probe specs to concrete uprobe targets.
//!
//! Scans ELF binaries (via /proc/pid/maps or system library paths) to find
//! symbols matching a `ProbeSpec`. Supports exact, glob, regex, and demangled
//! name matching, as well as source-location resolution via DWARF debug info.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use addr2line::demangle;
use gimli::{self, EndianSlice, NativeEndian};
use object::{Object, ObjectSymbol};
use procfs::process::{MMPermissions, MMapPath, Process};

use crate::probe_spec::{ProbeSpec, SymbolPattern};

/// A resolved probe target — a concrete (library, symbol, offset) triple
/// that can be passed to `UProbe::attach()`.
#[derive(Debug, Clone)]
pub struct ResolvedProbe {
    /// Absolute path to the ELF binary or shared library.
    pub library_path: PathBuf,
    /// The raw (mangled) symbol name as it appears in the ELF.
    pub symbol_name: String,
    /// Byte offset from the start of the symbol (from the spec's +offset).
    pub offset: u64,
    /// Virtual address of the symbol in the ELF file.
    pub address: u64,
    /// Symbol size (if available from ELF).
    pub size: u64,
    /// Demangled name (if different from symbol_name).
    pub demangled: Option<String>,
    /// Whether this should be a return probe.
    pub is_ret: bool,
}

/// Resolves probe specifications to concrete uprobe attach targets.
pub struct ProbeResolver;

impl Default for ProbeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeResolver {
    pub fn new() -> Self {
        Self
    }

    /// Resolve a probe spec for a running process.
    ///
    /// Reads /proc/<pid>/maps, scans each mapped executable ELF for matching symbols.
    pub fn resolve_for_pid(
        &self,
        spec: &ProbeSpec,
        pid: u32,
    ) -> Result<Vec<ResolvedProbe>, String> {
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                let maps = self.get_executable_maps(pid)?;
                let mut results = Vec::new();

                for (path, _start, _end) in &maps {
                    // If library filter is set, check it
                    if let Some(lib_filter) = library {
                        if !library_matches(lib_filter, path) {
                            continue;
                        }
                    }

                    match self.scan_elf_for_symbols(path, pattern, *offset, *is_ret) {
                        Ok(mut probes) => results.append(&mut probes),
                        Err(e) => {
                            // Non-fatal: some mapped files may not be readable
                            tracing::debug!("skipping {}: {}", path.display(), e);
                        }
                    }
                }

                Ok(results)
            }
            ProbeSpec::SourceLocation { file, line, is_ret } => {
                let maps = self.get_executable_maps(pid)?;
                let mut results = Vec::new();

                for (path, _start, _end) in &maps {
                    match self.resolve_source_location(path, file, *line, *is_ret) {
                        Ok(mut probes) => results.append(&mut probes),
                        Err(_) => continue,
                    }
                }

                Ok(results)
            }
        }
    }

    /// Resolve a probe spec by scanning system library paths.
    ///
    /// Used when no --pid is specified. Scans well-known library directories
    /// and ldconfig cache.
    pub fn resolve_system_wide(&self, spec: &ProbeSpec) -> Result<Vec<ResolvedProbe>, String> {
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                let lib_paths = if let Some(lib_filter) = library {
                    // If a specific library is named, find it
                    self.find_library_paths(lib_filter)?
                } else {
                    // Scan common library directories
                    self.get_system_libraries()?
                };

                let mut results = Vec::new();
                for path in &lib_paths {
                    match self.scan_elf_for_symbols(path, pattern, *offset, *is_ret) {
                        Ok(mut probes) => results.append(&mut probes),
                        Err(_) => continue,
                    }
                }

                Ok(results)
            }
            ProbeSpec::SourceLocation { file, line, is_ret } => {
                // For source locations without a PID, there's not much we can do
                // besides scanning system libraries for DWARF info
                let lib_paths = self.get_system_libraries()?;
                let mut results = Vec::new();

                for path in &lib_paths {
                    match self.resolve_source_location(path, file, *line, *is_ret) {
                        Ok(mut probes) => results.append(&mut probes),
                        Err(_) => continue,
                    }
                }

                Ok(results)
            }
        }
    }

    /// Get all executable memory-mapped files for a process.
    fn get_executable_maps(&self, pid: u32) -> Result<Vec<(PathBuf, u64, u64)>, String> {
        let process =
            Process::new(pid as i32).map_err(|e| format!("failed to open /proc/{}: {}", pid, e))?;

        let maps = process
            .maps()
            .map_err(|e| format!("failed to read /proc/{}/maps: {}", pid, e))?;

        let root_path = format!("/proc/{}/root", pid);
        let mut seen = HashMap::new();
        let mut result = Vec::new();

        for map in maps.iter() {
            if !map.perms.contains(MMPermissions::EXECUTE)
                || !map.perms.contains(MMPermissions::READ)
            {
                continue;
            }

            let file_path = match &map.pathname {
                MMapPath::Path(p) => p.to_path_buf(),
                _ => continue,
            };

            // Deduplicate: same binary may be mapped multiple times
            if seen.contains_key(&file_path) {
                continue;
            }
            seen.insert(file_path.clone(), ());

            // Resolve through /proc/<pid>/root for container/namespace support
            let resolved = if file_path.is_absolute() {
                let ns_path = PathBuf::from(&root_path)
                    .join(file_path.strip_prefix("/").unwrap_or(&file_path));
                if ns_path.exists() {
                    ns_path
                } else {
                    file_path
                }
            } else {
                file_path
            };

            result.push((resolved, map.address.0, map.address.1));
        }

        Ok(result)
    }

    /// Scan an ELF binary for symbols matching the given pattern.
    fn scan_elf_for_symbols(
        &self,
        path: &Path,
        pattern: &SymbolPattern,
        spec_offset: u64,
        is_ret: bool,
    ) -> Result<Vec<ResolvedProbe>, String> {
        let data = fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

        let obj = object::File::parse(&*data)
            .map_err(|e| format!("cannot parse ELF {}: {}", path.display(), e))?;

        let mut results = Vec::new();
        let mut seen_names = HashMap::new();

        // Iterate both .symtab and .dynsym
        for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
            let name = match symbol.name() {
                Ok(n) if !n.is_empty() => n,
                _ => continue,
            };

            // Skip non-function symbols
            if symbol.kind() != object::SymbolKind::Text {
                continue;
            }

            // Skip undefined (imported) symbols
            if symbol.is_undefined() {
                continue;
            }

            // Deduplicate
            if seen_names.contains_key(name) {
                continue;
            }

            let matched = match pattern {
                SymbolPattern::Exact(_) | SymbolPattern::Glob(_) | SymbolPattern::Regex(_) => {
                    pattern.matches(name)
                }
                SymbolPattern::Demangled(_) => {
                    // Demangle and check
                    let demangled = try_demangle(name);
                    if let Some(ref dm) = demangled {
                        pattern.matches_demangled(dm)
                    } else {
                        // No demangling possible, try raw name
                        pattern.matches_demangled(name)
                    }
                }
            };

            if matched {
                seen_names.insert(name.to_string(), ());
                let demangled = try_demangle(name);

                results.push(ResolvedProbe {
                    library_path: path.to_path_buf(),
                    symbol_name: name.to_string(),
                    offset: spec_offset,
                    address: symbol.address(),
                    size: symbol.size(),
                    demangled,
                    is_ret,
                });
            }
        }

        Ok(results)
    }

    /// Resolve a source file:line to a probe target using DWARF debug info.
    fn resolve_source_location(
        &self,
        elf_path: &Path,
        target_file: &str,
        target_line: u32,
        is_ret: bool,
    ) -> Result<Vec<ResolvedProbe>, String> {
        let data =
            fs::read(elf_path).map_err(|e| format!("cannot read {}: {}", elf_path.display(), e))?;

        let obj = object::File::parse(&*data)
            .map_err(|e| format!("cannot parse ELF {}: {}", elf_path.display(), e))?;

        // Load DWARF sections as EndianSlice references into `data`
        let load_section =
            |id: gimli::SectionId| -> Result<EndianSlice<'_, NativeEndian>, gimli::Error> {
                let slice = obj
                    .section_by_name(id.name())
                    .and_then(|s| {
                        use object::ObjectSection;
                        s.data().ok()
                    })
                    .unwrap_or(&[]);
                Ok(EndianSlice::new(slice, NativeEndian))
            };

        let dwarf = gimli::Dwarf::load(load_section)
            .map_err(|e| format!("failed to load DWARF from {}: {}", elf_path.display(), e))?;

        let mut results = Vec::new();
        let mut units = dwarf.units();

        while let Ok(Some(header)) = units.next() {
            let unit = match dwarf.unit(header) {
                Ok(u) => u,
                Err(_) => continue,
            };

            let line_program = match unit.line_program.clone() {
                Some(lp) => lp,
                None => continue,
            };

            let mut rows = line_program.rows();
            let mut best_match: Option<(u64, u32)> = None; // (address, actual_line)

            while let Ok(Some((header, row))) = rows.next_row() {
                if row.end_sequence() {
                    continue;
                }

                if let Some(file_entry) = row.file(header) {
                    let file_name: Option<String> = dwarf
                        .attr_string(&unit, file_entry.path_name())
                        .ok()
                        .and_then(|s| s.to_string().ok().map(|s| s.to_string()));

                    if let Some(ref fname) = file_name {
                        // Match: the file name ends with the target file name
                        // This handles both "main.c" matching "/home/user/src/main.c"
                        // and exact matches
                        if fname.ends_with(target_file) || target_file.ends_with(fname.as_str()) {
                            if let Some(line) = row.line() {
                                let line_num = line.get() as u32;
                                // Find the closest line >= target_line
                                if line_num >= target_line {
                                    match best_match {
                                        None => best_match = Some((row.address(), line_num)),
                                        Some((_, best_line)) if line_num < best_line => {
                                            best_match = Some((row.address(), line_num));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some((address, actual_line)) = best_match {
                // Try to find the function name at this address
                let fn_name = find_function_at_address(&dwarf, &unit, address);

                results.push(ResolvedProbe {
                    library_path: elf_path.to_path_buf(),
                    symbol_name: fn_name.unwrap_or_else(|| format!("0x{:x}", address)),
                    offset: 0, // Source location resolves to exact address
                    address,
                    size: 0,
                    demangled: None,
                    is_ret,
                });

                if actual_line != target_line {
                    tracing::info!(
                        "{}:{} resolved to line {} at 0x{:x}",
                        target_file,
                        target_line,
                        actual_line,
                        address,
                    );
                }
            }
        }

        Ok(results)
    }

    /// Find library paths matching a name (e.g. "libc" -> "/usr/lib/x86_64-linux-gnu/libc.so.6").
    fn find_library_paths(&self, name: &str) -> Result<Vec<PathBuf>, String> {
        // If it's an absolute path, use directly
        if name.starts_with('/') {
            if Path::new(name).exists() {
                return Ok(vec![PathBuf::from(name)]);
            } else {
                return Err(format!("library not found: {}", name));
            }
        }

        // Try ldconfig cache
        let mut paths = Vec::new();

        if let Ok(output) = std::process::Command::new("ldconfig").arg("-p").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // Format: "    libfoo.so.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libfoo.so.1"
                if let Some(arrow_pos) = line.find("=>") {
                    let lib_part = line[..arrow_pos].trim();
                    let path_part = line[arrow_pos + 2..].trim();

                    // Match: library name starts with the filter
                    // e.g. "libc" matches "libc.so.6", "libc.so", etc.
                    let lib_name = lib_part.split_whitespace().next().unwrap_or("");
                    if lib_name.starts_with(name) || lib_name.starts_with(&format!("lib{}", name)) {
                        let path = PathBuf::from(path_part);
                        if path.exists() && !paths.contains(&path) {
                            paths.push(path);
                        }
                    }
                }
            }
        }

        // Fallback: scan common directories
        if paths.is_empty() {
            let search_dirs = [
                "/usr/lib",
                "/usr/lib64",
                "/lib",
                "/lib64",
                "/usr/lib/x86_64-linux-gnu",
                "/usr/lib/aarch64-linux-gnu",
            ];

            for dir in &search_dirs {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let fname = entry.file_name();
                        let fname_str = fname.to_string_lossy();
                        if (fname_str.starts_with(name)
                            || fname_str.starts_with(&format!("lib{}", name)))
                            && fname_str.contains(".so")
                        {
                            let path = entry.path();
                            if !paths.contains(&path) {
                                paths.push(path);
                            }
                        }
                    }
                }
            }
        }

        if paths.is_empty() {
            Err(format!(
                "library '{}' not found in ldconfig cache or standard paths",
                name
            ))
        } else {
            Ok(paths)
        }
    }

    /// Get a list of commonly-used system libraries for system-wide scanning.
    fn get_system_libraries(&self) -> Result<Vec<PathBuf>, String> {
        let mut paths = Vec::new();

        // Parse ldconfig cache for all libraries
        if let Ok(output) = std::process::Command::new("ldconfig").arg("-p").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(arrow_pos) = line.find("=>") {
                    let path_str = line[arrow_pos + 2..].trim();
                    let path = PathBuf::from(path_str);
                    if path.exists() && !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
        }

        Ok(paths)
    }
}

/// Try to demangle a symbol name using both Rust and C++ demanglers.
fn try_demangle(name: &str) -> Option<String> {
    // Try Rust demangling first
    let rust_result = demangle(name, gimli::DW_LANG_Rust);
    if let Some(ref demangled) = rust_result {
        if demangled != name {
            return rust_result;
        }
    }

    // Try C++ demangling
    let cpp_result = demangle(name, gimli::DW_LANG_C_plus_plus);
    if let Some(ref demangled) = cpp_result {
        if demangled != name {
            return cpp_result;
        }
    }

    None
}

/// Check if a library filter matches a given path.
fn library_matches(filter: &str, path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Exact path match
    if path_str == filter {
        return true;
    }

    // Absolute path prefix match
    if filter.starts_with('/') {
        return path_str.starts_with(filter);
    }

    // Library name match: "libc" matches "/usr/lib/x86_64-linux-gnu/libc.so.6"
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();

    file_name.starts_with(filter)
        || file_name.starts_with(&format!("lib{}", filter))
        // Also match just the stem: "libc" matches "libc-2.31.so"
        || file_name.contains(&format!("{}.so", filter))
        || file_name.contains(&format!("lib{}.so", filter))
}

/// Find the function name at a given address using DWARF debug info.
fn find_function_at_address<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    target_address: u64,
) -> Option<String> {
    let mut entries = unit.entries();
    while let Ok(Some((_, entry))) = entries.next_dfs() {
        if entry.tag() == gimli::DW_TAG_subprogram {
            // Check if this function contains the target address
            let low_pc = entry
                .attr_value(gimli::DW_AT_low_pc)
                .ok()
                .flatten()
                .and_then(|v| match v {
                    gimli::AttributeValue::Addr(addr) => Some(addr),
                    _ => None,
                });

            if let Some(low) = low_pc {
                let high_pc = entry
                    .attr_value(gimli::DW_AT_high_pc)
                    .ok()
                    .flatten()
                    .and_then(|v| match v {
                        gimli::AttributeValue::Addr(addr) => Some(addr),
                        gimli::AttributeValue::Udata(size) => Some(low + size),
                        _ => None,
                    });

                let contains = match high_pc {
                    Some(high) => target_address >= low && target_address < high,
                    None => target_address == low,
                };

                if contains {
                    if let Some(name) = entry
                        .attr_value(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|v| dwarf.attr_string(unit, v).ok())
                        .and_then(|s| s.to_string().ok().map(|s| s.to_string()))
                    {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

/// Format resolved probes for display (used by --list-probes).
pub fn format_resolved_probes(probes: &[ResolvedProbe]) -> String {
    if probes.is_empty() {
        return "No matching symbols found.".to_string();
    }

    // Group by library path
    let mut by_library: HashMap<&Path, Vec<&ResolvedProbe>> = HashMap::new();
    for probe in probes {
        by_library
            .entry(&probe.library_path)
            .or_default()
            .push(probe);
    }

    let mut output = String::new();
    let mut libs: Vec<_> = by_library.keys().collect();
    libs.sort();

    for lib in libs {
        let probes = &by_library[lib];
        output.push_str(&format!("\n{}:\n", lib.display()));

        let mut sorted_probes = probes.to_vec();
        sorted_probes.sort_by_key(|p| p.address);

        for probe in sorted_probes {
            let name_display = if let Some(ref dm) = probe.demangled {
                format!("{} ({})", probe.symbol_name, dm)
            } else {
                probe.symbol_name.clone()
            };

            if probe.size > 0 {
                output.push_str(&format!(
                    "  {:<50} 0x{:08x}  ({} bytes)\n",
                    name_display, probe.address, probe.size
                ));
            } else {
                output.push_str(&format!("  {:<50} 0x{:08x}\n", name_display, probe.address));
            }
        }
    }

    let total = probes.len();
    let lib_count = by_library.len();
    output.push_str(&format!(
        "\nTotal: {} match{} across {} librar{}\n",
        total,
        if total == 1 { "" } else { "es" },
        lib_count,
        if lib_count == 1 { "y" } else { "ies" },
    ));

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_matches_exact() {
        let path = Path::new("/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert!(library_matches("libc", path));
        assert!(library_matches("libc.so.6", path));
        assert!(library_matches("/usr/lib/x86_64-linux-gnu/libc.so.6", path));
        assert!(!library_matches("libpthread", path));
    }

    #[test]
    fn test_library_matches_lib_prefix() {
        let path = Path::new("/usr/lib/libpthread.so.0");
        assert!(library_matches("pthread", path));
        assert!(library_matches("libpthread", path));
    }

    #[test]
    fn test_try_demangle_rust() {
        // A typical Rust mangled symbol
        let demangled = try_demangle("_ZN3std2io5stdio6_print17h1234567890abcdefE");
        assert!(demangled.is_some());
    }

    #[test]
    fn test_try_demangle_plain() {
        // Plain C symbol — should return None (no demangling needed)
        let demangled = try_demangle("malloc");
        assert!(demangled.is_none());
    }
}
