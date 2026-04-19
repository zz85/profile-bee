//! JITDump file parser for resolving JIT-compiled function names.
//!
//! JITDump is a standard binary format written by JIT runtimes to map
//! dynamically-generated code addresses to function names. Supported by
//! Bun (JavaScriptCore via `BUN_JSC_useJITDump=1`), Node.js (`--perf-prof`),
//! Java HotSpot, LuaJIT, and others.
//!
//! Reference: `tools/perf/Documentation/jitdump-specification.txt` in the
//! Linux kernel source.
//!
//! This module provides a zero-dependency parser (std only) with a
//! `BTreeMap`-backed symbol table for O(log n) address range lookups.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

// JITDump magic numbers
const JITDUMP_MAGIC_LE: u32 = 0x4A695444; // "JiTD" little-endian
const JITDUMP_MAGIC_BE: u32 = 0x4454694A; // "JiTD" big-endian

// Record type IDs
const JIT_CODE_LOAD: u32 = 0;
const JIT_CODE_MOVE: u32 = 1;
const JIT_CODE_DEBUG_INFO: u32 = 2;
const JIT_CODE_CLOSE: u32 = 3;
// const JIT_CODE_UNWINDING_INFO: u32 = 4; // not needed

// Header size in bytes (10 fields)
const JITDUMP_HEADER_SIZE: u64 = 40;

// Record header size: id(u32) + total_size(u32) + timestamp(u64)
const RECORD_HEADER_SIZE: u64 = 16;

/// A single JIT symbol region: code address range -> function name.
#[derive(Debug, Clone)]
pub struct JitSymbol {
    pub code_addr: u64,
    pub code_size: u64,
    pub name: String,
    /// Optional source file + line from JIT_CODE_DEBUG_INFO.
    pub source: Option<(String, u32)>,
}

/// Parsed JITDump symbol table for a single process.
///
/// Uses a `BTreeMap` keyed by `code_addr` for O(log n) range-based lookup.
/// Supports incremental reloading for streaming/TUI modes.
pub struct JitSymbolTable {
    symbols: BTreeMap<u64, JitSymbol>,
    /// Debug info that arrives before its corresponding JIT_CODE_LOAD.
    /// Keyed by `code_index` (matches JIT_CODE_LOAD's `code_index` field).
    pending_debug: HashMap<u64, (String, u32)>,
    /// File offset for incremental reload — next read starts here.
    last_read_offset: u64,
}

impl JitSymbolTable {
    /// Look up a symbol by instruction pointer address.
    ///
    /// Returns the function name if `addr` falls within a known JIT region
    /// `[code_addr, code_addr + code_size)`.
    pub fn resolve(&self, addr: u64) -> Option<&JitSymbol> {
        // Find the last entry with code_addr <= addr
        self.symbols
            .range(..=addr)
            .next_back()
            .map(|(_, sym)| sym)
            .filter(|sym| addr < sym.code_addr + sym.code_size)
    }

    /// Parse a JITDump file and populate the symbol table.
    ///
    /// Tolerates partial/truncated files — returns whatever was successfully
    /// parsed. This is important because the JIT runtime may still be writing
    /// the file while we read it.
    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);

        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: 0,
        };

        // Parse and validate header
        let _header = match parse_header(&mut reader) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("JITDump header parse failed: {}", e);
                return Ok(table);
            }
        };

        table.last_read_offset = JITDUMP_HEADER_SIZE;

        // Read records
        table.read_records(&mut reader)?;

        Ok(table)
    }

    /// Resume reading from a partially-read file for streaming modes.
    ///
    /// Seeks to `last_read_offset` and reads any new records appended since
    /// the last read. Returns the number of new symbols loaded.
    pub fn reload_from_file(&mut self, path: &Path) -> io::Result<usize> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);

        reader.seek(SeekFrom::Start(self.last_read_offset))?;

        let before = self.symbols.len();
        self.read_records(&mut reader)?;
        Ok(self.symbols.len() - before)
    }

    /// Number of symbols in the table.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Read records from the current reader position until EOF or JIT_CODE_CLOSE.
    fn read_records<R: Read + Seek>(&mut self, reader: &mut R) -> io::Result<()> {
        loop {
            let record_start = reader.stream_position()?;

            // Read record header (16 bytes)
            let (record_id, total_size, _timestamp) = match read_record_header(reader) {
                Ok(h) => h,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Partial file — stop reading, keep what we have
                    self.last_read_offset = record_start;
                    break;
                }
                Err(e) => {
                    tracing::debug!("JITDump record header read error: {}", e);
                    self.last_read_offset = record_start;
                    break;
                }
            };

            if total_size < RECORD_HEADER_SIZE as u32 {
                tracing::debug!(
                    "JITDump record with invalid size {} at offset {}",
                    total_size,
                    record_start
                );
                self.last_read_offset = record_start;
                break;
            }

            let payload_size = total_size as u64 - RECORD_HEADER_SIZE;

            match record_id {
                JIT_CODE_LOAD => match self.parse_code_load(reader, payload_size) {
                    Ok(()) => {}
                    Err(_) => {
                        self.last_read_offset = record_start;
                        break;
                    }
                },
                JIT_CODE_MOVE => match self.parse_code_move(reader, payload_size) {
                    Ok(()) => {}
                    Err(_) => {
                        self.last_read_offset = record_start;
                        break;
                    }
                },
                JIT_CODE_DEBUG_INFO => match self.parse_debug_info(reader, payload_size) {
                    Ok(()) => {}
                    Err(_) => {
                        self.last_read_offset = record_start;
                        break;
                    }
                },
                JIT_CODE_CLOSE => {
                    self.last_read_offset = record_start + total_size as u64;
                    break;
                }
                _ => {
                    // Unknown record type — skip
                    skip_bytes(reader, payload_size)?;
                }
            }

            self.last_read_offset = record_start + total_size as u64;
        }

        Ok(())
    }

    /// Parse a JIT_CODE_LOAD record.
    ///
    /// Fixed fields after record header:
    ///   pid(u32), tid(u32), vma(u64), code_addr(u64), code_size(u64), code_index(u64)
    /// Followed by: null-terminated function name, then raw code bytes.
    fn parse_code_load<R: Read>(&mut self, reader: &mut R, payload_size: u64) -> io::Result<()> {
        // Fixed fields: 4 + 4 + 8 + 8 + 8 + 8 = 40 bytes
        const FIXED_SIZE: u64 = 40;
        if payload_size < FIXED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JIT_CODE_LOAD too small",
            ));
        }

        let _pid = read_u32(reader)?;
        let _tid = read_u32(reader)?;
        let _vma = read_u64(reader)?;
        let code_addr = read_u64(reader)?;
        let code_size = read_u64(reader)?;
        let code_index = read_u64(reader)?;

        // Remaining bytes: null-terminated name + code bytes
        let remaining = payload_size - FIXED_SIZE;
        let mut name_and_code = vec![0u8; remaining as usize];
        reader.read_exact(&mut name_and_code)?;

        // Extract null-terminated name
        let name_end = name_and_code
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_and_code.len());
        let name = String::from_utf8_lossy(&name_and_code[..name_end]).to_string();

        // Check for pending debug info
        let source = self.pending_debug.remove(&code_index);

        self.symbols.insert(
            code_addr,
            JitSymbol {
                code_addr,
                code_size,
                name,
                source,
            },
        );

        Ok(())
    }

    /// Parse a JIT_CODE_MOVE record.
    ///
    /// Fixed fields: old_code_addr(u64), new_code_addr(u64),
    ///               new_code_size(u64), code_index(u64)
    fn parse_code_move<R: Read>(&mut self, reader: &mut R, payload_size: u64) -> io::Result<()> {
        const FIXED_SIZE: u64 = 32;
        if payload_size < FIXED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JIT_CODE_MOVE too small",
            ));
        }

        let old_code_addr = read_u64(reader)?;
        let new_code_addr = read_u64(reader)?;
        let new_code_size = read_u64(reader)?;
        let _code_index = read_u64(reader)?;

        // Skip any remaining payload
        if payload_size > FIXED_SIZE {
            skip_bytes(reader, payload_size - FIXED_SIZE)?;
        }

        // Move the symbol entry
        if let Some(mut sym) = self.symbols.remove(&old_code_addr) {
            sym.code_addr = new_code_addr;
            sym.code_size = new_code_size;
            self.symbols.insert(new_code_addr, sym);
        }

        Ok(())
    }

    /// Parse a JIT_CODE_DEBUG_INFO record.
    ///
    /// Fixed fields: code_addr(u64), nr_entry(u64)
    /// Followed by array of debug entries: addr(u64), line(u32), discrim(u32),
    /// then null-terminated filename.
    ///
    /// Per spec, DEBUG_INFO must appear before its corresponding CODE_LOAD.
    /// We store the first entry's (filename, line) in pending_debug keyed by
    /// code_addr (used as a proxy for code_index).
    fn parse_debug_info<R: Read>(&mut self, reader: &mut R, payload_size: u64) -> io::Result<()> {
        if payload_size < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JIT_CODE_DEBUG_INFO too small",
            ));
        }

        let code_addr = read_u64(reader)?;
        let nr_entry = read_u64(reader)?;

        // Read the first debug entry if available, skip the rest.
        // Each entry: addr(u64) + line(u32) + discrim(u32) + null-terminated filename
        let mut consumed = 16u64;
        if nr_entry > 0 && payload_size > consumed + 16 {
            let _entry_addr = read_u64(reader)?;
            let line = read_u32(reader)?;
            let _discrim = read_u32(reader)?;
            consumed += 16;

            // Read null-terminated filename from remaining payload
            let remaining = payload_size - consumed;
            let mut buf = vec![0u8; remaining as usize];
            reader.read_exact(&mut buf)?;

            let name_end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let filename = String::from_utf8_lossy(&buf[..name_end]).to_string();

            if !filename.is_empty() {
                self.pending_debug.insert(code_addr, (filename, line));
            }

            return Ok(());
        }

        // Skip remaining payload
        if payload_size > consumed {
            skip_bytes(reader, payload_size - consumed)?;
        }

        Ok(())
    }
}

/// Check if a JITDump file exists for the given PID.
///
/// Searches for JITDump files in `/tmp/` using two naming conventions:
/// 1. Standard: `/tmp/jit-<pid>.dump` (used by Java HotSpot, LuaJIT, `perf`)
/// 2. JSC/Bun: `/tmp/jit-<tid>-<pid>-<random>` (used by JavaScriptCore)
///
/// Returns the first matching file path, preferring the standard convention.
pub fn find_jitdump_for_pid(pid: u32) -> Option<PathBuf> {
    // Standard convention: /tmp/jit-<pid>.dump
    let standard = PathBuf::from(format!("/tmp/jit-{}.dump", pid));
    if standard.exists() {
        return Some(standard);
    }

    // JSC/Bun convention: /tmp/jit-<tid>-<pid>-<random>
    // Scan /tmp/ for files matching this pattern.
    let prefix = format!("jit-");
    let pid_str = pid.to_string();
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Match pattern: jit-<digits>-<pid>-<alphanum>
            if name.starts_with(&prefix) && name.contains(&format!("-{}-", pid_str)) {
                return Some(entry.path());
            }
        }
    }

    None
}

/// Format a JIT symbol for display in flamegraphs.
///
/// If source file info is available: `functionName (file.js:42)`
/// Otherwise just: `functionName`
pub fn format_jit_symbol(sym: &JitSymbol) -> String {
    if let Some((ref file, line)) = sym.source {
        let basename = Path::new(file)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(file);
        format!("{} ({}:{})", sym.name, basename, line)
    } else {
        sym.name.clone()
    }
}

// ── Binary reading helpers ──────────────────────────────────────────────────

/// JITDump file header (40 bytes).
struct JitdumpHeader {
    _version: u32,
    _elf_mach: u32,
    _pid: u32,
}

fn parse_header<R: Read>(reader: &mut R) -> io::Result<JitdumpHeader> {
    let magic = read_u32(reader)?;
    if magic != JITDUMP_MAGIC_LE && magic != JITDUMP_MAGIC_BE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid JITDump magic: {:#x}", magic),
        ));
    }
    if magic == JITDUMP_MAGIC_BE {
        // We only support little-endian (x86_64). Big-endian JITDump files
        // are theoretically possible but not encountered in practice.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "big-endian JITDump not supported",
        ));
    }

    let version = read_u32(reader)?;
    let _total_size = read_u32(reader)?;
    let elf_mach = read_u32(reader)?;
    let _pad1 = read_u32(reader)?;
    let pid = read_u32(reader)?;
    let _timestamp = read_u64(reader)?;
    let _flags = read_u64(reader)?;

    Ok(JitdumpHeader {
        _version: version,
        _elf_mach: elf_mach,
        _pid: pid,
    })
}

fn read_record_header<R: Read>(reader: &mut R) -> io::Result<(u32, u32, u64)> {
    let id = read_u32(reader)?;
    let total_size = read_u32(reader)?;
    let timestamp = read_u64(reader)?;
    Ok((id, total_size, timestamp))
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn skip_bytes<R: Read>(reader: &mut R, n: u64) -> io::Result<()> {
    // For BufReader, seeking is more efficient but Read doesn't guarantee Seek.
    // Use a small buffer to discard bytes.
    let mut remaining = n;
    let mut buf = [0u8; 4096];
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..to_read])?;
        remaining -= to_read as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal JITDump file in memory with the given records.
    fn build_jitdump(records: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header (40 bytes)
        buf.extend_from_slice(&JITDUMP_MAGIC_LE.to_le_bytes()); // magic
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&40u32.to_le_bytes()); // total_size (header)
        buf.extend_from_slice(&0x3Eu32.to_le_bytes()); // elf_mach (EM_X86_64)
        buf.extend_from_slice(&0u32.to_le_bytes()); // pad1
        buf.extend_from_slice(&1234u32.to_le_bytes()); // pid
        buf.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u64.to_le_bytes()); // flags

        for record in records {
            buf.extend_from_slice(record);
        }

        buf
    }

    /// Build a JIT_CODE_LOAD record.
    fn code_load_record(code_addr: u64, code_size: u64, code_index: u64, name: &str) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        // name + null terminator, no code bytes for simplicity
        let payload_size = 40 + name_bytes.len() as u32 + 1;
        let total_size = 16 + payload_size;

        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_LOAD.to_le_bytes()); // id
        rec.extend_from_slice(&total_size.to_le_bytes()); // total_size
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp

        // Fixed payload
        rec.extend_from_slice(&1234u32.to_le_bytes()); // pid
        rec.extend_from_slice(&1234u32.to_le_bytes()); // tid
        rec.extend_from_slice(&code_addr.to_le_bytes()); // vma
        rec.extend_from_slice(&code_addr.to_le_bytes()); // code_addr
        rec.extend_from_slice(&code_size.to_le_bytes()); // code_size
        rec.extend_from_slice(&code_index.to_le_bytes()); // code_index

        // Name + null
        rec.extend_from_slice(name_bytes);
        rec.push(0);

        rec
    }

    /// Build a JIT_CODE_MOVE record.
    fn code_move_record(old_addr: u64, new_addr: u64, new_size: u64, code_index: u64) -> Vec<u8> {
        let total_size: u32 = 16 + 32;
        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_MOVE.to_le_bytes());
        rec.extend_from_slice(&total_size.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec.extend_from_slice(&old_addr.to_le_bytes());
        rec.extend_from_slice(&new_addr.to_le_bytes());
        rec.extend_from_slice(&new_size.to_le_bytes());
        rec.extend_from_slice(&code_index.to_le_bytes());
        rec
    }

    /// Build a JIT_CODE_CLOSE record.
    fn close_record() -> Vec<u8> {
        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_CLOSE.to_le_bytes());
        rec.extend_from_slice(&16u32.to_le_bytes()); // total_size = header only
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec
    }

    #[test]
    fn test_parse_single_symbol() {
        let data = build_jitdump(&[code_load_record(0x1000, 0x100, 0, "myFunction")]);
        let mut cursor = Cursor::new(data);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        assert_eq!(table.len(), 1);

        // Exact start address
        let sym = table.resolve(0x1000).unwrap();
        assert_eq!(sym.name, "myFunction");
        assert_eq!(sym.code_size, 0x100);

        // Middle of the range
        assert!(table.resolve(0x1050).is_some());

        // Just before the end
        assert!(table.resolve(0x10FF).is_some());

        // At the end (exclusive)
        assert!(table.resolve(0x1100).is_none());

        // Before the start
        assert!(table.resolve(0x0FFF).is_none());
    }

    #[test]
    fn test_parse_multiple_symbols() {
        let data = build_jitdump(&[
            code_load_record(0x1000, 0x100, 0, "funcA"),
            code_load_record(0x2000, 0x200, 1, "funcB"),
            code_load_record(0x3000, 0x50, 2, "funcC"),
        ]);
        let mut cursor = Cursor::new(data);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        assert_eq!(table.len(), 3);
        assert_eq!(table.resolve(0x1050).unwrap().name, "funcA");
        assert_eq!(table.resolve(0x2100).unwrap().name, "funcB");
        assert_eq!(table.resolve(0x3000).unwrap().name, "funcC");

        // In the gap between funcA and funcB
        assert!(table.resolve(0x1500).is_none());
    }

    #[test]
    fn test_code_move() {
        let data = build_jitdump(&[
            code_load_record(0x1000, 0x100, 0, "movedFunc"),
            code_move_record(0x1000, 0x5000, 0x200, 0),
        ]);
        let mut cursor = Cursor::new(data);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        assert_eq!(table.len(), 1);
        // Old address should not resolve
        assert!(table.resolve(0x1050).is_none());
        // New address should resolve
        let sym = table.resolve(0x5050).unwrap();
        assert_eq!(sym.name, "movedFunc");
        assert_eq!(sym.code_size, 0x200);
    }

    #[test]
    fn test_close_record_stops_parsing() {
        let data = build_jitdump(&[
            code_load_record(0x1000, 0x100, 0, "beforeClose"),
            close_record(),
            code_load_record(0x2000, 0x100, 1, "afterClose"),
        ]);
        let mut cursor = Cursor::new(data);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        assert_eq!(table.len(), 1);
        assert!(table.resolve(0x1050).is_some());
        assert!(table.resolve(0x2050).is_none());
    }

    #[test]
    fn test_truncated_file() {
        // Build a valid file but truncate it mid-record
        let data = build_jitdump(&[code_load_record(0x1000, 0x100, 0, "complete")]);
        let mut truncated = data.clone();
        // Append a partial second record (just the header, no payload)
        truncated.extend_from_slice(&JIT_CODE_LOAD.to_le_bytes());
        truncated.extend_from_slice(&100u32.to_le_bytes()); // total_size
                                                            // No more bytes — truncated

        let mut cursor = Cursor::new(truncated);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        // Should have the first complete symbol
        assert_eq!(table.len(), 1);
        assert_eq!(table.resolve(0x1050).unwrap().name, "complete");
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let mut cursor = Cursor::new(data);
        assert!(parse_header(&mut cursor).is_err());
    }

    #[test]
    fn test_format_jit_symbol_with_source() {
        let sym = JitSymbol {
            code_addr: 0x1000,
            code_size: 0x100,
            name: "handleRequest".to_string(),
            source: Some(("/home/user/app/server.js".to_string(), 42)),
        };
        assert_eq!(format_jit_symbol(&sym), "handleRequest (server.js:42)");
    }

    #[test]
    fn test_format_jit_symbol_without_source() {
        let sym = JitSymbol {
            code_addr: 0x1000,
            code_size: 0x100,
            name: "anonymous".to_string(),
            source: None,
        };
        assert_eq!(format_jit_symbol(&sym), "anonymous");
    }

    #[test]
    fn test_find_jitdump_nonexistent() {
        // PID 0 should never have a JITDump file
        assert!(find_jitdump_for_pid(0).is_none());
    }

    #[test]
    fn test_empty_table() {
        let data = build_jitdump(&[]);
        let mut cursor = Cursor::new(data);
        let _header = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert!(table.resolve(0x1000).is_none());
    }
}
