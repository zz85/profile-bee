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
    /// Keyed by `code_addr` — the same address `parse_debug_info` stores under
    /// and `parse_code_load` looks up (see those methods).
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
    /// the last read. Returns the number of records that mutated the table
    /// (loads and applied moves) — nonzero means a cache flush is warranted,
    /// including same-length replacements that a net symbol-count delta would
    /// miss.
    ///
    /// If the file has been truncated or rotated (size < last_read_offset),
    /// resets state and re-parses from the beginning.
    pub fn reload_from_file(&mut self, path: &Path) -> io::Result<usize> {
        let file = std::fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        // Detect truncated/rotated file — reset and re-parse from scratch.
        if file_len < self.last_read_offset {
            tracing::debug!(
                "JITDump file shrunk ({} < {}), resetting",
                file_len,
                self.last_read_offset
            );
            self.symbols.clear();
            self.pending_debug.clear();
            self.last_read_offset = 0;
        }

        // Not yet past the header (never loaded, or just reset above): parse and
        // validate the header before reading records, so header bytes are never
        // misinterpreted as a record. Keep an incompletely-written header
        // retryable — leave the offset at 0 so a later reload picks it up.
        if self.last_read_offset < JITDUMP_HEADER_SIZE {
            let mut reader = BufReader::new(file);
            match parse_header(&mut reader) {
                Ok(_) => {
                    self.last_read_offset = JITDUMP_HEADER_SIZE;
                    return self.read_records(&mut reader);
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.last_read_offset))?;

        self.read_records(&mut reader)
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
    ///
    /// Returns the number of records that mutated the symbol table (loads and
    /// applied moves). Callers use this to decide whether to flush caches —
    /// counting *mutations* rather than the net symbol-count delta so that
    /// same-length replacements (a move onto an existing address, or a reload
    /// at the same address) still register as a change.
    fn read_records<R: Read + Seek>(&mut self, reader: &mut R) -> io::Result<usize> {
        let mut mutations: usize = 0;
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
                    Ok(changed) => {
                        if changed {
                            mutations += 1;
                        }
                    }
                    Err(_) => {
                        self.last_read_offset = record_start;
                        break;
                    }
                },
                JIT_CODE_MOVE => match self.parse_code_move(reader, payload_size) {
                    Ok(changed) => {
                        if changed {
                            mutations += 1;
                        }
                    }
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
                    // Unknown record type — skip its payload. A truncated skip
                    // (partial file) is handled like any other incomplete record:
                    // rewind to the record start and stop, leaving it retryable.
                    // Unrelated I/O errors still propagate.
                    match skip_bytes(reader, payload_size) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            self.last_read_offset = record_start;
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }

            self.last_read_offset = record_start + total_size as u64;
        }

        Ok(mutations)
    }

    /// Parse a JIT_CODE_LOAD record.
    ///
    /// Fixed fields after record header:
    ///   pid(u32), tid(u32), vma(u64), code_addr(u64), code_size(u64), code_index(u64)
    /// Followed by: null-terminated function name, then raw code bytes.
    fn parse_code_load<R: Read>(&mut self, reader: &mut R, payload_size: u64) -> io::Result<bool> {
        // Fixed fields: 4 + 4 + 8 + 8 + 8 + 8 = 40 bytes
        const FIXED_SIZE: u64 = 40;
        // Upper bound on the symbol-name portion we will allocate. Real JIT
        // function names / source paths are short; this caps memory use if a
        // malformed record advertises a huge total_size (profile-bee reads
        // attacker-influenceable /tmp/jit-<pid>.dump files as root).
        const MAX_NAME_BYTES: u64 = 64 * 1024;

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
        let _code_index = read_u64(reader)?;

        // The remaining payload is the null-terminated name followed by
        // `code_size` bytes of native code. Reject records whose code_size
        // can't fit — this catches oversized/malformed sizes before we read.
        let remaining = payload_size - FIXED_SIZE;
        if code_size > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JIT_CODE_LOAD code_size exceeds record payload",
            ));
        }

        // Name occupies the bytes before the native code. Read only a bounded
        // prefix of it (never the code), so a huge advertised size can't drive
        // a huge allocation.
        let name_region = remaining - code_size;
        let name_read = name_region.min(MAX_NAME_BYTES) as usize;
        let mut name_buf = vec![0u8; name_read];
        reader.read_exact(&mut name_buf)?;

        let name_end = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_buf.len());
        let name = String::from_utf8_lossy(&name_buf[..name_end]).to_string();

        // Skip the rest of the name region (if we capped it) and the native
        // code bytes without allocating them.
        skip_bytes(reader, (name_region - name_read as u64) + code_size)?;

        // Check for pending debug info (keyed by code_addr — the same
        // address that appeared in the preceding JIT_CODE_DEBUG_INFO record)
        let source = self.pending_debug.remove(&code_addr);

        self.symbols.insert(
            code_addr,
            JitSymbol {
                code_addr,
                code_size,
                name,
                source,
            },
        );

        Ok(true)
    }

    /// Parse a JIT_CODE_MOVE record.
    ///
    /// Fixed fields (perf JITDump `jr_code_move`, 48 bytes after the header):
    ///   pid(u32), tid(u32), vma(u64), old_code_addr(u64),
    ///   new_code_addr(u64), code_size(u64), code_index(u64)
    ///
    /// Returns whether an existing symbol was actually moved.
    fn parse_code_move<R: Read>(&mut self, reader: &mut R, payload_size: u64) -> io::Result<bool> {
        const FIXED_SIZE: u64 = 48;
        if payload_size < FIXED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "JIT_CODE_MOVE too small",
            ));
        }

        let _pid = read_u32(reader)?;
        let _tid = read_u32(reader)?;
        let _vma = read_u64(reader)?;
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
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Parse a JIT_CODE_DEBUG_INFO record.
    ///
    /// Fixed fields: code_addr(u64), nr_entry(u64)
    /// Followed by array of debug entries: addr(u64), line(u32), discrim(u32),
    /// then null-terminated filename.
    ///
    /// Per spec, DEBUG_INFO must appear before its corresponding CODE_LOAD.
    /// We store the first entry's (filename, line) in pending_debug keyed by
    /// `code_addr` — the same address that will appear in the subsequent
    /// JIT_CODE_LOAD record's `code_addr` field.
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

            // Read a bounded prefix of the null-terminated filename, then skip
            // the rest of the payload. Bounding the allocation guards against a
            // malformed record advertising a huge total_size (these files come
            // from /tmp and profile-bee reads them as root).
            const MAX_FILENAME_BYTES: u64 = 64 * 1024;
            let remaining = payload_size - consumed;
            let read_len = remaining.min(MAX_FILENAME_BYTES) as usize;
            let mut buf = vec![0u8; read_len];
            reader.read_exact(&mut buf)?;

            let name_end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let filename = String::from_utf8_lossy(&buf[..name_end]).to_string();

            // Keep the reader aligned to the end of the record.
            skip_bytes(reader, remaining - read_len as u64)?;

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
    find_jitdump_for_pid_in_dir(pid, Path::new("/tmp"))
}

/// Search for a JITDump file for the given PID in the specified directory.
///
/// This is the testable core of [`find_jitdump_for_pid`], allowing tests to
/// use an isolated directory instead of the global `/tmp`.
pub fn find_jitdump_for_pid_in_dir(pid: u32, dir: &Path) -> Option<PathBuf> {
    // Standard convention: jit-<pid>.dump
    let standard = dir.join(format!("jit-{}.dump", pid));
    if standard.exists() {
        return Some(standard);
    }

    // JSC/Bun convention: jit-<tid>-<pid>-<random>
    // Scan directory for files matching this pattern.
    let pid_str = pid.to_string();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Match pattern: jit-<digits>-<pid>-<alphanum>
            // Split on '-' and verify PID is in the expected segment (index 2).
            if !name.starts_with("jit-") {
                continue;
            }
            let parts: Vec<&str> = name.splitn(4, '-').collect();
            // parts: ["jit", "<tid>", "<pid>", "<random>"]
            if parts.len() >= 4 && parts[2] == pid_str {
                return Some(entry.path());
            }
        }
    }

    None
}

/// Format a JIT symbol for display in flamegraphs.
///
/// Cleans up JSC-specific noise from the symbol name:
/// - Strips `#<hash>` suffixes (JSC JIT code version hashes, e.g. `hello#DdCypB` → `hello`)
///
/// If source file info is available: `functionName (file.js:42)`
/// Otherwise just: `functionName`
pub fn format_jit_symbol(sym: &JitSymbol) -> String {
    let name = strip_jsc_hash(&sym.name);
    if let Some((ref file, line)) = sym.source {
        let basename = Path::new(file)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(file);
        format!("{} ({}:{})", name, basename, line)
    } else {
        name.to_string()
    }
}

/// Strip JSC JIT code version hash from a symbol name.
///
/// JSC appends `#<alphanumeric>` to JIT-compiled function names to
/// disambiguate recompilations (e.g. `hello#DdCypB`, `/tmp/test.js#B9UAQK`).
/// This is internal noise that obscures the actual function name.
fn strip_jsc_hash(name: &str) -> &str {
    if let Some(pos) = name.rfind('#') {
        let suffix = &name[pos + 1..];
        // Only strip if the suffix is non-empty alphanumeric (JSC hash format)
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return &name[..pos];
        }
    }
    name
}

// ── Binary reading helpers ──────────────────────────────────────────────────

/// JITDump file header (40 bytes).
struct JitdumpHeader {
    _version: u32,
    _elf_mach: u32,
    /// PID of the process that produced the dump. Used to confirm a dump file
    /// belongs to the process being symbolized before its symbols are applied.
    pid: u32,
}

/// Read only the JITDump header and return its embedded PID.
///
/// Callers use this to reject a dump whose header PID does not match the
/// process being symbolized (defends against pid reuse / a mislabeled file)
/// before loading and applying its symbols.
pub fn read_header_pid(path: &Path) -> io::Result<u32> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    Ok(parse_header(&mut reader)?.pid)
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
        pid,
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

    /// Build a JIT_CODE_LOAD record (spec-compliant: name + `code_size` bytes
    /// of native code follow the fixed fields).
    fn code_load_record(code_addr: u64, code_size: u64, code_index: u64, name: &str) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        // fixed(40) + name + null + code_size code bytes
        let payload_size = 40 + name_bytes.len() as u32 + 1 + code_size as u32;
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

        // Native code bytes (content irrelevant — the parser skips them)
        rec.extend(std::iter::repeat_n(0xCCu8, code_size as usize));

        rec
    }

    /// Build a JIT_CODE_MOVE record (spec-compliant 48-byte payload with
    /// pid/tid/vma preceding the address fields).
    fn code_move_record(old_addr: u64, new_addr: u64, new_size: u64, code_index: u64) -> Vec<u8> {
        let total_size: u32 = 16 + 48;
        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_MOVE.to_le_bytes());
        rec.extend_from_slice(&total_size.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec.extend_from_slice(&1234u32.to_le_bytes()); // pid
        rec.extend_from_slice(&1234u32.to_le_bytes()); // tid
        rec.extend_from_slice(&new_addr.to_le_bytes()); // vma
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

    /// Build a JIT_CODE_DEBUG_INFO record with a single entry.
    fn debug_info_record(code_addr: u64, entry_addr: u64, line: u32, filename: &str) -> Vec<u8> {
        let fname = filename.as_bytes();
        // code_addr(8) + nr_entry(8) + entry[addr(8)+line(4)+discrim(4)] + name+null
        let payload_size = 16 + 16 + fname.len() as u32 + 1;
        let total_size = 16 + payload_size;
        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_DEBUG_INFO.to_le_bytes());
        rec.extend_from_slice(&total_size.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec.extend_from_slice(&code_addr.to_le_bytes());
        rec.extend_from_slice(&1u64.to_le_bytes()); // nr_entry
        rec.extend_from_slice(&entry_addr.to_le_bytes());
        rec.extend_from_slice(&line.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes()); // discriminator
        rec.extend_from_slice(fname);
        rec.push(0);
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
    fn test_read_records_reports_mutations() {
        // A load followed by a move is two mutations even though the net symbol
        // count stays at one — this is what drives cache invalidation.
        let data = build_jitdump(&[
            code_load_record(0x1000, 0x100, 0, "f"),
            code_move_record(0x1000, 0x5000, 0x100, 0),
        ]);
        let mut cursor = Cursor::new(data);
        let _ = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        let mutations = table.read_records(&mut cursor).unwrap();
        assert_eq!(mutations, 2, "load + move should count as two mutations");
        assert_eq!(table.len(), 1);
        assert!(table.resolve(0x5050).is_some());
    }

    #[test]
    fn test_code_load_oversized_code_size_rejected() {
        // A JIT_CODE_LOAD whose code_size far exceeds the record payload must be
        // rejected without loading a symbol (and without a huge allocation),
        // rather than trusting the advertised size.
        let name = b"evil\0";
        let payload_size = 40u32 + name.len() as u32; // fixed fields + name, no code
        let total_size = 16 + payload_size;
        let mut rec = Vec::new();
        rec.extend_from_slice(&JIT_CODE_LOAD.to_le_bytes());
        rec.extend_from_slice(&total_size.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec.extend_from_slice(&1234u32.to_le_bytes()); // pid
        rec.extend_from_slice(&1234u32.to_le_bytes()); // tid
        rec.extend_from_slice(&0x1000u64.to_le_bytes()); // vma
        rec.extend_from_slice(&0x1000u64.to_le_bytes()); // code_addr
        rec.extend_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // code_size (bogus)
        rec.extend_from_slice(&0u64.to_le_bytes()); // code_index
        rec.extend_from_slice(name);

        let data = build_jitdump(&[rec]);
        let mut cursor = Cursor::new(data);
        let _ = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        // Stops cleanly; no symbol loaded.
        table.read_records(&mut cursor).unwrap();
        assert_eq!(table.len(), 0);
        assert!(table.resolve(0x1000).is_none());
    }

    #[test]
    fn test_debug_info_populates_source_and_format() {
        // DEBUG_INFO precedes its CODE_LOAD (per spec); the loaded symbol should
        // carry the (file, line) and format_jit_symbol should render it.
        let data = build_jitdump(&[
            debug_info_record(0x1000, 0x1000, 42, "app/server.js"),
            code_load_record(0x1000, 0x100, 0, "handleRequest"),
        ]);
        let mut cursor = Cursor::new(data);
        let _ = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        table.read_records(&mut cursor).unwrap();

        let sym = table.resolve(0x1050).unwrap();
        assert_eq!(sym.source, Some(("app/server.js".to_string(), 42)));
        assert_eq!(format_jit_symbol(sym), "handleRequest (server.js:42)");
    }

    #[test]
    fn test_debug_info_oversized_rejected() {
        // A DEBUG_INFO advertising a huge payload but with a short body must be
        // handled without a giant allocation: the bounded filename read hits EOF
        // and parsing stops cleanly rather than allocating the advertised size.
        let mut rec = Vec::new();
        let huge_payload: u32 = 512 * 1024 * 1024; // advertise 512 MiB
        let total_size = 16 + huge_payload;
        rec.extend_from_slice(&JIT_CODE_DEBUG_INFO.to_le_bytes());
        rec.extend_from_slice(&total_size.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        rec.extend_from_slice(&0x1000u64.to_le_bytes()); // code_addr
        rec.extend_from_slice(&1u64.to_le_bytes()); // nr_entry
        rec.extend_from_slice(&0x1000u64.to_le_bytes()); // entry addr
        rec.extend_from_slice(&7u32.to_le_bytes()); // line
        rec.extend_from_slice(&0u32.to_le_bytes()); // discriminator
        rec.extend_from_slice(b"short.js\0"); // real body is tiny (truncated vs advertised)

        let data = build_jitdump(&[rec]);
        let mut cursor = Cursor::new(data);
        let _ = parse_header(&mut cursor).unwrap();
        let mut table = JitSymbolTable {
            symbols: BTreeMap::new(),
            pending_debug: HashMap::new(),
            last_read_offset: JITDUMP_HEADER_SIZE,
        };
        // Returns cleanly; no code loaded (only a truncated debug-info record).
        assert!(table.read_records(&mut cursor).is_ok());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_reload_incremental_and_shrink() {
        let dir = std::env::temp_dir().join("jitdump_test_reload");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("jit-reload-{}.dump", std::process::id()));

        // Initial file: header + one symbol.
        let initial = build_jitdump(&[code_load_record(0x1000, 0x100, 0, "first")]);
        std::fs::write(&path, &initial).unwrap();
        let mut table = JitSymbolTable::load_from_file(&path).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.resolve(0x1050).is_some());

        // Append a second record; incremental reload reads only the new one.
        let mut appended = initial.clone();
        appended.extend_from_slice(&code_load_record(0x2000, 0x100, 1, "second"));
        std::fs::write(&path, &appended).unwrap();
        let mutations = table.reload_from_file(&path).unwrap();
        assert_eq!(mutations, 1, "only the appended record should be read");
        assert_eq!(table.len(), 2);
        assert!(table.resolve(0x2050).is_some());

        // Shrink/rotate the file: reload resets and re-parses from scratch.
        let shrunk = build_jitdump(&[code_load_record(0x3000, 0x100, 0, "third")]);
        std::fs::write(&path, &shrunk).unwrap();
        table.reload_from_file(&path).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.resolve(0x3050).is_some());
        assert!(table.resolve(0x1050).is_none());

        let _ = std::fs::remove_file(&path);
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
            name: "handleRequest#AbCdEf".to_string(),
            source: Some(("/home/user/app/server.js".to_string(), 42)),
        };
        assert_eq!(format_jit_symbol(&sym), "handleRequest (server.js:42)");
    }

    #[test]
    fn test_format_jit_symbol_without_source() {
        let sym = JitSymbol {
            code_addr: 0x1000,
            code_size: 0x100,
            name: "hello#DdCypB".to_string(),
            source: None,
        };
        assert_eq!(format_jit_symbol(&sym), "hello");
    }

    #[test]
    fn test_format_jit_symbol_no_hash() {
        let sym = JitSymbol {
            code_addr: 0x1000,
            code_size: 0x100,
            name: "anonymous".to_string(),
            source: None,
        };
        assert_eq!(format_jit_symbol(&sym), "anonymous");
    }

    #[test]
    fn test_strip_jsc_hash() {
        assert_eq!(strip_jsc_hash("hello#DdCypB"), "hello");
        assert_eq!(strip_jsc_hash("/tmp/test.js#B9UAQK"), "/tmp/test.js");
        assert_eq!(strip_jsc_hash("no_hash"), "no_hash");
        // Don't strip if suffix contains non-alphanumeric
        assert_eq!(strip_jsc_hash("color#ff-00"), "color#ff-00");
    }

    #[test]
    fn test_find_jitdump_nonexistent() {
        // Use an isolated temp directory so stale files in /tmp can't cause false failures
        let dir = std::env::temp_dir().join("jitdump_test_nonexistent");
        let _ = std::fs::create_dir_all(&dir);
        // Clean any leftovers from previous test runs
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
        assert!(find_jitdump_for_pid_in_dir(99999, &dir).is_none());
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_find_jitdump_standard_convention() {
        let dir = std::env::temp_dir().join("jitdump_test_standard");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jit-1234.dump");
        std::fs::write(&path, b"dummy").unwrap();
        let found = find_jitdump_for_pid_in_dir(1234, &dir);
        assert_eq!(found, Some(path.clone()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_find_jitdump_jsc_convention() {
        let dir = std::env::temp_dir().join("jitdump_test_jsc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jit-5678-1234-AbCdEf");
        std::fs::write(&path, b"dummy").unwrap();
        let found = find_jitdump_for_pid_in_dir(1234, &dir);
        assert_eq!(found, Some(path.clone()));
        // Verify it doesn't match wrong PID
        assert!(find_jitdump_for_pid_in_dir(5678, &dir).is_none());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
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
