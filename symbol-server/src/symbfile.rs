//! Symbfile writer — produces the devfiler-compatible symbol file format.
//!
//! Format: zstd-compressed stream of ULEB128-prefixed protobuf messages.
//! ```text
//! [8 bytes "symbfile" magic]
//! [ULEB128 len][ULEB128 type=1][protobuf Header]
//! [ULEB128 len][ULEB128 type=4][protobuf StringTableV1]  (optional)
//! [ULEB128 len][ULEB128 type=2][protobuf RangeV1]
//! [ULEB128 len][ULEB128 type=2][protobuf RangeV1]
//! ...
//! ```

use crate::extract::SymbolRange;
use prost::Message;
use std::io::Write;

const MAGIC: &[u8; 8] = b"symbfile";
const MT_HEADER: u32 = 1;
const MT_RANGE_V1: u32 = 2;
const MT_STRING_TABLE_V1: u32 = 4;

// Hand-written prost message structs matching symbfile.proto

/// Header message (currently empty, must be first after magic)
#[derive(Clone, PartialEq, Message)]
struct Header {}

/// A single function range record.
#[derive(Clone, PartialEq, Message)]
struct RangeV1 {
    /// Length of the function
    #[prost(uint64, tag = "2")]
    length: u64,
    /// Function name (inline string for unique names)
    #[prost(string, optional, tag = "3")]
    func_str: Option<String>,
    /// Function name (string table reference)
    #[prost(uint32, optional, tag = "9")]
    func_ref: Option<u32>,
    /// Source file (inline string)
    #[prost(string, optional, tag = "4")]
    file_str: Option<String>,
    /// Source file (string table reference)
    #[prost(uint32, optional, tag = "10")]
    file_ref: Option<u32>,
    /// Inline depth (0 = top-level)
    #[prost(uint32, tag = "7")]
    depth: u32,
    /// ELF virtual address - either absolute (first record) or delta (subsequent)
    #[prost(oneof = "range_v1::ElfVa", tags = "1, 12")]
    elf_va: Option<range_v1::ElfVa>,
}

pub mod range_v1 {
    /// Oneof for ELF VA: either delta (relative) or absolute (set).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ElfVa {
        /// Delta from previous record's ELF VA (sint64, zigzag encoded)
        #[prost(sint64, tag = "1")]
        DeltaElfVa(i64),
        /// Absolute ELF VA — used for the first record to establish baseline.
        #[prost(uint64, tag = "12")]
        SetElfVa(u64),
    }
}

/// String table message — replaces the reader's current table.
#[derive(Clone, PartialEq, Message)]
struct StringTableV1 {
    #[prost(string, repeated, tag = "1")]
    strings: Vec<String>,
}

/// Write symbols as a zstd-compressed symbfile.
pub fn write_symbfile(symbols: &[SymbolRange]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut encoder = zstd::Encoder::new(&mut output, 3)?;
        write_symbfile_inner(&mut encoder, symbols)?;
        encoder.finish()?;
    }
    Ok(output)
}

fn write_symbfile_inner<W: Write>(w: &mut W, symbols: &[SymbolRange]) -> anyhow::Result<()> {
    // Write magic
    w.write_all(MAGIC)?;

    // Write header (empty, type=1)
    let header = Header {};
    write_message(w, MT_HEADER, &header)?;

    // Build string table for repeated strings
    let mut string_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for sym in symbols {
        *string_counts.entry(&sym.name).or_default() += 1;
        if let Some(ref f) = sym.file {
            *string_counts.entry(f.as_str()).or_default() += 1;
        }
    }

    // Strings that appear more than once go in the string table
    let mut string_table: Vec<String> = Vec::new();
    let mut string_index: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (s, count) in &string_counts {
        if *count > 1 {
            let idx = string_table.len() as u32;
            string_table.push(s.to_string());
            string_index.insert(s.to_string(), idx);
        }
    }

    // Write string table if non-empty
    if !string_table.is_empty() {
        let st = StringTableV1 {
            strings: string_table,
        };
        write_message(w, MT_STRING_TABLE_V1, &st)?;
    }

    // Write range records: first uses absolute VA, rest use delta encoding
    let mut prev_va: i64 = 0;
    let mut is_first = true;
    for sym in symbols {
        let elf_va = if is_first {
            is_first = false;
            prev_va = sym.elf_va as i64;
            Some(range_v1::ElfVa::SetElfVa(sym.elf_va))
        } else {
            let delta = sym.elf_va as i64 - prev_va;
            prev_va = sym.elf_va as i64;
            Some(range_v1::ElfVa::DeltaElfVa(delta))
        };

        let (func_str, func_ref) = if let Some(&idx) = string_index.get(&sym.name) {
            (None, Some(idx))
        } else {
            (Some(sym.name.clone()), None)
        };

        let (file_str, file_ref) = if let Some(ref f) = sym.file {
            if let Some(&idx) = string_index.get(f.as_str()) {
                (None, Some(idx))
            } else {
                (Some(f.clone()), None)
            }
        } else {
            (None, None)
        };

        let range = RangeV1 {
            length: sym.length,
            func_str,
            func_ref,
            file_str,
            file_ref,
            depth: 0,
            elf_va,
        };
        write_message(w, MT_RANGE_V1, &range)?;
    }

    Ok(())
}

/// Write a single ULEB128-prefixed protobuf message.
///
/// Format: [ULEB128 body_length] [ULEB128 msg_type] [protobuf body]
/// The length field is the size of the protobuf body ONLY (excludes the type varint).
fn write_message<W: Write, M: Message>(w: &mut W, msg_type: u32, msg: &M) -> anyhow::Result<()> {
    let encoded = msg.encode_to_vec();
    write_uleb128(w, encoded.len() as u32)?; // body length only
    write_uleb128(w, msg_type)?;              // message type
    w.write_all(&encoded)?;                   // protobuf body
    Ok(())
}

/// Encode a u32 as ULEB128 bytes.
fn encode_uleb128(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
    bytes
}

/// Write a ULEB128-encoded u32 to the writer.
fn write_uleb128<W: Write>(w: &mut W, value: u32) -> std::io::Result<()> {
    let bytes = encode_uleb128(value);
    w.write_all(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_symbols() {
        let result = write_symbfile(&[]).unwrap();
        assert!(!result.is_empty()); // at least magic + header
    }

    #[test]
    fn test_single_symbol() {
        let symbols = vec![SymbolRange {
            elf_va: 0x1000,
            length: 64,
            name: "main".to_string(),
            file: None,
        }];
        let result = write_symbfile(&symbols).unwrap();
        assert!(!result.is_empty());

        // Decompress and verify magic
        let decompressed = zstd::decode_all(result.as_slice()).unwrap();
        assert_eq!(&decompressed[..8], MAGIC);
    }

    #[test]
    fn test_uleb128_encoding() {
        assert_eq!(encode_uleb128(0), vec![0]);
        assert_eq!(encode_uleb128(1), vec![1]);
        assert_eq!(encode_uleb128(127), vec![127]);
        assert_eq!(encode_uleb128(128), vec![0x80, 0x01]);
        assert_eq!(encode_uleb128(300), vec![0xAC, 0x02]);
    }
}
