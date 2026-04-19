//! FileId (htlhash) computation — compatible with devfiler/elastic's format.
//!
//! Algorithm: SHA-256(first_4096_bytes || last_4096_bytes || big_endian_u64_length)[0:16]
//! Serialized as URL-safe base64 without padding (for URL paths) or hex (for display).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const PARTIAL_HASH_SIZE: u64 = 4096;

/// 128-bit file identity hash, compatible with devfiler's FileId.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u128);

impl FileId {
    /// Compute the FileId (htlhash) from an open file handle.
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> anyhow::Result<Self> {
        // Get file length
        let file_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        let mut hasher = Sha256::new();

        // Hash the first min(4096, file_len) bytes (head)
        let head_size = file_len.min(PARTIAL_HASH_SIZE) as usize;
        let mut head_buf = vec![0u8; head_size];
        reader.read_exact(&mut head_buf)?;
        hasher.update(&head_buf);

        // Hash the last min(4096, file_len) bytes (tail)
        let tail_start = file_len.saturating_sub(PARTIAL_HASH_SIZE);
        reader.seek(SeekFrom::Start(tail_start))?;
        let tail_size = (file_len - tail_start) as usize;
        let mut tail_buf = vec![0u8; tail_size];
        reader.read_exact(&mut tail_buf)?;
        hasher.update(&tail_buf);

        // Hash file length as big-endian u64
        hasher.update(file_len.to_be_bytes());

        // Finalize and truncate to 128 bits
        let digest = hasher.finalize();
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&digest[..16]);
        Ok(FileId(u128::from_be_bytes(id_bytes)))
    }

    /// Compute the FileId from a file path.
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        Self::from_reader(&mut file)
    }

    /// Format as URL-safe base64 without padding (devfiler "ES" format).
    pub fn format_es(&self) -> String {
        let bytes = self.0.to_be_bytes();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Format as lowercase 32-char hex string.
    pub fn format_hex(&self) -> String {
        format!("{:032x}", self.0)
    }

    /// Parse from URL-safe base64 (ES format).
    pub fn parse_es(s: &str) -> anyhow::Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        if bytes.len() != 16 {
            anyhow::bail!("invalid FileId length: expected 16 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(FileId(u128::from_be_bytes(arr)))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_es())
    }
}

impl std::fmt::Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileId({})", self.format_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_small_file() {
        // 123 zero bytes should produce a known FileId
        let data = vec![0u8; 123];
        let mut cursor = Cursor::new(data);
        let id = FileId::from_reader(&mut cursor).unwrap();
        // Verify it produces a valid 128-bit hash
        assert_ne!(id.0, 0);
        // Verify round-trip through ES format
        let es = id.format_es();
        let parsed = FileId::parse_es(&es).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_large_file() {
        // File larger than 8192 bytes: head and tail don't overlap
        let data = vec![0xAB; 16384];
        let mut cursor = Cursor::new(data);
        let id = FileId::from_reader(&mut cursor).unwrap();
        assert_ne!(id.0, 0);
    }

    #[test]
    fn test_es_format_roundtrip() {
        let id = FileId(0xc34f3585fca1b579fb458e827851a599);
        let es = id.format_es();
        assert_eq!(es, "w081hfyhtXn7RY6CeFGlmQ");
        let parsed = FileId::parse_es(&es).unwrap();
        assert_eq!(id, parsed);
    }
}
