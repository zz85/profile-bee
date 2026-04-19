//! On-disk symbol store — caches processed symbfiles keyed by FileId.

use crate::fileid::FileId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Metadata about a stored symbol file.
#[derive(Clone, Debug)]
pub struct SymbolEntry {
    pub file_id: FileId,
    pub filename: String,
    pub num_symbols: usize,
}

/// On-disk + in-memory symbol store.
pub struct SymbolStore {
    dir: PathBuf,
    /// In-memory index of known FileIds -> metadata
    index: Arc<RwLock<HashMap<FileId, SymbolEntry>>>,
}

impl SymbolStore {
    pub fn new(dir: &str) -> anyhow::Result<Self> {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)?;

        let store = Self {
            dir,
            index: Arc::new(RwLock::new(HashMap::new())),
        };

        // Scan existing files to rebuild index
        store.rebuild_index();

        Ok(store)
    }

    /// Get the directory path for a given FileId.
    fn id_dir(&self, id: &FileId) -> PathBuf {
        let es = id.format_es();
        self.dir.join(&es[0..2]).join(&es[2..4]).join(&es)
    }

    /// Store a processed symbfile for a given FileId.
    pub fn store_symbfile(
        &self,
        id: FileId,
        ranges_data: &[u8],
        filename: &str,
        num_symbols: usize,
    ) -> anyhow::Result<()> {
        let dir = self.id_dir(&id);
        std::fs::create_dir_all(&dir)?;

        // Write ranges file atomically (temp + rename)
        let ranges_tmp = dir.join("ranges.tmp");
        std::fs::write(&ranges_tmp, ranges_data)?;
        std::fs::rename(&ranges_tmp, dir.join("ranges"))?;

        // Write metadata.json atomically
        let metadata = serde_json::json!({
            "version": 1,
            "symbolFileReferences": {
                "dwarfFileID": id.format_es()
            }
        });
        let meta_tmp = dir.join("metadata.json.tmp");
        std::fs::write(&meta_tmp, metadata.to_string())?;
        std::fs::rename(&meta_tmp, dir.join("metadata.json"))?;

        // Update index
        let entry = SymbolEntry {
            file_id: id,
            filename: filename.to_string(),
            num_symbols,
        };
        self.index.write().insert(id, entry);

        tracing::info!(
            "stored {} symbols for {} (FileId: {})",
            num_symbols,
            filename,
            id
        );
        Ok(())
    }

    /// Check if we have symbols for a given FileId.
    pub fn has_symbols(&self, id: &FileId) -> bool {
        self.index.read().contains_key(id)
    }

    /// Get the metadata.json content for a FileId.
    pub fn get_metadata(&self, id: &FileId) -> Option<String> {
        let dir = self.id_dir(id);
        std::fs::read_to_string(dir.join("metadata.json")).ok()
    }

    /// Get the ranges file content for a FileId.
    pub fn get_ranges(&self, id: &FileId) -> Option<Vec<u8>> {
        let dir = self.id_dir(id);
        std::fs::read(dir.join("ranges")).ok()
    }

    /// Rebuild index from existing files on disk.
    fn rebuild_index(&self) {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                // Walk two levels down (xx/yy/full_id/)
                if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                    for sub in sub_entries.flatten() {
                        if let Ok(id_entries) = std::fs::read_dir(sub.path()) {
                            for id_entry in id_entries.flatten() {
                                let id_path = id_entry.path();
                                if id_path.join("ranges").exists()
                                    && id_path.join("metadata.json").exists()
                                {
                                    let id_str = id_entry.file_name();
                                    if let Ok(id) = FileId::parse_es(id_str.to_str().unwrap_or(""))
                                    {
                                        self.index.write().insert(
                                            id,
                                            SymbolEntry {
                                                file_id: id,
                                                filename: String::new(),
                                                num_symbols: 0,
                                            },
                                        );
                                        count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if count > 0 {
            tracing::info!("loaded {} cached symbol entries from disk", count);
        }
    }

    /// List all stored entries.
    pub fn list(&self) -> Vec<SymbolEntry> {
        self.index.read().values().cloned().collect()
    }
}
