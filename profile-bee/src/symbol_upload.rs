//! Background binary uploader for the symbol server.
//!
//! Discovers ELF binaries from `/proc/<pid>/maps` during profiling and
//! uploads them to a symbol-server instance for devfiler symbolization.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Handle for sending binary paths to the uploader task.
#[derive(Clone)]
pub struct SymbolUploader {
    tx: mpsc::UnboundedSender<PathBuf>,
}

impl SymbolUploader {
    /// Spawn a background uploader task that POSTs binaries to the symbol server.
    ///
    /// Returns a handle that can be used to submit binary paths for upload.
    pub fn spawn(symbol_server_url: String, runtime: tokio::runtime::Handle) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let uploader = Self { tx };

        runtime.spawn(upload_loop(symbol_server_url, rx));

        uploader
    }

    /// Submit a binary path for upload. Non-blocking, deduplicates automatically.
    pub fn upload(&self, path: PathBuf) {
        let _ = self.tx.send(path);
    }

    /// Discover and upload all executable mappings for a given PID.
    pub fn upload_for_pid(&self, pid: u32) {
        let maps_path = format!("/proc/{}/maps", pid);
        let Ok(contents) = std::fs::read_to_string(&maps_path) else {
            return;
        };

        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            let _range = parts.next();
            let Some(perms) = parts.next() else { continue };
            if !perms.contains('x') {
                continue;
            }
            let _offset = parts.next();
            let _dev = parts.next();
            let _inode = parts.next();
            let Some(pathname) = parts.next() else {
                continue;
            };
            if pathname.starts_with('[') || pathname.is_empty() {
                continue;
            }
            let path = PathBuf::from(pathname);
            if path.exists() {
                self.upload(path);
            }
        }
    }

    /// Scan all running processes and upload their executable mappings.
    /// Iterates /proc/*/maps for every PID visible on the system.
    pub fn upload_all_processes(&self) {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };

        let mut pids_scanned = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };
            self.upload_for_pid(pid);
            pids_scanned += 1;
        }

        eprintln!(
            "symbol uploader: scanned {} processes for binaries",
            pids_scanned
        );
    }
}

/// Background upload loop — deduplicates and POSTs binaries to the symbol server.
async fn upload_loop(server_url: String, mut rx: mpsc::UnboundedReceiver<PathBuf>) {
    let uploaded: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let client = reqwest::Client::new();

    eprintln!("symbol uploader: started, server={}", server_url);

    while let Some(path) = rx.recv().await {
        // Deduplicate
        {
            let mut set = uploaded.lock();
            if set.contains(&path) {
                continue;
            }
            set.insert(path.clone());
        }

        // Read binary
        let data = match tokio::fs::read(&path).await {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("symbol uploader: cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        // Skip tiny files (unlikely to be real executables)
        if data.len() < 64 {
            continue;
        }

        // Verify ELF magic
        if &data[..4] != b"\x7fELF" {
            continue;
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let url = format!("{}/upload?filename={}", server_url, urlencoding(filename));

        eprintln!(
            "symbol uploader: uploading {} ({} bytes)",
            path.display(),
            data.len()
        );

        match client
            .post(&url)
            .body(data)
            .header("content-type", "application/octet-stream")
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!("symbol uploader: uploaded {} -> {}", path.display(), body);
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!(
                        "symbol uploader: server returned {} for {}: {}",
                        status,
                        path.display(),
                        body
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "symbol uploader: failed to upload {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }
}

/// Simple percent-encoding for filenames in URLs.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}
