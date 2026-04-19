//! Embedded symbol server — runs inside the profile-bee process.
//!
//! When `--symbol-server-listen <port>` is passed, profile-bee starts a local
//! HTTP server that serves symbols in devfiler-compatible format. This combines
//! the profiler and symbol server into a single process for simpler debugging
//! and development workflows.
//!
//! Uses the same `profile-bee-symbols` crate as the standalone `symbol-server` binary.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Atomic counter for unique temp file names across concurrent requests.
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use parking_lot::RwLock;

use profile_bee_symbols::extract;
use profile_bee_symbols::fileid::FileId;

/// Stored symbol entry metadata.
struct SymbolEntry {
    file_id: FileId,
    filename: String,
    num_symbols: usize,
    ranges_data: Vec<u8>,
    metadata_json: String,
}

/// In-memory symbol store for the embedded server.
struct EmbeddedStore {
    entries: RwLock<HashMap<FileId, Arc<SymbolEntry>>>,
}

impl EmbeddedStore {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }
}

type AppState = Arc<EmbeddedStore>;

/// Start the embedded symbol server on the given port.
/// Returns a oneshot receiver that is signaled once the server has bound.
pub fn spawn_embedded_server(
    port: u16,
    runtime: tokio::runtime::Handle,
) -> tokio::sync::oneshot::Receiver<()> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        let state: AppState = Arc::new(EmbeddedStore::new());

        let app = Router::new()
            .route("/upload", post(handle_upload))
            .route("/status", get(handle_status))
            .route("/:a/:b/:id/metadata.json", get(handle_metadata))
            .route("/:a/:b/:id/ranges", get(handle_ranges))
            .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
            .with_state(state);

        let addr = format!("127.0.0.1:{}", port);
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("embedded symbol-server: failed to bind {}: {}", addr, e);
                return;
            }
        };
        eprintln!("embedded symbol-server: listening on {}", addr);
        let _ = ready_tx.send(());
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("embedded symbol-server: error: {}", e);
        }
    });
    ready_rx
}

/// Handle binary upload.
async fn handle_upload(
    State(store): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    body: Bytes,
) -> impl IntoResponse {
    let filename = params
        .get("filename")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    // Compute FileId
    let mut cursor = std::io::Cursor::new(&body[..]);
    let file_id = match FileId::from_reader(&mut cursor) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("failed to compute FileId: {}", e),
            )
                .into_response();
        }
    };

    // Check if already processed
    if store.entries.read().contains_key(&file_id) {
        return Json(serde_json::json!({
            "status": "already_exists",
            "file_id": file_id.format_es(),
            "file_id_hex": file_id.format_hex(),
        }))
        .into_response();
    }

    // Move blocking I/O and CPU-heavy extraction into a blocking task
    let result = tokio::task::spawn_blocking(
        move || -> Result<(Vec<extract::SymbolRange>, Vec<u8>), (StatusCode, String)> {
            // Write to per-request unique temp file
            let nonce = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp_path = std::env::temp_dir().join(format!(
                "probee-symb-{}-{}-{}.elf",
                file_id.format_hex(),
                std::process::id(),
                nonce
            ));
            if let Err(e) = std::fs::write(&tmp_path, &body) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to write temp file: {}", e),
                ));
            }

            let symbols = match extract::extract_symbols(&tmp_path) {
                Ok(s) => s,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("failed to extract symbols: {}", e),
                    ));
                }
            };
            let _ = std::fs::remove_file(&tmp_path);

            if symbols.is_empty() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "no symbols found in binary".to_string(),
                ));
            }

            let ranges_data = match write_symbfile(&symbols) {
                Ok(d) => d,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to generate symbfile: {}", e),
                    ));
                }
            };

            Ok((symbols, ranges_data))
        },
    )
    .await;

    let (symbols, ranges_data) = match result {
        Ok(Ok(data)) => data,
        Ok(Err((status, msg))) => return (status, msg).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn_blocking failed: {}", e),
            )
                .into_response()
        }
    };

    let num_symbols = symbols.len();
    let metadata_json = serde_json::json!({
        "version": 1,
        "symbolFileReferences": {
            "dwarfFileID": file_id.format_es()
        }
    })
    .to_string();

    let entry = Arc::new(SymbolEntry {
        file_id,
        filename: filename.clone(),
        num_symbols,
        ranges_data: ranges_data.clone(),
        metadata_json,
    });

    store.entries.write().insert(file_id, entry);

    eprintln!(
        "embedded symbol-server: stored {} symbols for {} ({})",
        num_symbols,
        filename,
        file_id.format_hex()
    );

    Json(serde_json::json!({
        "status": "ok",
        "file_id": file_id.format_es(),
        "file_id_hex": file_id.format_hex(),
        "num_symbols": num_symbols,
        "ranges_size": ranges_data.len(),
    }))
    .into_response()
}

/// Metadata endpoint.
async fn handle_metadata(
    State(store): State<AppState>,
    Path((_a, _b, id_str)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let file_id = match FileId::parse_es(&id_str) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match store.entries.read().get(&file_id) {
        Some(entry) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            entry.metadata_json.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Ranges endpoint.
async fn handle_ranges(
    State(store): State<AppState>,
    Path((_a, _b, id_str)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let file_id = match FileId::parse_es(&id_str) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match store.entries.read().get(&file_id) {
        Some(entry) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            entry.ranges_data.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Status endpoint.
async fn handle_status(State(store): State<AppState>) -> impl IntoResponse {
    let entries = store.entries.read();
    let items: Vec<serde_json::Value> = entries
        .values()
        .map(|e| {
            serde_json::json!({
                "file_id": e.file_id.format_es(),
                "file_id_hex": e.file_id.format_hex(),
                "filename": e.filename,
                "num_symbols": e.num_symbols,
            })
        })
        .collect();

    Json(serde_json::json!({
        "count": items.len(),
        "entries": items,
    }))
}

// ---------------------------------------------------------------------------
// Inline symbfile writer (same logic as symbol-server crate)
// ---------------------------------------------------------------------------

use prost::Message;
use std::io::Write;

const MAGIC: &[u8; 8] = b"symbfile";
const MT_HEADER: u32 = 1;
const MT_RANGE_V1: u32 = 2;
const MT_STRING_TABLE_V1: u32 = 4;

#[derive(Clone, PartialEq, Message)]
struct Header {}

#[derive(Clone, PartialEq, Message)]
struct RangeV1 {
    #[prost(uint64, tag = "2")]
    length: u64,
    #[prost(string, optional, tag = "3")]
    func_str: Option<String>,
    #[prost(uint32, optional, tag = "9")]
    func_ref: Option<u32>,
    #[prost(string, optional, tag = "4")]
    file_str: Option<String>,
    #[prost(uint32, optional, tag = "10")]
    file_ref: Option<u32>,
    #[prost(uint32, tag = "7")]
    depth: u32,
    #[prost(oneof = "range_v1::ElfVa", tags = "1, 12")]
    elf_va: Option<range_v1::ElfVa>,
}

mod range_v1 {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ElfVa {
        #[prost(sint64, tag = "1")]
        DeltaElfVa(i64),
        #[prost(uint64, tag = "12")]
        SetElfVa(u64),
    }
}

#[derive(Clone, PartialEq, Message)]
struct StringTableV1 {
    #[prost(string, repeated, tag = "1")]
    strings: Vec<String>,
}

fn write_symbfile(symbols: &[extract::SymbolRange]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut encoder = zstd::Encoder::new(&mut output, 3)?;
        write_symbfile_inner(&mut encoder, symbols)?;
        encoder.finish()?;
    }
    Ok(output)
}

fn write_symbfile_inner<W: Write>(
    w: &mut W,
    symbols: &[extract::SymbolRange],
) -> anyhow::Result<()> {
    w.write_all(MAGIC)?;
    write_message(w, MT_HEADER, &Header {})?;

    // String table for repeated strings
    let mut string_counts: HashMap<&str, usize> = HashMap::new();
    for sym in symbols {
        *string_counts.entry(&sym.name).or_default() += 1;
        if let Some(ref f) = sym.file {
            *string_counts.entry(f.as_str()).or_default() += 1;
        }
    }
    let mut string_table: Vec<String> = Vec::new();
    let mut string_index: HashMap<String, u32> = HashMap::new();
    for (s, count) in &string_counts {
        if *count > 1 {
            let idx = string_table.len() as u32;
            string_table.push(s.to_string());
            string_index.insert(s.to_string(), idx);
        }
    }
    if !string_table.is_empty() {
        write_message(
            w,
            MT_STRING_TABLE_V1,
            &StringTableV1 {
                strings: string_table,
            },
        )?;
    }

    // Range records
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

        write_message(
            w,
            MT_RANGE_V1,
            &RangeV1 {
                length: sym.length,
                func_str,
                func_ref,
                file_str,
                file_ref,
                depth: 0,
                elf_va,
            },
        )?;
    }
    Ok(())
}

fn write_message<W: Write, M: Message>(w: &mut W, msg_type: u32, msg: &M) -> anyhow::Result<()> {
    let encoded = msg.encode_to_vec();
    write_uleb128(w, encoded.len() as u32)?;
    write_uleb128(w, msg_type)?;
    w.write_all(&encoded)?;
    Ok(())
}

fn write_uleb128<W: Write>(w: &mut W, mut value: u32) -> std::io::Result<()> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        w.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}
