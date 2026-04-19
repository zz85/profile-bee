//! HTTP server — serves devfiler-compatible symbol endpoints and accepts uploads.
//!
//! Endpoints:
//! - `POST /upload`         — Accept an ELF binary, compute FileId, extract symbols, store
//! - `GET /:a/:b/:id/metadata.json` — devfiler auto-fetch: metadata
//! - `GET /:a/:b/:id/ranges`        — devfiler auto-fetch: zstd-compressed symbfile
//! - `GET /status`          — List stored symbols

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use crate::extract;
use crate::fileid::FileId;
use crate::store::SymbolStore;
use crate::symbfile;

type AppState = Arc<SymbolStore>;

pub async fn run(store: SymbolStore, bind: &str, port: u16) -> anyhow::Result<()> {
    let state: AppState = Arc::new(store);

    let app = Router::new()
        .route("/upload", post(handle_upload))
        .route("/status", get(handle_status))
        // Devfiler-compatible endpoints: /{prefix1}/{prefix2}/{id}/metadata.json
        .route("/:a/:b/:id/metadata.json", get(handle_metadata))
        .route("/:a/:b/:id/ranges", get(handle_ranges))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB limit for binary uploads
        .with_state(state);

    let addr = format!("{}:{}", bind, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Handle binary upload from profile-bee.
///
/// Accepts raw ELF binary in request body. Computes FileId, extracts symbols,
/// generates symbfile, and stores it.
///
/// Optional query param: ?filename=<name> for display purposes.
async fn handle_upload(
    State(store): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> impl IntoResponse {
    let filename = params
        .get("filename")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    tracing::info!("upload: received {} bytes for '{}'", body.len(), filename);

    // Compute FileId from the binary data
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
    if store.has_symbols(&file_id) {
        tracing::info!(
            "upload: {} already processed (FileId: {})",
            filename,
            file_id
        );
        return Json(serde_json::json!({
            "status": "already_exists",
            "file_id": file_id.format_es(),
            "file_id_hex": file_id.format_hex(),
        }))
        .into_response();
    }

    // Write to temp file for object crate to parse
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("symbol-server-{}.elf", file_id.format_hex()));
    if let Err(e) = std::fs::write(&tmp_path, &body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write temp file: {}", e),
        )
            .into_response();
    }

    // Extract symbols
    let symbols = match extract::extract_symbols(&tmp_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            tracing::warn!("upload: failed to extract symbols from '{}': {}", filename, e);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("failed to extract symbols: {}", e),
            )
                .into_response();
        }
    };
    let _ = std::fs::remove_file(&tmp_path);

    if symbols.is_empty() {
        tracing::warn!("upload: no symbols found in '{}'", filename);
        return (StatusCode::UNPROCESSABLE_ENTITY, "no symbols found in binary").into_response();
    }

    // Generate symbfile
    let ranges_data = match symbfile::write_symbfile(&symbols) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to generate symbfile: {}", e),
            )
                .into_response();
        }
    };

    // Store
    let num_symbols = symbols.len();
    if let Err(e) = store.store_symbfile(file_id, &ranges_data, &filename, num_symbols) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store: {}", e),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "status": "ok",
        "file_id": file_id.format_es(),
        "file_id_hex": file_id.format_hex(),
        "num_symbols": num_symbols,
        "ranges_size": ranges_data.len(),
    }))
    .into_response()
}

/// Devfiler-compatible metadata endpoint.
async fn handle_metadata(
    State(store): State<AppState>,
    Path((_a, _b, id_str)): Path<(String, String, String)>,
) -> impl IntoResponse {
    tracing::info!("GET metadata: id_str={}", id_str);
    let file_id = match FileId::parse_es(&id_str) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("bad FileId parse: {} -> {}", id_str, e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    tracing::info!("  resolved to FileId hex={}, has_symbols={}", file_id.format_hex(), store.has_symbols(&file_id));

    match store.get_metadata(&file_id) {
        Some(metadata) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            metadata,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Devfiler-compatible ranges endpoint.
async fn handle_ranges(
    State(store): State<AppState>,
    Path((_a, _b, id_str)): Path<(String, String, String)>,
) -> impl IntoResponse {
    tracing::info!("GET ranges: id_str={}", id_str);
    let file_id = match FileId::parse_es(&id_str) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("bad FileId parse for ranges: {} -> {}", id_str, e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    match store.get_ranges(&file_id) {
        Some(data) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Status endpoint — list all stored symbols.
async fn handle_status(State(store): State<AppState>) -> impl IntoResponse {
    let entries = store.list();
    let items: Vec<serde_json::Value> = entries
        .iter()
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
