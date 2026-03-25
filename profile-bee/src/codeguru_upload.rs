//! AWS CodeGuru Profiler upload sink.
//!
//! Uploads profiling data directly to CodeGuru's `PostAgentProfile` API.
//! Behind the `aws` feature flag to avoid pulling in AWS SDK for all users.
//!
//! # Usage
//!
//! ```bash
//! # Note: use sudo -E to preserve AWS credentials in the environment
//! sudo -E probee --codeguru-upload --profiling-group my-group --time 10000
//! ```
//!
//! Credentials are resolved via the standard AWS credential chain
//! (environment variables, `~/.aws/credentials`, IAM role, etc.).
//! When running with `sudo`, use `sudo -E` to preserve environment variables.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_sdk_codeguruprofiler::primitives::Blob;
use aws_sdk_codeguruprofiler::Client;

use crate::codeguru::{collapse_to_codeguru, CodeGuruOptions};
use crate::output::OutputSink;

/// Default timeout for the upload operation (30 seconds).
const UPLOAD_TIMEOUT_SECS: u64 = 30;

/// Uploads profiling data to AWS CodeGuru Profiler on finish.
///
/// Uses the `PostAgentProfile` API with `Content-Type: application/json`.
/// Also optionally writes a local copy of the JSON for debugging.
pub struct CodeGuruUploadSink {
    profiling_group: String,
    options: CodeGuruOptions,
    /// Optional local file path to also save the JSON (for debugging).
    local_copy: Option<PathBuf>,
    /// Tokio runtime handle for spawning the async upload task.
    rt_handle: tokio::runtime::Handle,
}

impl CodeGuruUploadSink {
    /// Create a new upload sink.
    ///
    /// AWS config is loaded lazily in `finish()`, not at construction time.
    /// This avoids hanging during profiling if credentials aren't available.
    pub fn new(
        profiling_group: String,
        options: CodeGuruOptions,
        local_copy: Option<PathBuf>,
        rt_handle: tokio::runtime::Handle,
    ) -> Self {
        // Warn early if AWS credentials look missing (best-effort check)
        if std::env::var("AWS_ACCESS_KEY_ID").is_err()
            && std::env::var("AWS_PROFILE").is_err()
            && std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE").is_err()
        {
            tracing::error!(
                "No AWS credentials detected in environment. \
                 If running with sudo, use `sudo -E` to preserve credentials."
            );
        }

        Self {
            profiling_group,
            options,
            local_copy,
            rt_handle,
        }
    }
}

impl OutputSink for CodeGuruUploadSink {
    fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        self.options.duration_ms = duration_ms;
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        let json = collapse_to_codeguru(final_stacks, &self.options);
        let json_bytes = json.into_bytes();

        // Optionally save a local copy for debugging
        if let Some(path) = &self.local_copy {
            eprintln!("Saving local CodeGuru JSON copy to: {}", path.display());
            std::fs::write(path, &json_bytes)
                .context("Failed to write local CodeGuru JSON copy")?;
        }

        let profiling_group = self.profiling_group.clone();
        let size = json_bytes.len();

        eprintln!(
            "Uploading {} bytes to CodeGuru profiling group '{}'...",
            size, profiling_group,
        );

        // Spawn the upload as a tokio task and wait for it via a oneshot channel.
        // We cannot use block_on() here because finish() is called from within
        // the tokio runtime (inside #[tokio::main]). Using block_on() from
        // inside a runtime panics with "Cannot start a runtime from within a
        // runtime". Instead, we spawn the work and use a std channel to bridge
        // the sync/async boundary.
        let (tx, rx) = std::sync::mpsc::channel();

        self.rt_handle.spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(UPLOAD_TIMEOUT_SECS),
                do_upload(&profiling_group, json_bytes),
            )
            .await;
            let _ = tx.send(result);
        });

        // Wait for the spawned task's result (blocking the current thread
        // is fine here — we're in a sync OutputSink::finish call and the
        // upload task runs on a different tokio worker thread).
        let result = rx
            .recv()
            .map_err(|_| anyhow::anyhow!("Upload task died before sending result"))?;

        match result {
            Ok(Ok(())) => {
                eprintln!(
                    "Successfully uploaded profile to CodeGuru profiling group '{}'",
                    self.profiling_group,
                );
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow::anyhow!(
                "CodeGuru upload timed out after {}s. \
                 Check AWS credentials and network connectivity.",
                UPLOAD_TIMEOUT_SECS,
            )),
        }
    }
}

async fn do_upload(profiling_group: &str, json_bytes: Vec<u8>) -> Result<()> {
    // Load AWS config (credential resolution happens here)
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = Client::new(&config);

    client
        .post_agent_profile()
        .profiling_group_name(profiling_group)
        .content_type("application/json")
        .agent_profile(Blob::new(json_bytes))
        .send()
        .await
        .context("CodeGuru PostAgentProfile API call failed")?;

    Ok(())
}
