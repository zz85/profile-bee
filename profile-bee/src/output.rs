//! Output sink abstraction for profiling data.
//!
//! The `OutputSink` trait decouples the profiling pipeline from output format
//! concerns. Adding a new output format (pprof, OpenTelemetry, remote HTTP)
//! requires only implementing this trait — no changes to the profiling loop.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use inferno::flamegraph::{self, Options};

use crate::codeguru::{collapse_to_codeguru, CodeGuruOptions, CounterType};
use crate::event_loop::RawAddressSample;
use crate::html::{collapse_to_json, generate_html_file};
use crate::pprof::{collapse_to_pprof, PprofOptions};
use crate::types::FrameCount;

#[cfg(feature = "otlp")]
use crate::otlp::{self, OtlpOptions, ProfilesServiceClient};
#[cfg(feature = "otlp")]
use tonic::transport::Channel;

/// Default timeout for OTLP connect and export operations.
#[cfg(feature = "otlp")]
const OTLP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Trait for consuming profiling output.
///
/// In batch mode, `write_batch` is called once with the final stacks.
/// In streaming mode, `write_batch` is called periodically with the
/// current accumulated stacks. `finish` is called once at the end.
pub trait OutputSink: Send {
    /// Called with the current set of collapse-format stack strings.
    /// May be called multiple times in streaming mode.
    fn write_batch(&mut self, _stacks: &[String]) -> Result<()> {
        Ok(())
    }

    /// Called once when profiling is complete with the final stacks.
    /// File-based sinks write their output here.
    fn finish(&mut self, _final_stacks: &[String]) -> Result<()> {
        Ok(())
    }

    /// Called before `finish` to update metadata with the actual profiling
    /// duration. Sinks that embed duration in their output (pprof, CodeGuru)
    /// should override this; others can ignore it.
    fn set_actual_duration_ms(&mut self, _duration_ms: u64) {}
}

/// Fans out to multiple sinks.
pub struct MultiplexSink {
    sinks: Vec<Box<dyn OutputSink>>,
}

impl MultiplexSink {
    pub fn new(sinks: Vec<Box<dyn OutputSink>>) -> Self {
        Self { sinks }
    }
}

impl OutputSink for MultiplexSink {
    fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        for sink in &mut self.sinks {
            sink.set_actual_duration_ms(duration_ms);
        }
    }

    fn write_batch(&mut self, stacks: &[String]) -> Result<()> {
        for sink in &mut self.sinks {
            if let Err(e) = sink.write_batch(stacks) {
                // Log but don't propagate — other sinks should keep working
                // even if one fails (e.g., OTLP endpoint is temporarily down).
                tracing::warn!("MultiplexSink: write_batch error: {:#}", e);
            }
        }
        Ok(())
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        for sink in &mut self.sinks {
            if let Err(e) = sink.finish(final_stacks) {
                tracing::warn!("MultiplexSink: finish error: {:#}", e);
            }
        }
        Ok(())
    }
}

/// Writes an SVG flamegraph on finish.
pub struct SvgSink {
    path: PathBuf,
    title: String,
    off_cpu: bool,
}

impl SvgSink {
    pub fn new(path: PathBuf, title: String, off_cpu: bool) -> Self {
        Self {
            path,
            title,
            off_cpu,
        }
    }
}

impl OutputSink for SvgSink {
    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        let mut opts = Options::default();
        opts.title = self.title.clone();
        if self.off_cpu {
            opts.count_name = "us".to_string();
        }
        let mut writer =
            std::io::BufWriter::with_capacity(1024 * 1024, std::fs::File::create(&self.path)?);
        flamegraph::from_lines(
            &mut opts,
            final_stacks.iter().map(|v| v.as_str()),
            &mut writer,
        )
        .map_err(|e| {
            tracing::error!("Failed to write SVG {:?}: {:?}", self.path, e);
            e
        })?;
        Ok(())
    }
}

/// Writes an HTML flamegraph on finish.
pub struct HtmlSink {
    path: PathBuf,
}

impl HtmlSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl OutputSink for HtmlSink {
    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        let json = collapse_to_json(&final_stacks.iter().map(|v| v.as_str()).collect::<Vec<_>>());
        generate_html_file(&self.path, &json).context("Unable to write HTML flamegraph file")?;
        Ok(())
    }
}

/// Writes a JSON file on finish.
pub struct JsonFileSink {
    path: PathBuf,
}

impl JsonFileSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl OutputSink for JsonFileSink {
    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        let json = collapse_to_json(&final_stacks.iter().map(|v| v.as_str()).collect::<Vec<_>>());
        std::fs::write(&self.path, &json).context("Unable to write JSON file")?;
        Ok(())
    }
}

/// Writes a stackcollapse file on finish.
pub struct CollapseSink {
    path: PathBuf,
}

impl CollapseSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl OutputSink for CollapseSink {
    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        tracing::info!("Writing to file: {}", self.path.display());
        std::fs::write(&self.path, final_stacks.join("\n"))
            .context("Unable to write stack collapsed file")?;
        Ok(())
    }
}

/// Sends JSON to a tokio broadcast channel on every batch.
pub struct WebBroadcastSink {
    tx: tokio::sync::broadcast::Sender<String>,
}

impl WebBroadcastSink {
    pub fn new(tx: tokio::sync::broadcast::Sender<String>) -> Self {
        Self { tx }
    }
}

impl OutputSink for WebBroadcastSink {
    fn write_batch(&mut self, stacks: &[String]) -> Result<()> {
        let json = collapse_to_json(&stacks.iter().map(|v| v.as_str()).collect::<Vec<_>>());
        tracing::debug!("WebBroadcastSink: generated JSON ({} bytes)", json.len());
        if let Err(e) = self.tx.send(json) {
            tracing::warn!(
                "WebBroadcastSink: broadcast send failed (no receivers?): {:?}",
                e
            );
        } else {
            tracing::debug!(
                "WebBroadcastSink: broadcast sent to {} receivers",
                self.tx.receiver_count()
            );
        }
        Ok(())
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        // Forward the final batch so web clients see the last data snapshot.
        self.write_batch(final_stacks)
    }
}

/// Writes a gzip-compressed pprof protobuf file on finish.
///
/// The output is compatible with `go tool pprof`, Grafana/Pyroscope,
/// Speedscope, and other pprof-compatible tools.
pub struct PprofSink {
    path: PathBuf,
    options: PprofOptions,
}

impl PprofSink {
    pub fn new(path: PathBuf, frequency_hz: u64, duration_ms: u64, off_cpu: bool) -> Self {
        Self {
            path,
            options: PprofOptions {
                frequency_hz,
                duration_ms,
                off_cpu,
            },
        }
    }

    /// Update the duration after profiling completes so the exported
    /// metadata reflects the actual session length, not the requested timeout.
    pub fn set_duration_ms(&mut self, duration_ms: u64) {
        self.options.duration_ms = duration_ms;
    }
}

impl OutputSink for PprofSink {
    fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        self.options.duration_ms = duration_ms;
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        tracing::info!("Writing pprof to: {}", self.path.display());
        let pprof_bytes = collapse_to_pprof(final_stacks, &self.options)
            .context("Failed to generate pprof output")?;
        std::fs::write(&self.path, pprof_bytes).context("Unable to write pprof file")?;
        Ok(())
    }
}

/// Writes an AWS CodeGuru Profiler JSON file on finish.
///
/// The output conforms to CodeGuru's `PostAgentProfile` API schema
/// (`Content-Type: application/json`). Can be uploaded via:
/// ```bash
/// aws codeguruprofiler post-agent-profile \
///   --profiling-group-name my-group \
///   --agent-profile fileb://profile.codeguru.json \
///   --content-type application/json
/// ```
pub struct CodeGuruSink {
    path: PathBuf,
    options: CodeGuruOptions,
}

impl CodeGuruSink {
    pub fn new(path: PathBuf, frequency_hz: u64, duration_ms: u64, off_cpu: bool) -> Self {
        Self {
            path,
            options: CodeGuruOptions {
                frequency_hz,
                duration_ms,
                counter_type: if off_cpu {
                    CounterType::Waiting
                } else {
                    CounterType::Runnable
                },
                ..Default::default()
            },
        }
    }

    /// Update the duration after profiling completes so the exported
    /// metadata reflects the actual session length, not the requested timeout.
    pub fn set_duration_ms(&mut self, duration_ms: u64) {
        self.options.duration_ms = duration_ms;
    }

    /// Create with explicit fleet info for AWS environments.
    pub fn with_fleet_info(
        path: PathBuf,
        frequency_hz: u64,
        duration_ms: u64,
        off_cpu: bool,
        fleet_id: String,
        host_type: String,
    ) -> Self {
        Self {
            path,
            options: CodeGuruOptions {
                frequency_hz,
                duration_ms,
                fleet_id,
                host_type,
                counter_type: if off_cpu {
                    CounterType::Waiting
                } else {
                    CounterType::Runnable
                },
            },
        }
    }
}

impl OutputSink for CodeGuruSink {
    fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        self.options.duration_ms = duration_ms;
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        tracing::info!("Writing CodeGuru JSON to: {}", self.path.display());
        let json = collapse_to_codeguru(final_stacks, &self.options);
        std::fs::write(&self.path, &json).context("Unable to write CodeGuru JSON file")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Raw address collapse output — for offline/post-hoc symbolization
// ---------------------------------------------------------------------------

/// Writes an unsymbolized "raw collapse" file containing hex instruction
/// pointer addresses and process memory mapping metadata.
///
/// The output format is a self-contained text file that can be re-symbolized
/// offline:
///
/// ```text
/// # profile-bee raw v1
/// # mappings:1234
/// #   7f000000-7f100000 0 /usr/bin/node
/// #   7f200000-7f300000 1000 /lib/x86_64-linux-gnu/libc.so.6
/// # end_mappings:1234
/// node;0xffffffff81234567_k;0xffffffff81234568_k;0x7f000042;0x7f000084 42
/// ```
///
/// - Kernel addresses are suffixed with `_k`
/// - User addresses are bare hex
/// - The `# mappings` header captures `/proc/<pid>/maps` for each unique PID
/// - Multiple PIDs can appear in one file (system-wide profiling)
pub struct RawCollapseSink {
    path: PathBuf,
    samples: Vec<RawAddressSample>,
    /// Cached /proc/<pid>/maps snapshots, keyed by tgid
    mappings_cache: HashMap<u32, Vec<String>>,
}

impl RawCollapseSink {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            samples: Vec::new(),
            mappings_cache: HashMap::new(),
        }
    }

    /// Append raw address samples. Called by the event loop each collection cycle.
    pub fn add_samples(&mut self, samples: Vec<RawAddressSample>) {
        for sample in &samples {
            // Snapshot /proc/<pid>/maps on first encounter of each PID
            self.mappings_cache
                .entry(sample.tgid)
                .or_insert_with(|| Self::read_proc_maps(sample.tgid));
        }
        self.samples.extend(samples);
    }

    /// Write the complete raw collapse file.
    pub fn write(&self) -> Result<()> {
        use std::io::Write;
        tracing::info!("Writing raw collapse to: {}", self.path.display());

        let file = std::fs::File::create(&self.path)
            .with_context(|| format!("unable to create {}", self.path.display()))?;
        let mut w = std::io::BufWriter::new(file);

        // Header
        writeln!(w, "# profile-bee raw v1")?;

        // Write mappings for each unique PID in sorted order for deterministic output
        let mut sorted_tgids: Vec<u32> = self.mappings_cache.keys().copied().collect();
        sorted_tgids.sort();
        for tgid in sorted_tgids {
            if let Some(maps) = self.mappings_cache.get(&tgid) {
                writeln!(w, "# mappings:{}", tgid)?;
                for line in maps {
                    writeln!(w, "#   {}", line)?;
                }
                writeln!(w, "# end_mappings:{}", tgid)?;
            }
        }
        writeln!(w, "#")?;

        // Aggregate samples by (tgid, kernel_addrs, user_addrs)
        let mut aggregated: HashMap<String, u64> = HashMap::new();
        for sample in &self.samples {
            let key = Self::format_sample_key(sample);
            *aggregated.entry(key).or_insert(0) += sample.count;
        }

        // Write sorted collapse lines
        let mut lines: Vec<_> = aggregated.into_iter().collect();
        lines.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, count) in lines {
            writeln!(w, "{} {}", key, count)?;
        }

        w.flush()?;
        Ok(())
    }

    /// Format a single sample as a collapse-style key string.
    /// Kernel frames get `_k` suffix, user frames are bare hex.
    /// The tgid is included as a `[pid:N]` prefix after the command name
    /// so samples from different PIDs with the same command don't collide
    /// during aggregation. The symbolizer uses this to select the correct
    /// Process(Pid) source for each sample.
    fn format_sample_key(sample: &RawAddressSample) -> String {
        let mut frames = Vec::new();

        // Process name + PID as root frame (prevents cross-PID aggregation collision)
        frames.push(format!("{}[pid:{}]", sample.cmd, sample.tgid));

        // Kernel frames (bottom of stack, reversed for collapse format)
        for addr in sample.kernel_addrs.iter().rev() {
            if *addr != 0 {
                frames.push(format!("{:#x}_k", addr));
            }
        }

        // User frames (bottom of stack, reversed for collapse format)
        for addr in sample.user_addrs.iter().rev() {
            if *addr != 0 {
                frames.push(format!("{:#x}", addr));
            }
        }

        frames.join(";")
    }

    /// Read /proc/<pid>/maps and return executable mapping lines.
    fn read_proc_maps(tgid: u32) -> Vec<String> {
        let path = format!("/proc/{}/maps", tgid);
        let Ok(contents) = std::fs::read_to_string(&path) else {
            tracing::debug!("cannot read {}: process may have exited", path);
            return Vec::new();
        };

        contents
            .lines()
            .filter(|line| {
                // Only include executable mappings (r-xp or r--xp)
                line.split_whitespace()
                    .nth(1)
                    .is_some_and(|perms| perms.contains('x'))
            })
            .map(|s| s.to_string())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// OTLP gRPC profile export sink
// ---------------------------------------------------------------------------

/// Sends profiling data to an OTLP-compatible gRPC endpoint.
///
/// Compatible with:
/// - [devfiler](https://github.com/elastic/devfiler) (port 11000)
/// - OpenTelemetry Collector with profiles receiver
/// - Grafana Pyroscope (via OTel Collector)
/// - Any backend implementing `ProfilesService/Export`
///
/// Supports both batch mode (single send on `finish()`) and streaming mode
/// (periodic sends via `write_batch()`).
#[cfg(feature = "otlp")]
pub struct OtlpSink {
    endpoint: String,
    service_name: String,
    frequency_hz: u64,
    off_cpu: bool,
    duration_ms: u64,
    /// Lazily initialized gRPC client. Created on first send.
    client: Option<ProfilesServiceClient<Channel>>,
    /// Tokio runtime handle for blocking gRPC calls from sync OutputSink methods.
    runtime: tokio::runtime::Handle,
}

#[cfg(feature = "otlp")]
impl OtlpSink {
    pub fn new(
        endpoint: String,
        service_name: String,
        frequency_hz: u64,
        off_cpu: bool,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            endpoint,
            service_name,
            frequency_hz,
            off_cpu,
            duration_ms: 0,
            client: None,
            runtime,
        }
    }

    /// Send a batch of collapse-format stacks to the OTLP endpoint.
    fn send_stacks(&mut self, stacks: &[String]) -> Result<()> {
        if stacks.is_empty() {
            return Ok(());
        }

        let opts = OtlpOptions {
            service_name: self.service_name.clone(),
            frequency_hz: self.frequency_hz,
            duration_ms: self.duration_ms,
            off_cpu: self.off_cpu,
        };

        let request = otlp::collapse_to_otlp_request(stacks, &opts);
        let sample_count: usize = request
            .resource_profiles
            .iter()
            .flat_map(|rp| &rp.scope_profiles)
            .flat_map(|sp| &sp.profiles)
            .map(|p| p.samples.len())
            .sum();

        tracing::debug!(
            "OTLP: sending {} samples ({} stacks) to {}",
            sample_count,
            stacks.len(),
            self.endpoint
        );

        // Ensure gRPC client is connected.
        if let Err(e) = self.ensure_connected() {
            // Reset client so we retry connection on next send.
            self.client = None;
            return Err(e);
        }

        let client = self.client.as_mut().unwrap();
        let runtime = self.runtime.clone();
        let response = tokio::task::block_in_place(|| {
            runtime.block_on(async {
                client
                    .export(tonic::Request::new(request))
                    .await
                    .map_err(|e| anyhow::anyhow!("OTLP export failed: {}", e))
            })
        });

        match response {
            Ok(resp) => {
                let resp = resp.into_inner();
                if let Some(partial) = resp.partial_success {
                    if partial.rejected_profiles > 0 {
                        tracing::warn!(
                            "OTLP: server rejected {} profiles: {}",
                            partial.rejected_profiles,
                            partial.error_message
                        );
                    }
                }
                tracing::info!(
                    "OTLP: exported {} samples to {}",
                    sample_count,
                    self.endpoint
                );
                Ok(())
            }
            Err(e) => {
                // Reset client so we reconnect on next attempt.
                self.client = None;
                Err(e)
            }
        }
    }

    /// Ensure the gRPC client is connected, connecting lazily if needed.
    fn ensure_connected(&mut self) -> Result<()> {
        if self.client.is_some() {
            return Ok(());
        }

        let endpoint = self.endpoint.clone();
        tracing::info!("OTLP: connecting to gRPC endpoint: {}", endpoint);

        let uri = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.clone()
        } else {
            format!("http://{}", endpoint)
        };

        let channel = tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let ch = tonic::transport::Channel::from_shared(uri)
                    .map_err(|e| anyhow::anyhow!("invalid OTLP endpoint: {}", e))?;
                tokio::time::timeout(OTLP_TIMEOUT, ch.connect())
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("OTLP connect timed out after {:?}", OTLP_TIMEOUT)
                    })?
                    .map_err(|e| anyhow::anyhow!("failed to connect to OTLP endpoint: {}", e))
            })
        })?;

        self.client = Some(ProfilesServiceClient::new(channel));
        tracing::info!("OTLP: connected to {}", self.endpoint);
        Ok(())
    }
}

#[cfg(feature = "otlp")]
impl OutputSink for OtlpSink {
    fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        self.duration_ms = duration_ms;
    }

    fn write_batch(&mut self, stacks: &[String]) -> Result<()> {
        self.send_stacks(stacks)
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        self.send_stacks(final_stacks)
    }
}

// ---------------------------------------------------------------------------
// OTLP native-address profile export sink
// ---------------------------------------------------------------------------

/// Sends profiling data with real instruction pointer addresses and proc-map
/// mappings to an OTLP-compatible gRPC endpoint.
///
/// Unlike `OtlpSink` (which sends pre-symbolized collapse strings), this sink
/// consumes structured `FrameCount` data from `collect_raw()` and builds OTLP
/// profiles with:
/// - Real `Location.address` values (instruction pointers)
/// - Real `Mapping` entries from `/proc/<pid>/maps` with build IDs
/// - `profile.frame.type = "native"` so devfiler can do its own symbolization
/// - Function names in `Location.lines` as a fallback for receivers that don't
///   symbolize server-side
///
/// This sink operates outside the `OutputSink` trait since it receives
/// `Vec<FrameCount>` rather than `&[String]`.
#[cfg(feature = "otlp")]
pub struct OtlpNativeSink {
    endpoint: String,
    service_name: String,
    frequency_hz: u64,
    off_cpu: bool,
    duration_ms: u64,
    client: Option<ProfilesServiceClient<Channel>>,
    runtime: tokio::runtime::Handle,
}

#[cfg(feature = "otlp")]
impl OtlpNativeSink {
    pub fn new(
        endpoint: String,
        service_name: String,
        frequency_hz: u64,
        off_cpu: bool,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            endpoint,
            service_name,
            frequency_hz,
            off_cpu,
            duration_ms: 0,
            client: None,
            runtime,
        }
    }

    pub fn set_actual_duration_ms(&mut self, duration_ms: u64) {
        self.duration_ms = duration_ms;
    }

    /// Send structured frame counts with real addresses to the OTLP endpoint.
    pub fn send_framecounts(&mut self, frame_counts: &[FrameCount]) -> Result<()> {
        if frame_counts.is_empty() {
            return Ok(());
        }

        let opts = OtlpOptions {
            service_name: self.service_name.clone(),
            frequency_hz: self.frequency_hz,
            duration_ms: self.duration_ms,
            off_cpu: self.off_cpu,
        };

        let request = otlp::framecounts_to_otlp_request(frame_counts, &opts);
        let sample_count: usize = request
            .resource_profiles
            .iter()
            .flat_map(|rp| &rp.scope_profiles)
            .flat_map(|sp| &sp.profiles)
            .map(|p| p.samples.len())
            .sum();

        tracing::debug!(
            "OTLP native: sending {} samples ({} stacks) to {}",
            sample_count,
            frame_counts.len(),
            self.endpoint
        );

        if let Err(e) = self.ensure_connected() {
            self.client = None;
            return Err(e);
        }

        let client = self.client.as_mut().unwrap();
        let runtime = self.runtime.clone();
        let response = tokio::task::block_in_place(|| {
            runtime.block_on(async {
                tokio::time::timeout(OTLP_TIMEOUT, client.export(tonic::Request::new(request)))
                    .await
                    .map_err(|_| anyhow::anyhow!("OTLP export timed out after {:?}", OTLP_TIMEOUT))?
                    .map_err(|e| anyhow::anyhow!("OTLP export failed: {}", e))
            })
        });

        match response {
            Ok(resp) => {
                let resp = resp.into_inner();
                if let Some(partial) = resp.partial_success {
                    if partial.rejected_profiles > 0 {
                        tracing::warn!(
                            "OTLP: server rejected {} profiles: {}",
                            partial.rejected_profiles,
                            partial.error_message
                        );
                    }
                }
                tracing::info!(
                    "OTLP native: exported {} samples to {}",
                    sample_count,
                    self.endpoint
                );
                Ok(())
            }
            Err(e) => {
                self.client = None;
                Err(e)
            }
        }
    }

    fn ensure_connected(&mut self) -> Result<()> {
        if self.client.is_some() {
            return Ok(());
        }

        let endpoint = self.endpoint.clone();
        tracing::info!("OTLP native: connecting to gRPC endpoint: {}", endpoint);

        let uri = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.clone()
        } else {
            format!("http://{}", endpoint)
        };

        let channel = tokio::task::block_in_place(|| {
            self.runtime.block_on(async {
                let ch = tonic::transport::Channel::from_shared(uri)
                    .map_err(|e| anyhow::anyhow!("invalid OTLP endpoint: {}", e))?;
                tokio::time::timeout(OTLP_TIMEOUT, ch.connect())
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("OTLP connect timed out after {:?}", OTLP_TIMEOUT)
                    })?
                    .map_err(|e| anyhow::anyhow!("failed to connect to OTLP endpoint: {}", e))
            })
        })?;

        self.client = Some(ProfilesServiceClient::new(channel));
        tracing::info!("OTLP native: connected to {}", self.endpoint);
        Ok(())
    }
}
