//! Output sink abstraction for profiling data.
//!
//! The `OutputSink` trait decouples the profiling pipeline from output format
//! concerns. Adding a new output format (pprof, OpenTelemetry, remote HTTP)
//! requires only implementing this trait — no changes to the profiling loop.

use std::path::PathBuf;

use anyhow::{Context, Result};
use inferno::flamegraph::{self, Options};

use crate::codeguru::{collapse_to_codeguru, CodeGuruOptions, CounterType};
use crate::html::{collapse_to_json, generate_html_file};
use crate::pprof::{collapse_to_pprof, PprofOptions};

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
        let mut first_err: Option<anyhow::Error> = None;
        for sink in &mut self.sinks {
            if let Err(e) = sink.write_batch(stacks) {
                tracing::warn!("MultiplexSink: write_batch error: {:#}", e);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn finish(&mut self, final_stacks: &[String]) -> Result<()> {
        let mut first_err: Option<anyhow::Error> = None;
        for sink in &mut self.sinks {
            if let Err(e) = sink.finish(final_stacks) {
                tracing::warn!("MultiplexSink: finish error: {:#}", e);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
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
