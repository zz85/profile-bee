//! Offline re-symbolization of raw collapse files.
//!
//! Parses the `profile-bee raw v1` format produced by [`RawCollapseSink`] and
//! re-symbolizes addresses via blazesym, producing standard collapse-format
//! output that can be fed into flamegraph tools.
//!
//! # Format
//!
//! ```text
//! # profile-bee raw v1
//! # mappings:1234
//! #   7f000000-7f100000 0 /usr/bin/node
//! # end_mappings:1234
//! #
//! node;0xffffffff81234567_k;0x7f000042 42
//! ```

use std::collections::HashMap;
use std::path::Path;

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use blazesym::Pid;

/// A parsed raw stack sample (one line of the raw collapse file).
#[derive(Debug)]
struct RawLine {
    /// Process name (first frame in the collapse line)
    cmd: String,
    /// Kernel instruction pointers (addresses ending in `_k`)
    kernel_addrs: Vec<u64>,
    /// User instruction pointers (bare hex addresses)
    user_addrs: Vec<u64>,
    /// Sample count
    count: u64,
}

/// Parsed mapping header for a process.
///
/// **Limitation:** The captured mapping lines are stored but not yet used during
/// symbolization. The current implementation uses `Source::Process(Pid)` which
/// queries the live `/proc/<pid>/maps`, so offline symbolization (process no
/// longer running) will fail to resolve user-space addresses. A future
/// improvement would construct a blazesym source from these captured mappings
/// so `probee symbolize` works on files captured from dead processes.
#[derive(Debug)]
struct ProcMappings {
    /// Raw mapping lines from `/proc/<pid>/maps`
    _lines: Vec<String>,
}

/// Parse a raw collapse file and re-symbolize all addresses.
///
/// Returns collapse-format strings (`"frame1;frame2;...;frameN count"`).
pub fn symbolize_raw_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path.display(), e))?;

    let (mappings, samples) = parse_raw_collapse(&contents)?;

    // Determine PIDs from mappings header
    let pids: Vec<u32> = mappings.keys().copied().collect();

    let symbolizer = Symbolizer::new();
    let mut output = Vec::new();

    // Fallback PID for samples that don't embed a tgid in their root frame.
    // Used only when the raw file was produced by an older version without
    // per-sample PID tagging.
    let fallback_pid = pids.first().copied();

    for sample in &samples {
        let mut frames: Vec<String> = Vec::new();

        // Parse per-sample PID from the root frame if present.
        // New format: "cmd[pid:1234]", old format: just "cmd".
        let (cmd_display, sample_pid) = parse_cmd_pid(&sample.cmd);
        frames.push(cmd_display);

        let target_pid = sample_pid.or(fallback_pid);

        // Symbolize kernel frames.
        // Addresses in the raw file are already in root-to-leaf order
        // (the writer reverses them from leaf-to-root eBPF order), so we
        // iterate in order — no .rev() needed.
        if !sample.kernel_addrs.is_empty() {
            let src = Source::Kernel(Kernel::default());
            match symbolizer.symbolize(&src, Input::AbsAddr(&sample.kernel_addrs)) {
                Ok(syms) => {
                    for sym in syms {
                        frames.push(format_symbolized(sym, true));
                    }
                }
                Err(e) => {
                    tracing::debug!("kernel symbolization failed: {}", e);
                    for addr in &sample.kernel_addrs {
                        frames.push(format!("{:#x}_k", addr));
                    }
                }
            }
        }

        // Symbolize user frames (also already root-to-leaf in the file).
        if !sample.user_addrs.is_empty() {
            if let Some(pid) = target_pid {
                let src = Source::Process(Process::new(Pid::from(pid)));
                match symbolizer.symbolize(&src, Input::AbsAddr(&sample.user_addrs)) {
                    Ok(syms) => {
                        for sym in syms {
                            frames.push(format_symbolized(sym, false));
                        }
                    }
                    Err(e) => {
                        tracing::debug!("user symbolization failed for pid {}: {}", pid, e);
                        for addr in &sample.user_addrs {
                            frames.push(format!("{:#x}", addr));
                        }
                    }
                }
            } else {
                // No PID available — keep raw addresses
                for addr in &sample.user_addrs {
                    frames.push(format!("{:#x}", addr));
                }
            }
        }

        output.push(format!("{} {}", frames.join(";"), sample.count));
    }

    output.sort();
    Ok(output)
}

/// Parse the raw collapse format into mappings and sample lines.
fn parse_raw_collapse(
    contents: &str,
) -> anyhow::Result<(HashMap<u32, ProcMappings>, Vec<RawLine>)> {
    let mut mappings: HashMap<u32, ProcMappings> = HashMap::new();
    let mut samples: Vec<RawLine> = Vec::new();

    let mut current_mapping_pid: Option<u32> = None;
    let mut current_mapping_lines: Vec<String> = Vec::new();

    for line in contents.lines() {
        if line.starts_with('#') {
            let trimmed = line.trim_start_matches('#').trim();

            // Parse mapping headers
            if let Some(pid_str) = trimmed.strip_prefix("mappings:") {
                current_mapping_pid = pid_str.trim().parse().ok();
                current_mapping_lines.clear();
            } else if let Some(pid_str) = trimmed.strip_prefix("end_mappings:") {
                let parsed_pid: Option<u32> = match pid_str.trim().parse() {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!("malformed end_mappings PID '{}': {}", pid_str.trim(), e);
                        None
                    }
                };
                if let Some(pid) = current_mapping_pid.take() {
                    if parsed_pid == Some(pid) {
                        mappings.insert(
                            pid,
                            ProcMappings {
                                _lines: std::mem::take(&mut current_mapping_lines),
                            },
                        );
                    } else {
                        tracing::warn!(
                            "end_mappings PID mismatch: expected {}, got {:?} — discarding mapping block",
                            pid,
                            parsed_pid,
                        );
                        current_mapping_lines.clear();
                    }
                } else {
                    tracing::warn!(
                        "end_mappings:{} without matching mappings: header",
                        pid_str.trim()
                    );
                }
            } else if current_mapping_pid.is_some() && !trimmed.is_empty() {
                current_mapping_lines.push(trimmed.to_string());
            }
            // Skip other comment lines
            continue;
        }

        // Parse sample lines: "cmd;0xaddr_k;0xaddr count"
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(sample) = parse_sample_line(line) {
            samples.push(sample);
        }
    }

    Ok((mappings, samples))
}

/// Parse a single collapse line into a RawLine.
/// Format: `cmd;0xffffffff81234567_k;0x7f000042 42`
fn parse_sample_line(line: &str) -> Option<RawLine> {
    // Split off the trailing count
    let (stack_part, count_str) = line.rsplit_once(' ')?;
    let count: u64 = count_str.parse().ok()?;

    let mut parts = stack_part.split(';');
    let cmd = parts.next()?.to_string();

    let mut kernel_addrs = Vec::new();
    let mut user_addrs = Vec::new();

    for frame in parts {
        if let Some(hex) = frame.strip_suffix("_k") {
            // Kernel address
            if let Some(addr) = parse_hex_addr(hex) {
                kernel_addrs.push(addr);
            }
        } else if let Some(addr) = parse_hex_addr(frame) {
            // User address
            user_addrs.push(addr);
        }
        // Skip non-hex frames (shouldn't happen in raw format)
    }

    Some(RawLine {
        cmd,
        kernel_addrs,
        user_addrs,
        count,
    })
}

/// Parse a hex address like "0x7f000042" or "0xffffffff81234567".
fn parse_hex_addr(s: &str) -> Option<u64> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

/// Format a symbolized result into a collapse frame string.
fn format_symbolized(sym: Symbolized, is_kernel: bool) -> String {
    match sym {
        Symbolized::Sym(sym) => {
            let suffix = if is_kernel { "_k" } else { "" };
            format!("{}{}", sym.name, suffix)
        }
        Symbolized::Unknown(_reason) => "[unknown]".to_string(),
    }
}

/// Parse per-sample PID from the root frame.
///
/// New format (with tgid): `"cmd[pid:1234]"` → `("cmd", Some(1234))`
/// Old format (without):   `"cmd"` → `("cmd", None)`
fn parse_cmd_pid(cmd: &str) -> (String, Option<u32>) {
    if let Some(bracket_start) = cmd.rfind("[pid:") {
        let after = &cmd[bracket_start + 5..];
        if let Some(bracket_end) = after.find(']') {
            if let Ok(pid) = after[..bracket_end].parse::<u32>() {
                let display = cmd[..bracket_start].to_string();
                return (display, Some(pid));
            }
        }
    }
    (cmd.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_addr() {
        assert_eq!(parse_hex_addr("0x7f000042"), Some(0x7f000042));
        assert_eq!(
            parse_hex_addr("0xffffffff81234567"),
            Some(0xffffffff81234567)
        );
        assert_eq!(parse_hex_addr("not_hex"), None);
        assert_eq!(parse_hex_addr("0x0"), Some(0));
    }

    #[test]
    fn test_parse_sample_line() {
        let line = "node;0xffffffff81234567_k;0xffffffff81234568_k;0x7f000042;0x7f000084 42";
        let sample = parse_sample_line(line).unwrap();
        assert_eq!(sample.cmd, "node");
        assert_eq!(
            sample.kernel_addrs,
            vec![0xffffffff81234567, 0xffffffff81234568]
        );
        assert_eq!(sample.user_addrs, vec![0x7f000042, 0x7f000084]);
        assert_eq!(sample.count, 42);
    }

    #[test]
    fn test_parse_sample_line_no_kernel() {
        let line = "myapp;0x7f000042;0x7f000084 1";
        let sample = parse_sample_line(line).unwrap();
        assert_eq!(sample.cmd, "myapp");
        assert!(sample.kernel_addrs.is_empty());
        assert_eq!(sample.user_addrs, vec![0x7f000042, 0x7f000084]);
        assert_eq!(sample.count, 1);
    }

    #[test]
    fn test_parse_sample_line_only_cmd() {
        let line = "idle 100";
        let sample = parse_sample_line(line).unwrap();
        assert_eq!(sample.cmd, "idle");
        assert!(sample.kernel_addrs.is_empty());
        assert!(sample.user_addrs.is_empty());
        assert_eq!(sample.count, 100);
    }

    #[test]
    fn test_parse_raw_collapse_header() {
        let raw = "\
# profile-bee raw v1
# mappings:1234
#   7f000000-7f100000 0 /usr/bin/node
#   7f200000-7f300000 1000 /lib/libc.so.6
# end_mappings:1234
#
node;0xffffffff81234567_k;0x7f000042 42
";
        let (mappings, samples) = parse_raw_collapse(raw).unwrap();
        assert!(mappings.contains_key(&1234));
        assert_eq!(mappings[&1234]._lines.len(), 2);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].count, 42);
    }

    #[test]
    fn test_parse_raw_collapse_multiple_pids() {
        let raw = "\
# profile-bee raw v1
# mappings:100
#   400000-500000 0 /usr/bin/app
# end_mappings:100
# mappings:200
#   400000-500000 0 /usr/bin/other
# end_mappings:200
#
app;0x400042 10
other;0x400042 5
";
        let (mappings, samples) = parse_raw_collapse(raw).unwrap();
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains_key(&100));
        assert!(mappings.contains_key(&200));
        assert_eq!(samples.len(), 2);
    }

    #[test]
    fn test_parse_cmd_pid_with_tag() {
        let (cmd, pid) = parse_cmd_pid("node[pid:1234]");
        assert_eq!(cmd, "node");
        assert_eq!(pid, Some(1234));
    }

    #[test]
    fn test_parse_cmd_pid_without_tag() {
        let (cmd, pid) = parse_cmd_pid("myapp");
        assert_eq!(cmd, "myapp");
        assert_eq!(pid, None);
    }

    #[test]
    fn test_parse_sample_line_with_pid_tag() {
        let line = "node[pid:1234];0xffffffff81234567_k;0x7f000042 42";
        let sample = parse_sample_line(line).unwrap();
        // The raw parser sees the whole "node[pid:1234]" as cmd
        assert_eq!(sample.cmd, "node[pid:1234]");
        assert_eq!(sample.count, 42);
    }
}
