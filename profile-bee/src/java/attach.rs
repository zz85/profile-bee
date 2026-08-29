//! HotSpot attach helpers for dumping JIT perf-maps without manual jcmd.
//!
//! When system-wide profiling sees a JVM, profile-bee needs `/tmp/perf-<pid>.map`
//! (or the container-equivalent path). OpenJDK can produce that via the
//! diagnostic command `Compiler.perfmap`.
//!
//! We try, in order:
//! 1. Host `jcmd <pid> Compiler.perfmap` (same user/root attach)
//! 2. `jcmd` from the process's own JAVA_HOME (`/proc/<pid>/exe`)
//! 3. Direct Unix-socket attach protocol (works when jcmd is missing)
//! 4. `nsenter -t <pid> -m -p` + jcmd inside the mount/PID namespace (containers)
//!
//! All methods are best-effort and never fail the profiler.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::{find_libjvm_path, is_jvm_process};
use crate::perf_map::find_perf_map_path;

/// Result of attempting to ensure a perf-map exists for a JVM.
#[derive(Debug, Clone)]
pub struct PerfMapEnsureResult {
    pub pid: u32,
    pub dumped: bool,
    pub path: Option<PathBuf>,
    pub method: Option<&'static str>,
    pub message: String,
}

/// Scan `/proc` for HotSpot JVMs (processes mapping `libjvm.so` or named `java`).
pub fn discover_jvm_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.as_bytes().iter().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        // Skip our own process.
        if pid == std::process::id() {
            continue;
        }
        if is_jvm_process(pid) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

/// Return namespace PIDs for `pid` from `/proc/<pid>/status` (`NSpid:`).
/// First entry is the host PID; last is the innermost PID namespace ID.
pub fn namespace_pids(pid: u32) -> Vec<u32> {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return vec![pid];
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let list: Vec<u32> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !list.is_empty() {
                return list;
            }
        }
    }
    vec![pid]
}

/// Paths where a JVM might have written a perf-map for this host PID.
pub fn candidate_perf_map_paths(pid: u32) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let nspids = namespace_pids(pid);
    let inner = *nspids.last().unwrap_or(&pid);

    paths.push(PathBuf::from(format!("/tmp/perf-{pid}.map")));
    paths.push(PathBuf::from(format!("/tmp/perf-{inner}.map")));
    paths.push(PathBuf::from(format!(
        "/proc/{pid}/root/tmp/perf-{pid}.map"
    )));
    paths.push(PathBuf::from(format!(
        "/proc/{pid}/root/tmp/perf-{inner}.map"
    )));
    // Dedup while preserving order
    paths.dedup();
    paths
}

/// True if any candidate perf-map path exists and is non-empty.
pub fn has_usable_perf_map(pid: u32) -> bool {
    if find_perf_map_path(pid).is_some_and(|p| file_nonempty(&p)) {
        return true;
    }
    candidate_perf_map_paths(pid)
        .into_iter()
        .any(|p| file_nonempty(&p))
}

fn file_nonempty(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
}

/// Ensure a perf-map exists for `pid`, dumping via HotSpot attach if needed.
pub fn ensure_perf_map(pid: u32) -> PerfMapEnsureResult {
    ensure_perf_map_inner(pid, false)
}

/// Re-dump the perf-map even if one already exists (picks up new JIT methods).
pub fn refresh_perf_map(pid: u32) -> PerfMapEnsureResult {
    ensure_perf_map_inner(pid, true)
}

fn ensure_perf_map_inner(pid: u32, force_dump: bool) -> PerfMapEnsureResult {
    if !is_jvm_process(pid) {
        return PerfMapEnsureResult {
            pid,
            dumped: false,
            path: None,
            method: None,
            message: "not a JVM process".into(),
        };
    }

    if !force_dump {
        if let Some(path) = find_existing_map(pid) {
            return PerfMapEnsureResult {
                pid,
                dumped: false,
                path: Some(path),
                method: Some("existing"),
                message: "perf-map already present".into(),
            };
        }
    }

    // Snapshot size so a forced re-dump can detect growth.
    let before_len = find_existing_map(pid)
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| m.len());

    // Attempt dumps in preference order.
    type DumpFn = fn(u32) -> Result<(), String>;
    let attempts: &[(&str, DumpFn)] = &[
        ("jcmd", dump_via_jcmd_path),
        ("jcmd-java-home", dump_via_process_jcmd),
        ("attach-socket", dump_via_attach_socket),
        ("nsenter-jcmd", dump_via_nsenter),
    ];

    let mut last_err = String::new();
    for (name, f) in attempts {
        match f(pid) {
            Ok(()) => {
                // Give the JVM a moment to flush the file.
                wait_for_map(pid, Duration::from_secs(2));
                if let Some(path) = find_existing_map(pid) {
                    let after_len = fs::metadata(&path).ok().map(|m| m.len());
                    let grew = match (before_len, after_len) {
                        (Some(b), Some(a)) => a >= b,
                        (None, Some(_)) => true,
                        _ => true,
                    };
                    if grew || !force_dump {
                        return PerfMapEnsureResult {
                            pid,
                            dumped: true,
                            path: Some(path),
                            method: Some(*name),
                            message: format!("dumped via {name}"),
                        };
                    }
                }
                last_err = format!("{name} reported success but map file not found");
            }
            Err(e) => {
                tracing::debug!("perf-map dump via {name} for pid {pid}: {e}");
                last_err = e;
            }
        }
    }

    // Forced refresh may fail attach but still have a previous map.
    if let Some(path) = find_existing_map(pid) {
        return PerfMapEnsureResult {
            pid,
            dumped: false,
            path: Some(path),
            method: Some("existing"),
            message: format!("refresh failed ({last_err}); keeping previous map"),
        };
    }

    PerfMapEnsureResult {
        pid,
        dumped: false,
        path: None,
        method: None,
        message: format!("failed to dump perf-map: {last_err}"),
    }
}

fn find_existing_map(pid: u32) -> Option<PathBuf> {
    candidate_perf_map_paths(pid)
        .into_iter()
        .find(|p| file_nonempty(p))
        .or_else(|| find_perf_map_path(pid).filter(|p| file_nonempty(p)))
}

fn wait_for_map(pid: u32, budget: Duration) {
    let start = Instant::now();
    while start.elapsed() < budget {
        if find_existing_map(pid).is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn dump_via_jcmd_path(pid: u32) -> Result<(), String> {
    run_jcmd("jcmd", pid)
}

fn dump_via_process_jcmd(pid: u32) -> Result<(), String> {
    let jcmd = find_jcmd_for_process(pid).ok_or_else(|| "no jcmd near process java".to_string())?;
    run_jcmd_binary(&jcmd, pid)
}

fn run_jcmd(bin: &str, pid: u32) -> Result<(), String> {
    let output = Command::new(bin)
        .arg(pid.to_string())
        .arg("Compiler.perfmap")
        .output()
        .map_err(|e| format!("spawn {bin}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "{bin} exit {}: {} {}",
            output.status, stdout, stderr
        ))
    }
}

fn run_jcmd_binary(bin: &Path, pid: u32) -> Result<(), String> {
    let output = Command::new(bin)
        .arg(pid.to_string())
        .arg("Compiler.perfmap")
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{} failed: {stderr}", bin.display()))
    }
}

/// Locate `jcmd` next to the process's `java` binary.
fn find_jcmd_for_process(pid: u32) -> Option<PathBuf> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    // .../bin/java → .../bin/jcmd
    if let Some(dir) = exe.parent() {
        let candidate = dir.join("jcmd");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // libjvm path: .../lib/server/libjvm.so → .../bin/jcmd
    if let Some(libjvm) = find_libjvm_path(pid) {
        // walk up looking for bin/jcmd
        let mut cur = libjvm.parent();
        for _ in 0..6 {
            let Some(dir) = cur else { break };
            let candidate = dir.join("bin/jcmd");
            if candidate.is_file() {
                return Some(candidate);
            }
            // also JAVA_HOME/bin when lib is under jre/lib
            let candidate = dir.join("jcmd");
            if candidate.is_file() {
                return Some(candidate);
            }
            cur = dir.parent();
        }
    }
    None
}

fn dump_via_nsenter(pid: u32) -> Result<(), String> {
    // Only useful when the process has a distinct mount/pid namespace.
    let nspids = namespace_pids(pid);
    if nspids.len() < 2 {
        return Err("process not in nested PID namespace".into());
    }
    let inner = *nspids.last().unwrap();
    // Prefer jcmd from inside the container root.
    let inner_jcmd = PathBuf::from(format!("/proc/{pid}/root/usr/bin/jcmd"));
    let jcmd_in_root = if inner_jcmd.is_file() {
        PathBuf::from("/usr/bin/jcmd")
    } else if let Some(j) = find_jcmd_for_process(pid) {
        // Translate host path to container path if under /proc/pid/root
        let prefix = format!("/proc/{pid}/root");
        j.strip_prefix(&prefix)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from("jcmd"))
    } else {
        PathBuf::from("jcmd")
    };

    let output = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-m",
            "-p",
            "--",
            jcmd_in_root.to_str().unwrap_or("jcmd"),
            &inner.to_string(),
            "Compiler.perfmap",
        ])
        .output()
        .map_err(|e| format!("nsenter: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nsenter jcmd failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Direct HotSpot attach socket protocol.
///
/// Protocol (Linux):
/// 1. Ensure attach listener: create `/tmp/.attach_pid<pid>` and SIGQUIT if needed
/// 2. Connect to `/tmp/.java_pid<pid>` (or under `/proc/<pid>/root/tmp/`)
/// 3. Write: `1\0jcmd\0Compiler.perfmap\0`
/// 4. Read response until EOF
fn dump_via_attach_socket(pid: u32) -> Result<(), String> {
    let nspids = namespace_pids(pid);
    let inner = *nspids.last().unwrap_or(&pid);

    let socket_candidates = [
        PathBuf::from(format!("/tmp/.java_pid{pid}")),
        PathBuf::from(format!("/tmp/.java_pid{inner}")),
        PathBuf::from(format!("/proc/{pid}/root/tmp/.java_pid{inner}")),
        PathBuf::from(format!("/proc/{pid}/root/tmp/.java_pid{pid}")),
    ];

    // Trigger attach listener if socket missing.
    if !socket_candidates.iter().any(|p| p.exists()) {
        trigger_attach_listener(pid, inner)?;
        // Wait briefly for socket creation
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if socket_candidates.iter().any(|p| p.exists()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let socket_path = socket_candidates
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| "HotSpot attach socket not found".to_string())?;

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // Attach protocol: version, command name, args... each NUL-terminated.
    // jcmd tool sends: "1", "jcmd", "<command line>"
    write_attach_string(&mut stream, "1")?;
    write_attach_string(&mut stream, "jcmd")?;
    write_attach_string(&mut stream, "Compiler.perfmap")?;

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => {
                tracing::debug!("attach read: {e}");
                break;
            }
        }
        if resp.len() > 1_000_000 {
            break;
        }
    }

    let text = String::from_utf8_lossy(&resp);
    // Success responses typically start with "0\n" (return code).
    if text.starts_with('0') || text.contains("perf") || resp.is_empty() {
        // empty can still mean success on some JDKs
        Ok(())
    } else if text.starts_with('-') || text.contains("Unknown diagnostic command") {
        Err(format!("attach command failed: {}", text.trim()))
    } else {
        // Many JDKs still wrote the file even with odd stdout.
        Ok(())
    }
}

fn write_attach_string(stream: &mut UnixStream, s: &str) -> Result<(), String> {
    stream
        .write_all(s.as_bytes())
        .and_then(|_| stream.write_all(&[0]))
        .map_err(|e| format!("attach write: {e}"))
}

fn trigger_attach_listener(pid: u32, inner: u32) -> Result<(), String> {
    // Create attach flag files HotSpot watches for.
    let flags = [
        PathBuf::from(format!("/tmp/.attach_pid{pid}")),
        PathBuf::from(format!("/tmp/.attach_pid{inner}")),
        PathBuf::from(format!("/proc/{pid}/root/tmp/.attach_pid{inner}")),
    ];
    let mut created = false;
    for path in &flags {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
        {
            Ok(_) => {
                created = true;
                // Best-effort permissions; JVM may need to see it.
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o666));
            }
            Err(e) => tracing::debug!("cannot create {}: {e}", path.display()),
        }
    }
    if !created {
        return Err("could not create attach flag file".into());
    }

    // SIGQUIT wakes the attach listener (HotSpot convention).
    let rc = unsafe { libc::kill(pid as i32, libc::SIGQUIT) };
    if rc != 0 {
        return Err(format!(
            "SIGQUIT pid {pid} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Discover all JVMs and ensure each has a perf-map. Returns per-PID results.
pub fn bootstrap_system_java_maps() -> Vec<PerfMapEnsureResult> {
    let pids = discover_jvm_pids();
    if pids.is_empty() {
        tracing::debug!("no JVM processes found during system scan");
        return Vec::new();
    }
    tracing::info!(
        "discovered {} JVM process(es) for automatic JIT symbol loading: {:?}",
        pids.len(),
        pids
    );
    pids.into_iter().map(ensure_perf_map).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_pids_self_nonempty() {
        let pid = std::process::id();
        let nsp = namespace_pids(pid);
        assert!(!nsp.is_empty());
        assert_eq!(nsp[0], pid);
    }

    #[test]
    fn candidate_paths_include_tmp() {
        let paths = candidate_perf_map_paths(1234);
        assert!(paths.iter().any(|p| p.ends_with("perf-1234.map")));
    }

    #[test]
    fn discover_does_not_panic() {
        let _ = discover_jvm_pids();
    }
}
