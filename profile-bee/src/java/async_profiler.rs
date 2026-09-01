//! Delegate Java stacks to async-profiler.
//!
//! Out-of-process eBPF unwinding can't walk HotSpot JIT frames without
//! `-XX:+PreserveFramePointer`. Instead, profile-bee can attach async-profiler
//! (`asprof`) to a JVM for the profiling window and use its folded ("collapsed")
//! output — which is `AsyncGetCallTrace`-accurate and needs no frame pointers.
//!
//! async-profiler's `-o collapsed` output is the same `frame;frame;… count`
//! folded format profile-bee emits, so merging is a splice:
//!
//! - **Single `--pid`**: eBPF sampling is already scoped to that process, so its
//!   whole collapse is replaced by async-profiler's output.
//! - **System-wide**: every discovered JVM is attached; [`merge_system_wide`]
//!   drops each attached JVM's eBPF stacks (matched by the `(pid)` in the
//!   `--group-by-process` root) and splices in async-profiler's, keeping eBPF
//!   stacks for native processes and any JVM that refused attach.
//!
//! `asprof` is taken from `$ASPROF`/`$PATH`/common install roots if present,
//! otherwise the pinned official release for the host arch is downloaded
//! (SHA-256-verified) and cached in a world-readable dir (`/var/tmp/profile-bee`,
//! override `$PROFILE_BEE_CACHE`) on first use — no manual install required. See
//! [`asprof_path`] / [`ensure_asprof`].
//!
//! Scope: batch (collapse/svg/json) output only; streaming/serve/TUI is a
//! follow-up.

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Pinned async-profiler release used for on-demand download.
const AP_VERSION: &str = "4.5";
/// SHA-256 of the official `async-profiler-<ver>-linux-<arch>.tar.gz` release
/// assets, verified after download before anything is extracted or executed.
const AP_SHA256_X64: &str = "89546fbb9ee0fc5496c7edd4099b0709489bc78b0d8057ccbb4b801f6b032b62";
const AP_SHA256_ARM64: &str = "64c41d1465d60097439c50d7e924b4946f1f62b1cbd21ce5b034fad09c0d6979";

/// Map the host arch to async-profiler's release-asset arch tag + expected
/// tarball SHA-256. Returns `None` on arches async-profiler doesn't publish.
fn ap_platform() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("x64", AP_SHA256_X64)),
        "aarch64" => Some(("arm64", AP_SHA256_ARM64)),
        _ => None,
    }
}

/// Cache directory for the auto-downloaded async-profiler.
///
/// Deliberately a **world-readable** location (default `/var/tmp/profile-bee`),
/// not `$HOME/.cache`: profile-bee typically runs as root (sudo) and attaches
/// JVMs owned by other users, and async-profiler injects `libasyncProfiler.so`
/// which the *target* JVM must then `dlopen` as its own uid. A root-only cache
/// (`/root/.cache` under sudo) makes that fail with "Permission denied".
/// Override with `$PROFILE_BEE_CACHE`.
fn cache_dir() -> PathBuf {
    if let Ok(d) = std::env::var("PROFILE_BEE_CACHE") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    PathBuf::from("/var/tmp/profile-bee")
}

/// `asprof` path inside the cache for the pinned version + host arch.
fn cached_asprof() -> Option<PathBuf> {
    let (arch, _) = ap_platform()?;
    Some(cache_dir().join(format!(
        "async-profiler-{AP_VERSION}-linux-{arch}/bin/asprof"
    )))
}

/// Security gate for auto-download cache paths. profile-bee usually runs as root
/// and the default cache lives under world-writable `/var/tmp`, so a local user
/// could plant a trojan `asprof`/`libasyncProfiler.so`. Require every component
/// from the cache root down to `path` to be a non-symlink, owned by root or the
/// current euid, and not group/other-writable — otherwise root might read or
/// execute an attacker-controlled file. Only applied to the download cache;
/// `$ASPROF`/`$PATH`/install-root binaries are operator-chosen and trusted.
fn is_trusted_cache_path(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    let secure = |p: &Path| -> bool {
        match std::fs::symlink_metadata(p) {
            Ok(md) => {
                !md.file_type().is_symlink()
                    && (md.uid() == 0 || md.uid() == euid)
                    && md.mode() & 0o022 == 0
            }
            Err(_) => false,
        }
    };
    let root = cache_dir();
    let Ok(rel) = path.strip_prefix(&root) else {
        return false;
    };
    if !secure(&root) {
        return false;
    }
    let mut cur = root;
    for comp in rel.components() {
        cur = cur.join(comp);
        if !secure(&cur) {
            return false;
        }
    }
    true
}

/// Locate an already-present async-profiler launcher without touching the
/// network: `$ASPROF`, then `asprof`/`profiler.sh` on `$PATH`, then common
/// install roots, then the auto-download cache.
pub fn asprof_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ASPROF") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            for name in ["asprof", "profiler.sh"] {
                let cand = Path::new(dir).join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    for base in ["/opt/async-profiler", "/usr/local/async-profiler"] {
        for rel in ["bin/asprof", "asprof", "profiler.sh"] {
            let cand = Path::new(base).join(rel);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    // Cache binaries are only trusted if the whole chain is root/self-owned and
    // not world/group-writable (the cache lives under world-writable /var/tmp).
    cached_asprof().filter(|p| p.is_file() && is_trusted_cache_path(p))
}

/// Ensure an `asprof` binary is available, downloading the pinned official
/// release for the host arch into the cache if none is found locally.
///
/// The download is checksum-verified (SHA-256) against a pinned digest before
/// extraction — nothing unverified is written to the cache or executed. Returns
/// the existing/`$ASPROF`/`$PATH` binary immediately when present (no network).
pub async fn ensure_asprof() -> std::io::Result<PathBuf> {
    use std::io::Error;

    if let Some(p) = asprof_path() {
        return Ok(p);
    }
    let (arch, expected_sha) = ap_platform().ok_or_else(|| {
        Error::other(format!(
            "no async-profiler release for arch {}; set $ASPROF",
            std::env::consts::ARCH
        ))
    })?;
    let asset = format!("async-profiler-{AP_VERSION}-linux-{arch}");
    let url = format!(
        "https://github.com/async-profiler/async-profiler/releases/download/v{AP_VERSION}/{asset}.tar.gz"
    );

    eprintln!("async-profiler: downloading pinned {asset} (verified) ...");
    // Bounded timeouts so a host with no GitHub egress fails fast into the eBPF
    // fallback instead of hanging the whole run on a stuck connection.
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(Error::other)?;
    let bytes = client
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(Error::other)?
        .bytes()
        .await
        .map_err(Error::other)?;

    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if hex != expected_sha {
        return Err(Error::other(format!(
            "async-profiler {asset} checksum mismatch: got {hex}, expected {expected_sha}"
        )));
    }

    let root = cache_dir();
    std::fs::create_dir_all(&root)?;
    // Normalize our cache root to 0755 (world-readable, not world-writable), then
    // refuse to extract into / use a root we don't control — the default cache
    // lives under world-writable /var/tmp, so a planted dir is possible.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755));
    }
    if !is_trusted_cache_path(&root) {
        return Err(Error::other(format!(
            "refusing untrusted async-profiler cache dir {} (unexpected owner/permissions/symlink); set $PROFILE_BEE_CACHE or $ASPROF",
            root.display()
        )));
    }

    // Extract fresh (drop any stale/tampered prior extraction under our root).
    let asset_dir = root.join(&asset);
    let _ = std::fs::remove_dir_all(&asset_dir);
    // The tarball has a single top-level dir `async-profiler-<ver>-linux-<arch>/`.
    let mut archive = tar::Archive::new(GzDecoder::new(&bytes[..]));
    archive.unpack(&root)?;

    // Make the extraction world-readable/traversable (never world-writable) so a
    // target JVM of any uid can dlopen libasyncProfiler.so (see `cache_dir`).
    set_tree_world_readable(&asset_dir);

    let asprof = asset_dir.join("bin/asprof");
    if !asprof.is_file() {
        return Err(Error::other(format!(
            "async-profiler extracted but {} is missing",
            asprof.display()
        )));
    }
    // Final gate: the resolved binary chain must be trusted before we return it
    // for execution.
    if !is_trusted_cache_path(&asprof) {
        return Err(Error::other(
            "async-profiler cache failed the trust check after extraction",
        ));
    }
    eprintln!("async-profiler: cached at {}", asprof.display());
    Ok(asprof)
}

/// Best-effort recursive `a+rX`: dirs and executables become world-rx, regular
/// files world-r, so any uid can read/execute the extracted async-profiler.
fn set_tree_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            return;
        }
        let mode = md.permissions().mode();
        let add = if md.is_dir() || mode & 0o111 != 0 {
            0o555
        } else {
            0o444
        };
        let mut perm = md.permissions();
        perm.set_mode(mode | add);
        let _ = std::fs::set_permissions(path, perm);
        if md.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten() {
                    set_tree_world_readable(&e.path());
                }
            }
        }
    }
}

/// A running async-profiler attach. Profiles for a fixed duration, then exits;
/// [`Session::finish`] waits for it and returns the re-rooted folded stacks.
pub struct Session {
    child: Child,
    output: PathBuf,
    root: String,
    pid: u32,
}

impl Session {
    /// Attach async-profiler to `pid` for `duration_ms`, sampling `event`
    /// (e.g. `"cpu"`, `"wall"`, `"alloc"`), writing collapsed output to a temp
    /// file. `root` is prepended to every folded stack so the JVM's frames land
    /// under one flamegraph root consistent with profile-bee's output.
    ///
    /// `interval_ns`, when non-zero, sets async-profiler's sampling interval
    /// (`-i`) so its rate matches the eBPF `--frequency` (interval = 1e9 / Hz);
    /// otherwise async-profiler's own default interval is used.
    pub fn start(
        asprof: &Path,
        pid: u32,
        duration_ms: u64,
        event: &str,
        interval_ns: u64,
        root: String,
    ) -> std::io::Result<Session> {
        let secs = duration_ms.div_ceil(1000).max(1);
        let output = std::env::temp_dir().join(format!("probee-asprof-{pid}.folded"));
        let _ = std::fs::remove_file(&output);
        let mut cmd = Command::new(asprof);
        cmd.arg("-d")
            .arg(secs.to_string())
            .arg("-e")
            .arg(event)
            .arg("-o")
            .arg("collapsed")
            .arg("-f")
            .arg(&output);
        if interval_ns > 0 {
            // async-profiler `-i` is in nanoseconds for time-based events.
            cmd.arg("-i").arg(interval_ns.to_string());
        }
        let child = cmd.arg(pid.to_string()).spawn()?;
        Ok(Session {
            child,
            output,
            root,
            pid,
        })
    }

    /// The profiled PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the profiling window to complete, then read and re-root the
    /// folded output. Returns one `stack;… count` line per collapsed entry.
    pub fn finish(mut self) -> std::io::Result<Vec<String>> {
        let status = self.child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "asprof exited with status {status}"
            )));
        }
        let text = std::fs::read_to_string(&self.output)?;
        let _ = std::fs::remove_file(&self.output);
        Ok(reroot_folded(&text, &self.root))
    }
}

/// Prefix each folded line's stack with `root`, preserving the trailing count.
fn reroot_folded(text: &str, root: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| reroot_line(line, root))
        .collect()
}

/// `"a;b 5"` + root `"java (12)"` -> `Some("java (12);a;b 5")`.
/// Returns `None` for blank lines or lines without a trailing integer count.
fn reroot_line(line: &str, root: &str) -> Option<String> {
    let line = line.trim_end();
    if line.is_empty() {
        return None;
    }
    let (stack, count) = line.rsplit_once(' ')?;
    if stack.is_empty() || count.parse::<u64>().is_err() {
        return None;
    }
    Some(format!("{root};{stack} {count}"))
}

/// Extract the process id from a folded line's root frame, which under
/// `--group-by-process` is `"<comm> (<pid>)"` (the pid is the trailing
/// parenthesized integer of the first `;`-separated segment). Used to attribute
/// eBPF folded lines to a process so async-profiler output can replace them
/// per-pid. Returns `None` if the root has no `(<int>)` suffix.
pub fn folded_line_pid(line: &str) -> Option<u32> {
    let root = line.split(';').next()?;
    let open = root.rfind('(')?;
    let close = root[open + 1..].find(')')? + open + 1;
    root[open + 1..close].parse::<u32>().ok()
}

/// System-wide merge: replace the eBPF folded stacks of every process in
/// `attached` with async-profiler's folded output for that pid, keeping eBPF
/// stacks for all other processes (native code, and JVMs that couldn't be
/// attached). `attached` maps pid -> already-re-rooted folded lines.
pub fn merge_system_wide(ebpf: Vec<String>, attached: &HashMap<u32, Vec<String>>) -> Vec<String> {
    let mut out: Vec<String> = ebpf
        .into_iter()
        .filter(|line| folded_line_pid(line).is_none_or(|pid| !attached.contains_key(&pid)))
        .collect();
    for lines in attached.values() {
        out.extend(lines.iter().cloned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reroot_basic() {
        assert_eq!(
            reroot_line("start;Main.run;fib 42", "java (7)"),
            Some("java (7);start;Main.run;fib 42".to_string())
        );
    }

    #[test]
    fn reroot_single_frame() {
        assert_eq!(
            reroot_line("Interpreter 3", "java (7)"),
            Some("java (7);Interpreter 3".to_string())
        );
    }

    #[test]
    fn reroot_rejects_malformed() {
        assert_eq!(reroot_line("", "r"), None);
        assert_eq!(reroot_line("no_count", "r"), None);
        assert_eq!(reroot_line("a;b notanumber", "r"), None);
    }

    #[test]
    fn reroot_folded_multi() {
        let text = "a;b 5\n\nc 2\nbad line here\n";
        let out = reroot_folded(text, "P (1)");
        assert_eq!(
            out,
            vec!["P (1);a;b 5".to_string(), "P (1);c 2".to_string()]
        );
    }

    #[test]
    fn folded_pid_parsing() {
        assert_eq!(folded_line_pid("java (2856450);main;fib 5"), Some(2856450));
        // Thread comm with a space/# still resolves via the trailing (pid).
        assert_eq!(folded_line_pid("GC Thread#0 (42);a;b 1"), Some(42));
        // Root-only line keeps its count after the ')'.
        assert_eq!(folded_line_pid("java (7) 3"), Some(7));
        // No pid in root -> None (line is kept during merge).
        assert_eq!(folded_line_pid("bash;main 9"), None);
        assert_eq!(folded_line_pid("swapper 1"), None);
    }

    #[test]
    fn merge_replaces_attached_pids_only() {
        let ebpf = vec![
            "java (10);GcBurn.main 5".to_string(), // attached JVM -> dropped
            "GC Thread#0 (10);gc 3".to_string(),   // same JVM, another thread -> dropped
            "nginx (20);worker 7".to_string(),     // not attached -> kept
            "bash;sh 1".to_string(),               // no pid root -> kept
        ];
        let mut attached = HashMap::new();
        attached.insert(
            10u32,
            vec!["java (10);start;GcBurn.main;alloc 42".to_string()],
        );
        let out = merge_system_wide(ebpf, &attached);
        assert!(out.contains(&"nginx (20);worker 7".to_string()));
        assert!(out.contains(&"bash;sh 1".to_string()));
        assert!(out.contains(&"java (10);start;GcBurn.main;alloc 42".to_string()));
        // Both eBPF lines for pid 10 were replaced.
        assert!(!out.iter().any(|l| l == "java (10);GcBurn.main 5"));
        assert!(!out.iter().any(|l| l == "GC Thread#0 (10);gc 3"));
        assert_eq!(out.len(), 3);
    }
}
