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
//! Scope: batch (collapse/svg/json) output only; streaming/serve/TUI is a
//! follow-up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Locate the async-profiler launcher: `$ASPROF`, then `asprof`/`profiler.sh`
/// on `$PATH`, then a couple of common install roots.
pub fn find_asprof() -> Option<PathBuf> {
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
    None
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
    pub fn start(
        asprof: &Path,
        pid: u32,
        duration_ms: u64,
        event: &str,
        root: String,
    ) -> std::io::Result<Session> {
        let secs = duration_ms.div_ceil(1000).max(1);
        let output = std::env::temp_dir().join(format!("probee-asprof-{pid}.folded"));
        let _ = std::fs::remove_file(&output);
        let child = Command::new(asprof)
            .arg("-d")
            .arg(secs.to_string())
            .arg("-e")
            .arg(event)
            .arg("-o")
            .arg("collapsed")
            .arg("-f")
            .arg(&output)
            .arg(pid.to_string())
            .spawn()?;
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
