//! Java / HotSpot JVM profiling support.
//!
//! # Architecture (phased)
//!
//! ```text
//! Phase 1 (this module + perf_map):
//!   Detect JVM processes → load /tmp/perf-<pid>.map → resolve JIT PCs
//!   Auto-dump maps via jcmd / HotSpot attach (system-wide, no manual jcmd)
//!
//! Phase 2 (future): HotSpot VM-struct introspection in userspace
//!   Parse gHotSpotVMStructs from libjvm.so → remote Method*/nmethod* reads
//!
//! Phase 3 (future): eBPF HotSpot unwinder (OTel eBPF Profiler model)
//!   Code-cache aware frame walk + cookies → userspace symbolize
//! ```
//!
//! See `docs/java_profiling.md`.

pub mod async_profiler;
mod attach;
mod vmstructs;

pub use vmstructs::{VmOffsets, VmStructsReader};

pub use attach::{
    bootstrap_system_java_maps, discover_jvm_pids, ensure_perf_map, has_usable_perf_map,
    namespace_pids, refresh_perf_map, PerfMapEnsureResult,
};

use procfs::process::{MMapPath, Process};
use std::path::{Path, PathBuf};

/// Return the mapped `libjvm.so` pathname (as recorded in `/proc/<pid>/maps`),
/// if the process maps one.
///
/// Uses `procfs` — the codebase's standard maps parser — so pathnames
/// containing spaces are preserved (raw whitespace-splitting truncated them)
/// and the trailing ` (deleted)` marker on unlinked mappings is stripped.
fn mapped_libjvm_path(pid: u32) -> Option<String> {
    let process = Process::new(pid as i32).ok()?;
    let maps = process.maps().ok()?;
    for map in maps.iter() {
        if let MMapPath::Path(p) = &map.pathname {
            let raw = p.to_string_lossy();
            let path = raw.strip_suffix(" (deleted)").unwrap_or(&raw);
            if path.ends_with("libjvm.so") {
                return Some(path.to_string());
            }
        }
    }
    None
}

/// Return true if `exe` looks like a HotSpot/OpenJDK `java` launcher.
///
/// This deliberately recognizes only the launcher itself — matching on the
/// file name, which already covers absolute paths like
/// `/usr/lib/jvm/java-21-openjdk/bin/java`. It must NOT match sibling tools
/// such as `javac`, `javadoc`, or `javap`, nor unrelated names like
/// `javascript`. (Real JVMs are still detected by their mapped `libjvm.so`
/// via [`process_has_libjvm`]; this name check is only a supplementary hint.)
pub fn is_java_binary(exe: &Path) -> bool {
    let name = exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(name.as_str(), "java" | "javaw" | "java.exe" | "javaw.exe")
        // Versioned launchers, e.g. `java-21` / `java-1.8.0`.
        || (name.starts_with("java-")
            && name["java-".len()..]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.'))
}

/// Return true if the process maps `libjvm.so`.
pub fn process_has_libjvm(pid: u32) -> bool {
    mapped_libjvm_path(pid).is_some()
}

/// Detect whether `pid` is a JVM worth enabling Java/JIT support for.
pub fn is_jvm_process(pid: u32) -> bool {
    if process_has_libjvm(pid) {
        return true;
    }
    let exe_link = format!("/proc/{}/exe", pid);
    if let Ok(exe) = std::fs::read_link(&exe_link) {
        if is_java_binary(&exe) {
            return true;
        }
    }
    false
}

/// Path to `libjvm.so` for a process, if mapped.
///
/// Prefers the container view (`/proc/<pid>/root/...`) when that file exists,
/// otherwise falls back to the host path.
pub fn find_libjvm_path(pid: u32) -> Option<PathBuf> {
    let path = mapped_libjvm_path(pid)?;
    let container = PathBuf::from(format!("/proc/{}/root{}", pid, path));
    if container.is_file() {
        return Some(container);
    }
    Some(PathBuf::from(path))
}

/// Best-effort human label for a JVM process (for logs).
pub fn describe_jvm(pid: u32) -> String {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown".into());
    let libjvm = find_libjvm_path(pid)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "libjvm.so (path unknown)".into());
    format!("pid={pid} exe={exe} libjvm={libjvm}")
}

/// Format a symbol that may be Java/JIT-related for display.
pub fn format_java_symbol(raw: &str) -> String {
    let formatted = crate::perf_map::format_jit_symbol(raw);
    if is_jvm_runtime_stub(&formatted) {
        format!("[jvm] {formatted}")
    } else {
        formatted
    }
}

fn is_jvm_runtime_stub(name: &str) -> bool {
    matches!(
        name,
        "Interpreter"
            | "I2C/C2I adapters"
            | "vtable chunks"
            | "method entries"
            | "BufferBlob"
            | "RuntimeStub"
            | "DeoptimizationBlob"
            | "UncommonTrapBlob"
            | "ExceptionBlob"
            | "SafepointBlob"
    ) || name.starts_with("StubRoutines")
        || name.contains("Adapter for")
}

/// Hint text shown once when automatic dump failed.
pub const PERF_MAP_HINT: &str = "\
JVM detected but automatic Compiler.perfmap dump failed.
profile-bee tried jcmd, process JAVA_HOME jcmd, HotSpot attach, and nsenter.
You can retry manually: jcmd <pid> Compiler.perfmap
Prefer -XX:+PreserveFramePointer on the JVM for better mixed stacks.
See docs/java_profiling.md";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_java_binaries() {
        assert!(is_java_binary(Path::new("/usr/bin/java")));
        assert!(is_java_binary(Path::new(
            "/usr/lib/jvm/java-21-openjdk/bin/java"
        )));
        assert!(is_java_binary(Path::new("javaw")));
        assert!(is_java_binary(Path::new("/opt/jdk/bin/java-21")));
        assert!(!is_java_binary(Path::new("/usr/bin/python3")));
        assert!(!is_java_binary(Path::new("/usr/bin/node")));
        // Siblings of the launcher must not be treated as JVM launchers,
        // even though their path contains "/bin/java".
        assert!(!is_java_binary(Path::new("/usr/bin/javac")));
        assert!(!is_java_binary(Path::new("/usr/bin/javadoc")));
        assert!(!is_java_binary(Path::new("/usr/bin/javap")));
        assert!(!is_java_binary(Path::new("/usr/bin/javascript")));
    }

    #[test]
    fn formats_java_symbols() {
        assert_eq!(
            format_java_symbol("Ljava/util/HashMap;get"),
            "java.util.HashMap.get"
        );
        assert!(format_java_symbol("Interpreter").contains("jvm"));
    }
}
