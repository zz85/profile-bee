//! Java / HotSpot JVM profiling support.
//!
//! # Architecture (phased)
//!
//! ```text
//! Phase 1 (this module + perf_map):
//!   Detect JVM processes → load /tmp/perf-<pid>.map → resolve JIT PCs
//!
//! Phase 2 (future): HotSpot VM-struct introspection in userspace
//!   Parse gHotSpotVMStructs from libjvm.so → remote Method*/nmethod* reads
//!
//! Phase 3 (future): eBPF HotSpot unwinder (OTel eBPF Profiler model)
//!   Code-cache aware frame walk + cookies → userspace symbolize
//! ```
//!
//! Phase 1 is non-intrusive and matches the Linux perf JIT interface that
//! HotSpot can emit. Enable maps with:
//! ```text
//! jcmd <pid> Compiler.perfmap
//! # or:
//! java -XX:+PreserveFramePointer ...
//! ```
//!
//! See `docs/java_profiling.md`.

use std::path::Path;

/// Return true if `exe` looks like a HotSpot/OpenJDK `java` launcher.
pub fn is_java_binary(exe: &Path) -> bool {
    let name = exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "java" || name == "java.exe" {
        return true;
    }
    let path = exe.to_string_lossy().to_ascii_lowercase();
    path.ends_with("/java") || path.contains("/bin/java")
}

/// Return true if `/proc/<pid>/maps` references `libjvm.so`.
pub fn process_has_libjvm(pid: u32) -> bool {
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(contents) = std::fs::read_to_string(&maps_path) else {
        return false;
    };
    contents.lines().any(|line| line.contains("libjvm.so"))
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
pub fn find_libjvm_path(pid: u32) -> Option<std::path::PathBuf> {
    let maps_path = format!("/proc/{}/maps", pid);
    let contents = std::fs::read_to_string(maps_path).ok()?;
    for line in contents.lines() {
        if let Some(path) = line.split_whitespace().last() {
            if path.ends_with("libjvm.so") {
                let container = std::path::PathBuf::from(format!("/proc/{}/root{}", pid, path));
                if container.is_file() {
                    return Some(container);
                }
                let host = std::path::PathBuf::from(path);
                if host.is_file() {
                    return Some(host);
                }
                return Some(host);
            }
        }
    }
    None
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

/// Hint text shown once when a JVM is detected without a perf-map.
pub const PERF_MAP_HINT: &str = "\
JVM detected but no /tmp/perf-<pid>.map found. To enable Java method names:
  jcmd <pid> Compiler.perfmap
  # or start with frame pointers:
  java -XX:+PreserveFramePointer ...
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
        assert!(!is_java_binary(Path::new("/usr/bin/python3")));
        assert!(!is_java_binary(Path::new("/usr/bin/node")));
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
