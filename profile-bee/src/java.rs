//! HotSpot JVM detection and perf-map integration.
//!
//! A JVM can publish its JIT code cache through the standard
//! `/tmp/perf-<pid>.map` format. `blazesym` consumes that format through the
//! existing process symbolization path, so no special symbolizer is needed.

use std::path::{Path, PathBuf};

/// Return whether a binary name identifies the HotSpot Java launcher.
///
/// This intentionally recognizes only launchers, not arbitrary binaries whose
/// name happens to contain "java".
pub fn is_hotspot_binary(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    matches!(name, "java" | "javaw" | "java.exe" | "javaw.exe")
        || (name.starts_with("java-")
            && name[5..]
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.'))
}

/// Return the conventional perf-map path for a process.
pub fn perf_map_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/perf-{pid}.map"))
}

/// Add `-XX:+PreserveFramePointer` unless it is already present.
pub fn java_tool_options_with_frame_pointers(existing: Option<String>) -> String {
    const FLAG: &str = "-XX:+PreserveFramePointer";

    match existing {
        Some(mut options) if !options.is_empty() => {
            if !options.split_whitespace().any(|option| option == FLAG) {
                options.push(' ');
                options.push_str(FLAG);
            }
            options
        }
        _ => FLAG.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hotspot_launchers_without_matching_unrelated_names() {
        assert!(is_hotspot_binary(Path::new("/usr/bin/java")));
        assert!(is_hotspot_binary(Path::new("/usr/bin/java-21")));
        assert!(is_hotspot_binary(Path::new("javaw")));
        assert!(!is_hotspot_binary(Path::new("/usr/bin/javascript")));
        assert!(!is_hotspot_binary(Path::new("/usr/bin/javac")));
    }

    #[test]
    fn adds_frame_pointer_flag_once() {
        assert_eq!(
            java_tool_options_with_frame_pointers(Some("-Xmx1g".to_string())),
            "-Xmx1g -XX:+PreserveFramePointer"
        );
        assert_eq!(
            java_tool_options_with_frame_pointers(Some(
                "-XX:+PreserveFramePointer -Xmx1g".to_string()
            )),
            "-XX:+PreserveFramePointer -Xmx1g"
        );
    }
}
