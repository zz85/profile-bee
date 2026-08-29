use std::io::Error;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};

use tokio::sync::mpsc::{self, Receiver, Sender};

pub struct Nothing;

#[derive(Clone)]
pub struct StopHandler {
    tx: Sender<Nothing>,
}

impl StopHandler {
    fn stop(&self) {
        tracing::debug!("stopping...");
        let _ = self.tx.try_send(Nothing);
    }
}

impl Drop for StopHandler {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct SpawnProcess {
    pid: u32,
    child: Child,
    running: Arc<AtomicBool>,
    stopper_rx: Receiver<Nothing>,
}

impl SpawnProcess {
    pub fn spawn(
        program: &str,
        args: &[&str],
        extra_env: &[(&str, String)],
    ) -> Result<(Self, StopHandler), Error> {
        Self::spawn_internal(program, args, false, extra_env)
    }

    /// Spawn the child with piped stdout and stderr so the parent can
    /// capture its output (e.g. for displaying in the TUI).
    pub fn spawn_captured(
        program: &str,
        args: &[&str],
        extra_env: &[(&str, String)],
    ) -> Result<(Self, StopHandler), Error> {
        Self::spawn_internal(program, args, true, extra_env)
    }

    fn spawn_internal(
        program: &str,
        args: &[&str],
        capture: bool,
        extra_env: &[(&str, String)],
    ) -> Result<(Self, StopHandler), Error> {
        use std::process::Stdio;

        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel::<Nothing>(1);

        let mut cmd = Command::new(program);
        cmd.args(args);
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        if capture {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let child = cmd.spawn()?;

        let pid = child.id().expect("pid");
        let stop = StopHandler { tx };

        Ok((
            Self {
                pid,
                child,
                running,
                stopper_rx: rx,
            },
            stop,
        ))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Take the child's piped stdout handle.
    /// Only available after `spawn_captured()`; returns `None` if stdio was
    /// inherited or already taken.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's piped stderr handle.
    /// Only available after `spawn_captured()`; returns `None` if stdio was
    /// inherited or already taken.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    async fn kill(&mut self) -> Result<(), Error> {
        if !self.running() {
            tracing::debug!("already stopped");
            return Ok(());
        }
        self.running.store(false, Ordering::SeqCst);
        tracing::debug!("killing child process...");
        let r = self.child.kill().await;
        tracing::debug!("child process killed");
        r
    }

    pub async fn work_done(&mut self) {
        tokio::select! {
            _ = self.child.wait() => {
                // Listen to when process stops
                tracing::info!("Child process stopped");
                self.running.store(false, Ordering::SeqCst);
            },
            stopper = self.stopper_rx.recv() => {
                match stopper {
                    // listen on stop signals from other applications
                    Some(_) => {
                        tracing::debug!("close signal received, killing child");
                        let _ = self.kill().await;
                    }
                    None => {
                        tracing::debug!("stopper channel disconnected, killing child");
                        let _ = self.kill().await;
                    }
                }
            }
        }
    }

    pub async fn close_signal(&mut self) -> Result<(), Error> {
        match self.stopper_rx.recv().await {
            Some(_) => {
                tracing::debug!("close signal received, killing child");
                return self.kill().await;
            }
            None => {
                tracing::debug!("stopper channel disconnected, killing child");
                return self.kill().await;
            }
        }
    }

    // Wait for the command to complete
    pub async fn wait(&mut self) -> Result<(), Error> {
        let _status = self.child.wait().await?;
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for SpawnProcess {
    fn drop(&mut self) {
        drop(self.kill());
    }
}

/// Check if a program name looks like Node.js.
fn is_nodejs_program(program: &str) -> bool {
    let basename = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    matches!(basename, "node" | "nodejs" | "nsolid")
}

/// Add `-XX:+PreserveFramePointer` to a `JAVA_TOOL_OPTIONS` value unless it is
/// already present. Preserving the frame pointer (JDK 8u60+, usually <1%
/// overhead) is what lets the frame-pointer unwinder walk through JIT-compiled
/// Java frames — see docs/java_profiling.md and Brendan Gregg's CPU flame
/// graph notes.
fn java_tool_options_with_frame_pointers(existing: Option<String>) -> String {
    const FLAG: &str = "-XX:+PreserveFramePointer";
    match existing {
        Some(options) if !options.is_empty() => {
            if options.split_whitespace().any(|opt| opt == FLAG) {
                options
            } else {
                format!("{options} {FLAG}")
            }
        }
        _ => FLAG.to_string(),
    }
}

/// Build extra environment variables for runtime-specific profiling support.
///
/// For Node.js processes, injects `NODE_OPTIONS` with `--perf-basic-prof`
/// (writes `/tmp/perf-<pid>.map` for JIT symbol resolution) and
/// `--interpreted-frames-native-stack` (enables frame pointers in interpreted
/// frames for reliable stack unwinding).
///
/// For HotSpot JVMs, injects `JAVA_TOOL_OPTIONS=-XX:+PreserveFramePointer` so
/// the frame-pointer unwinder can traverse JIT-compiled Java frames.
///
/// Merges with any existing `NODE_OPTIONS` / `JAVA_TOOL_OPTIONS` from the
/// parent environment.
fn build_runtime_env(program: &str) -> Vec<(&'static str, String)> {
    let mut env = Vec::new();

    if is_nodejs_program(program) {
        // --perf-basic-prof: writes /tmp/perf-<pid>.map with JIT symbol addresses
        //   (NOT --perf-prof which writes a binary jitdump for `perf inject`)
        // --interpreted-frames-native-stack: use native frames for interpreted JS
        //   so the frame-pointer unwinder can walk through them
        let node_flags = "--perf-basic-prof --interpreted-frames-native-stack";

        // Merge with existing NODE_OPTIONS if set
        let value = match std::env::var("NODE_OPTIONS") {
            Ok(existing) if !existing.is_empty() => {
                // Don't duplicate flags if they're already present
                let mut combined = existing.clone();
                if !existing.contains("--perf-basic-prof") {
                    combined.push_str(" --perf-basic-prof");
                }
                if !existing.contains("--interpreted-frames-native-stack") {
                    combined.push_str(" --interpreted-frames-native-stack");
                }
                combined
            }
            _ => node_flags.to_string(),
        };

        tracing::info!(
            "Node.js detected: injecting NODE_OPTIONS=\"{}\" for JIT symbol resolution",
            value
        );
        env.push(("NODE_OPTIONS", value));
    }

    if crate::java::is_java_binary(Path::new(program)) {
        // -XX:+PreserveFramePointer keeps RBP as a real frame pointer in
        // JIT-compiled code so the FP unwinder can walk mixed native/Java
        // stacks. Merge with any inherited JAVA_TOOL_OPTIONS.
        let value = java_tool_options_with_frame_pointers(std::env::var("JAVA_TOOL_OPTIONS").ok());
        tracing::info!(
            "HotSpot JVM detected: injecting JAVA_TOOL_OPTIONS=\"{}\" for native stack unwinding",
            value
        );
        env.push(("JAVA_TOOL_OPTIONS", value));
    }

    env
}

/// Sets up the process to profile if a command is provided.
///
/// Returns `(Option<StopHandler>, Option<SpawnProcess>)`.  When no command
/// is given, both are `None`.
///
/// When `capture_output` is true, the child's stdout/stderr are piped so
/// the caller can read them (e.g. for TUI display).  Use
/// [`SpawnProcess::take_stdout`] / [`take_stderr`] to obtain the handles.
///
/// For Node.js commands, injects `NODE_OPTIONS` to enable JIT symbol
/// resolution via perf-map files; for HotSpot `java` commands, injects
/// `JAVA_TOOL_OPTIONS=-XX:+PreserveFramePointer` for native stack unwinding.
pub fn setup_process_to_profile(
    cmd: &Option<String>,
    command: &[String],
    capture_output: bool,
) -> anyhow::Result<(Option<StopHandler>, Option<SpawnProcess>)> {
    // Prefer the new command format (--) over the old --cmd format
    if !command.is_empty() {
        let program = &command[0];
        let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();

        tracing::info!("Running command: {} {}", program, args.join(" "));

        let extra_env = build_runtime_env(program);
        let spawn_fn = if capture_output {
            SpawnProcess::spawn_captured
        } else {
            SpawnProcess::spawn
        };
        let (child, stopper) = spawn_fn(program, &args, &extra_env)?;
        tracing::info!("Profiling PID {}..", child.pid());

        return Ok((Some(stopper), Some(child)));
    }

    // Fall back to old --cmd format for backward compatibility
    if let Some(cmd) = cmd {
        tracing::warn!(
            "--cmd is deprecated. Use '-- <command> <args>' instead \
             (handles quoted and complex arguments correctly)."
        );
        tracing::info!("Running cmd: {cmd}");

        // todo: use shelltools
        let args: Vec<_> = cmd.split(' ').collect();
        let extra_env = build_runtime_env(args[0]);
        let spawn_fn = if capture_output {
            SpawnProcess::spawn_captured
        } else {
            SpawnProcess::spawn
        };
        let (child, stopper) = spawn_fn(args[0], &args[1..], &extra_env)?;

        tracing::info!("Profiling PID {}..", child.pid());

        Ok((Some(stopper), Some(child)))
    } else {
        Ok((None, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_frame_pointer_flag_once() {
        assert_eq!(
            java_tool_options_with_frame_pointers(None),
            "-XX:+PreserveFramePointer"
        );
        assert_eq!(
            java_tool_options_with_frame_pointers(Some(String::new())),
            "-XX:+PreserveFramePointer"
        );
        assert_eq!(
            java_tool_options_with_frame_pointers(Some("-Xmx1g".to_string())),
            "-Xmx1g -XX:+PreserveFramePointer"
        );
        // Already present — do not duplicate.
        assert_eq!(
            java_tool_options_with_frame_pointers(Some(
                "-XX:+PreserveFramePointer -Xmx1g".to_string()
            )),
            "-XX:+PreserveFramePointer -Xmx1g"
        );
    }

    #[test]
    fn build_runtime_env_injects_java_tool_options() {
        let env = build_runtime_env("/usr/lib/jvm/java-21/bin/java");
        assert!(env
            .iter()
            .any(|(k, v)| *k == "JAVA_TOOL_OPTIONS" && v.contains("-XX:+PreserveFramePointer")));
        // javac is not a JVM launcher — no injection.
        let env = build_runtime_env("/usr/bin/javac");
        assert!(!env.iter().any(|(k, _)| *k == "JAVA_TOOL_OPTIONS"));
    }
}
