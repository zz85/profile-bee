use std::io::Error;
// use std::process::{Child, Command, Stdio};
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
    pub fn spawn(program: &str, args: &[&str]) -> Result<(Self, StopHandler), Error> {
        Self::spawn_internal(program, args, false)
    }

    /// Spawn the child with piped stdout and stderr so the parent can
    /// capture its output (e.g. for displaying in the TUI).
    pub fn spawn_captured(program: &str, args: &[&str]) -> Result<(Self, StopHandler), Error> {
        Self::spawn_internal(program, args, true)
    }

    fn spawn_internal(
        program: &str,
        args: &[&str],
        capture: bool,
    ) -> Result<(Self, StopHandler), Error> {
        use std::process::Stdio;

        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel::<Nothing>(1);

        let mut cmd = Command::new(program);
        cmd.args(args);
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

/// Sets up the process to profile if a command is provided.
///
/// Returns `(Option<StopHandler>, Option<SpawnProcess>)`.  When no command
/// is given, both are `None`.
///
/// When `capture_output` is true, the child's stdout/stderr are piped so
/// the caller can read them (e.g. for TUI display).  Use
/// [`SpawnProcess::take_stdout`] / [`take_stderr`] to obtain the handles.
pub fn setup_process_to_profile(
    cmd: &Option<String>,
    command: &[String],
    capture_output: bool,
) -> anyhow::Result<(Option<StopHandler>, Option<SpawnProcess>)> {
    let spawn_fn = if capture_output {
        SpawnProcess::spawn_captured
    } else {
        SpawnProcess::spawn
    };

    // Prefer the new command format (--) over the old --cmd format
    if !command.is_empty() {
        let program = &command[0];
        let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();

        tracing::info!("Running command: {} {}", program, args.join(" "));

        let (child, stopper) = spawn_fn(program, &args)?;
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
        let (child, stopper) = spawn_fn(args[0], &args[1..])?;

        tracing::info!("Profiling PID {}..", child.pid());

        Ok((Some(stopper), Some(child)))
    } else {
        Ok((None, None))
    }
}
