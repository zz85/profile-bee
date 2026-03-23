use std::io::Error;
// use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::{Child, Command};

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
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel::<Nothing>(1);

        let child = Command::new(program)
            .args(args)
            // .stdout(Stdio::piped())
            // .stderr(Stdio::piped())
            .spawn()?;

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

    // Spawn new thread to monitor output in real-time
    // pub fn monitor(&mut self) {
    //     if let Some(stdout) = self.child.stdout.take() {
    //         std::thread::spawn(move || {
    //             let mut reader = io::BufReader::new(stdout);
    //             let mut buffer = String::new();
    //             while let Ok(n) = reader.read_line(&mut buffer) {
    //                 if n == 0 {
    //                     break;
    //                 }
    //                 print!("{}", buffer);
    //                 buffer.clear();
    //             }
    //         });
    //     }
    // }

    // pub fn monitor_stderr(&mut self) {
    //     if let Some(stderr) = self.child.stderr.take() {
    //         std::thread::spawn(move || {
    //             let mut reader = io::BufReader::new(stderr);
    //             let mut buffer = String::new();
    //             while let Ok(n) = reader.read_line(&mut buffer) {
    //                 if n == 0 {
    //                     break;
    //                 }
    //                 eprint!("{}", buffer);
    //                 buffer.clear();
    //             }
    //         });
    //     }
    // }

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
pub fn setup_process_to_profile(
    cmd: &Option<String>,
    command: &[String],
) -> anyhow::Result<(Option<StopHandler>, Option<SpawnProcess>)> {
    // Prefer the new command format (--) over the old --cmd format
    if !command.is_empty() {
        let program = &command[0];
        let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();

        tracing::info!("Running command: {} {}", program, args.join(" "));

        let (child, stopper) = SpawnProcess::spawn(program, &args)?;
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
        let (child, stopper) = SpawnProcess::spawn(args[0], &args[1..])?;

        tracing::info!("Profiling PID {}..", child.pid());

        Ok((Some(stopper), Some(child)))
    } else {
        Ok((None, None))
    }
}
