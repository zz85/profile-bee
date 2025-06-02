use std::io::{self, BufRead, Error, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc::{self, Receiver, Sender};

pub struct Nothing;

#[derive(Clone)]
pub struct StopHandler {
    tx: Sender<Nothing>,
}

impl StopHandler {
    fn stop(&self) {
        println!("stopping...");
        let _ = self.tx.try_send(Nothing);
    }
}

impl Drop for StopHandler {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct SpawnProcess {
    child: Child,
    running: Arc<AtomicBool>,
    stopper_rx: Receiver<Nothing>,
}

impl SpawnProcess {
    pub fn spawn(program: &str, args: &[&str]) -> Result<(u32, Self, StopHandler), Error> {
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel::<Nothing>(1);

        let child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let pid = child.id();

        let stop = StopHandler { tx };

        Ok((
            pid,
            Self {
                child,
                running,
                stopper_rx: rx,
            },
            stop,
        ))
    }

    fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn kill(&mut self) -> Result<(), Error> {
        if !self.running() {
            println!("already stopped");
            return Ok(());
        }
        self.running.store(false, Ordering::SeqCst);
        println!("killing...");
        let r = self.child.kill();
        println!("done...");
        r
    }

    /// Spawn new thread to monitor output in real-time
    pub fn monitor(&mut self) {
        if let Some(stdout) = self.child.stdout.take() {
            std::thread::spawn(move || {
                let mut reader = io::BufReader::new(stdout);
                let mut buffer = String::new();
                while let Ok(n) = reader.read_line(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    print!("{}", buffer);
                    buffer.clear();
                }
            });
        }
    }

    pub fn monitor_stderr(&mut self) {
        if let Some(stderr) = self.child.stderr.take() {
            std::thread::spawn(move || {
                let mut reader = io::BufReader::new(stderr);
                let mut buffer = String::new();
                while let Ok(n) = reader.read_line(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    eprint!("{}", buffer);
                    buffer.clear();
                }
            });
        }
    }

    pub fn close_signal(&mut self) -> Result<(), Error> {
        loop {
            match self.stopper_rx.try_recv() {
                Ok(_) => {
                    println!("close signal done...");
                    return self.kill();
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    if !self.running() {
                        println!("No running");
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    println!("Disconnected");
                    return self.kill();
                }
            }
        }

        Ok(())
    }

    // Wait for the command to complete
    pub fn wait(&mut self) -> Result<(), Error> {
        let _status = self.child.wait()?;
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for SpawnProcess {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
