# Answer: Does profile-bee terminate gracefully when the target PID exits?

## Short Answer

**Yes, profile-bee does terminate gracefully when the target PID exits.**

## Detailed Explanation

When profiling specific processes (using `--cmd` to spawn a command or `--pid` to attach to an existing process), profile-bee has built-in logic to detect when the target process completes and gracefully shut down the profiler.

### How it works

The termination logic is implemented in the `setup_stopping_mechanisms` function in `profile-bee/bin/profile-bee.rs` (lines 256-294). Profile-bee supports **three different stopping mechanisms**:

1. **Timer-based stopping**: When the specified `--time` duration expires
2. **Ctrl-C signal**: When the user sends an interrupt signal
3. **Child process completion**: When the target process exits (for `--cmd` spawned processes)

### Code Implementation

For spawned processes (`--cmd`), the relevant code is:

```rust
// Child process completion stopping
if let Some(mut child) = spawn {
    let child_stopper_tx = perf_tx.clone();
    tokio::spawn(async move {
        child.work_done().await;
        child_stopper_tx.send(PerfWork::Stop).unwrap_or_default();
    });
}
```

The `work_done()` method (in `profile-bee/src/spawn.rs`, lines 82-103) monitors the child process:

```rust
pub async fn work_done(&mut self) {
    tokio::select! {
        _ = self.child.wait() => {
            // Listen to when process stops
            println!("Child process stopped");
            self.running.store(false, Ordering::SeqCst);
        },
        stopper = self.stopper_rx.recv() => {
            // Handle external stop signals
            // ...
        }
    }
}
```

This implementation:
- Uses `tokio::select!` to asynchronously wait for either:
  - The child process to exit naturally (`self.child.wait()`)
  - An external stop signal
- When the child process exits, it prints "Child process stopped"
- Sends a `PerfWork::Stop` message to the main profiling loop
- The profiler then gracefully processes all collected data and exits

### What happens on termination

When the target PID exits:

1. The monitoring task detects the process exit
2. A `Stop` message is sent through the internal channel
3. The profiling loop receives the `Stop` message (line 370: `PerfWork::Stop => break`)
4. All collected stack traces are processed
5. Output files are generated (SVG, HTML, JSON, collapsed format as requested)
6. Statistics are printed
7. The profiler exits cleanly

### Limitations

For **externally specified PIDs** (using `--pid <pid>` without `--cmd`), the current implementation does **not** actively monitor whether the PID is still alive. The profiler will continue running for the specified `--time` duration even if the target process exits early. This is because:

- The code only sets up the child process monitor for spawned processes (`if let Some(mut child) = spawn`)
- For external PIDs, profile-bee relies on the timer or Ctrl-C to stop

### Summary

- **For `--cmd` spawned processes**: ✅ Gracefully terminates when the process exits
- **For `--pid` attached processes**: ⚠️ Continues until timer expires or Ctrl-C (does not detect PID exit)

## Example Usage

```bash
# This will automatically stop when 'sleep 2' completes
# (even if --time is set to 10000ms)
profile-bee --cmd "sleep 2" --svg output.svg --time 10000

# This will run for the full 10 seconds even if PID 1234 exits earlier
profile-bee --pid 1234 --svg output.svg --time 10000
```

## Recommendation

If you need profile-bee to detect when an externally-specified PID exits, consider:
1. Using a shorter `--time` value
2. Monitoring the process yourself and sending Ctrl-C to profile-bee when it exits
3. Filing a feature request to add PID monitoring for `--pid` mode
