//! Process output capture buffer for displaying child process stdout/stderr in the TUI.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Maximum number of lines retained in the output buffer.
const MAX_OUTPUT_LINES: usize = 10_000;

/// Which stream a line of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// A single line of captured process output.
#[derive(Debug, Clone)]
pub struct OutputLine {
    pub text: String,
    pub stream: OutputStream,
}

/// Thread-safe handle to a shared [`ProcessOutputBuffer`].
pub type SharedOutputBuffer = Arc<Mutex<ProcessOutputBuffer>>;

/// Ring buffer that accumulates process output lines.
///
/// When the buffer exceeds [`MAX_OUTPUT_LINES`], the oldest lines are dropped.
#[derive(Debug)]
pub struct ProcessOutputBuffer {
    lines: VecDeque<OutputLine>,
    /// Monotonically increasing counter — bumped on every push.
    version: u64,
}

impl ProcessOutputBuffer {
    pub fn new() -> Self {
        Self {
            lines: VecDeque::with_capacity(1024),
            version: 0,
        }
    }

    /// Create a new `SharedOutputBuffer` (the typical entry point).
    pub fn shared() -> SharedOutputBuffer {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Append one line, evicting the oldest if at capacity.
    pub fn push(&mut self, text: String, stream: OutputStream) {
        if self.lines.len() >= MAX_OUTPUT_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(OutputLine { text, stream });
        self.version = self.version.wrapping_add(1);
    }

    /// Number of lines currently stored.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Current version counter — callers can compare against a previously
    /// stored value to detect new output without copying the whole buffer.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Borrow the lines as a slice (contiguous because VecDeque may not be;
    /// callers should use `iter()` instead).
    pub fn iter(&self) -> impl Iterator<Item = &OutputLine> {
        self.lines.iter()
    }

    /// Get a specific line by index.
    pub fn get(&self, index: usize) -> Option<&OutputLine> {
        self.lines.get(index)
    }
}

impl Default for ProcessOutputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// UI state for the process-output view and split panel.
#[derive(Debug, Clone)]
pub struct ProcessOutputState {
    /// Lines scrolled up from the bottom.  0 = following the tail.
    pub scroll_offset: usize,
    /// When true the view auto-scrolls to the newest line on each tick.
    pub auto_scroll: bool,
    /// Whether the bottom split panel is visible (toggled with `o`).
    pub show_panel: bool,
    /// Last-seen buffer version — used to detect new output and set `dirty`.
    pub last_seen_version: u64,
    /// Last-seen total line count — used to adjust scroll_offset when paused.
    pub last_seen_total: usize,
}

impl Default for ProcessOutputState {
    fn default() -> Self {
        Self {
            scroll_offset: 0,
            auto_scroll: true,
            show_panel: false,
            last_seen_version: 0,
            last_seen_total: 0,
        }
    }
}

impl ProcessOutputState {
    /// Scroll up by `n` lines (moves away from the tail).
    pub fn scroll_up(&mut self, n: usize, total_lines: usize, visible_lines: usize) {
        self.auto_scroll = false;
        let max_offset = total_lines.saturating_sub(visible_lines);
        self.scroll_offset = (self.scroll_offset + n).min(max_offset);
    }

    /// Scroll down by `n` lines (moves toward the tail).
    pub fn scroll_down(&mut self, n: usize) {
        if n >= self.scroll_offset {
            self.scroll_offset = 0;
            self.auto_scroll = true;
        } else {
            self.scroll_offset -= n;
        }
    }

    /// Jump to the bottom and re-enable auto-scroll.
    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
        self.auto_scroll = true;
    }

    /// Jump to the top.
    pub fn scroll_to_top(&mut self, total_lines: usize, visible_lines: usize) {
        self.auto_scroll = false;
        self.scroll_offset = total_lines.saturating_sub(visible_lines);
    }

    /// Adjust scroll_offset when new lines arrive while paused.
    ///
    /// When `auto_scroll` is false the viewport should stay on the same
    /// absolute lines.  Since `scroll_offset` is measured from the bottom,
    /// new lines appended to the tail would shift the viewport downward
    /// unless we compensate by bumping `scroll_offset` by the delta.
    pub fn adjust_for_new_lines(&mut self, new_total: usize) {
        let old_total = self.last_seen_total;
        self.last_seen_total = new_total;
        if !self.auto_scroll && new_total > old_total {
            self.scroll_offset += new_total - old_total;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_push_and_eviction() {
        let mut buf = ProcessOutputBuffer::new();
        for i in 0..MAX_OUTPUT_LINES + 100 {
            buf.push(format!("line {i}"), OutputStream::Stdout);
        }
        assert_eq!(buf.len(), MAX_OUTPUT_LINES);
        // Oldest surviving line should be "line 100"
        assert_eq!(buf.get(0).unwrap().text, "line 100");
    }

    #[test]
    fn version_increments() {
        let mut buf = ProcessOutputBuffer::new();
        assert_eq!(buf.version(), 0);
        buf.push("a".into(), OutputStream::Stdout);
        assert_eq!(buf.version(), 1);
        buf.push("b".into(), OutputStream::Stderr);
        assert_eq!(buf.version(), 2);
    }

    #[test]
    fn scroll_state() {
        let mut state = ProcessOutputState::default();
        assert!(state.auto_scroll);

        // Scroll up disables auto-scroll
        state.scroll_up(5, 100, 20);
        assert!(!state.auto_scroll);
        assert_eq!(state.scroll_offset, 5);

        // Scroll down partially
        state.scroll_down(3);
        assert!(!state.auto_scroll);
        assert_eq!(state.scroll_offset, 2);

        // Scroll to bottom re-enables auto-scroll
        state.scroll_to_bottom();
        assert!(state.auto_scroll);
        assert_eq!(state.scroll_offset, 0);
    }
}
