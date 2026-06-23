use crate::flame::{FlameGraph, SearchPattern, StackIdentifier};
use crate::output::{ProcessOutputState, SharedOutputBuffer};
use crate::state::{FlameGraphState, UpdateMode};
use crate::view::FlameGraphView;
use std::collections::{HashMap, VecDeque};
use std::error;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
pub enum FlameGraphInput {
    File(String),
    Live,
}

#[derive(Debug, Clone)]
pub struct StackPosition {
    pub stack_id: StackIdentifier,
    pub x: u16,
    pub y: u16,
    pub width: u16,
}

#[derive(Debug)]
pub struct ParsedFlameGraph {
    pub flamegraph: FlameGraph,
    pub elapsed: Duration,
    pub collected_at: Instant,
}

#[derive(Debug, Clone)]
struct HistoricalFlameGraph {
    flamegraph: FlameGraph,
    collected_at: Instant,
}

const LIVE_HISTORY_LIMIT: usize = 120;

#[derive(Debug)]
pub struct InputBuffer {
    pub buffer: tui_input::Input,
    pub cursor: Option<(u16, u16)>,
}

/// Application.
#[derive(Debug)]
pub struct App {
    /// Is the application running?
    pub running: bool,
    /// Flamegraph view
    pub flamegraph_view: FlameGraphView,
    /// Flamegraph input information
    pub flamegraph_input: FlameGraphInput,
    /// User input buffer
    pub input_buffer: Option<InputBuffer>,
    /// Timing information for debugging
    pub elapsed: HashMap<String, Duration>,
    /// Transient message
    pub transient_message: Option<String>,
    /// Debug mode
    pub debug: bool,
    /// Whether the UI needs to be redrawn
    pub dirty: bool,
    /// Next flamegraph to swap in
    next_flamegraph: Arc<Mutex<Option<ParsedFlameGraph>>>,
    /// Recently collected live flamegraph snapshots, oldest first.
    history: VecDeque<HistoricalFlameGraph>,
    /// Snapshot being viewed in history mode. `None` means follow live/latest.
    history_cursor: Option<usize>,
    /// Shared update mode for the profiling thread
    update_mode_handle: Arc<Mutex<UpdateMode>>,
    /// Shared pid-mode flag for the profiling thread (toggled with 'p')
    pid_mode_handle: Arc<AtomicBool>,
    /// Stack positions from last render (for mouse click handling)
    pub stack_positions: Vec<StackPosition>,
    /// Last click for double-click detection
    pub last_click: Option<(std::time::Instant, u16, u16)>,
    /// Shared process output buffer (None when no child process)
    pub process_output: Option<SharedOutputBuffer>,
    /// UI state for the process output view / split panel
    pub output_state: ProcessOutputState,
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn with_flamegraph(filename: &str, flamegraph: FlameGraph) -> Self {
        Self {
            running: true,
            flamegraph_view: FlameGraphView::new(flamegraph),
            flamegraph_input: FlameGraphInput::File(filename.to_string()),
            input_buffer: None,
            elapsed: HashMap::new(),
            transient_message: None,
            debug: false,
            dirty: true,
            next_flamegraph: Arc::new(Mutex::new(None)),
            history: VecDeque::new(),
            history_cursor: None,
            update_mode_handle: Arc::new(Mutex::new(UpdateMode::default())),
            pid_mode_handle: Arc::new(AtomicBool::new(false)),
            stack_positions: Vec::new(),
            last_click: None,
            process_output: None,
            output_state: ProcessOutputState::default(),
        }
    }

    /// Constructs a new instance for live profiling mode
    pub fn with_live() -> Self {
        Self::with_live_and_mode(UpdateMode::default())
    }

    /// Constructs a new instance for live profiling mode with specified update mode
    pub fn with_live_and_mode(update_mode: UpdateMode) -> Self {
        let flamegraph = FlameGraph::from_string("".to_string(), true);
        let state = FlameGraphState {
            update_mode,
            ..Default::default()
        };
        let update_mode_handle = Arc::new(Mutex::new(update_mode));
        Self {
            running: true,
            flamegraph_view: FlameGraphView::new_with_state(flamegraph, state),
            flamegraph_input: FlameGraphInput::Live,
            next_flamegraph: Arc::new(Mutex::new(None)),
            input_buffer: None,
            elapsed: HashMap::new(),
            transient_message: None,
            debug: false,
            dirty: true,
            update_mode_handle,
            pid_mode_handle: Arc::new(AtomicBool::new(false)),
            history: VecDeque::new(),
            history_cursor: None,
            stack_positions: Vec::new(),
            last_click: None,
            process_output: None,
            output_state: ProcessOutputState::default(),
        }
    }

    /// Constructs a new instance for live profiling with process output capture.
    pub fn with_live_and_output(
        update_mode: UpdateMode,
        output_buffer: SharedOutputBuffer,
    ) -> Self {
        let mut app = Self::with_live_and_mode(update_mode);
        app.process_output = Some(output_buffer);
        app
    }

    /// Whether this app has a process output buffer attached.
    pub fn has_output(&self) -> bool {
        self.process_output.is_some()
    }

    /// Get a handle to update the flamegraph from another thread
    pub fn get_update_handle(&self) -> Arc<Mutex<Option<ParsedFlameGraph>>> {
        self.next_flamegraph.clone()
    }

    /// Get the current update mode
    pub fn get_update_mode(&self) -> UpdateMode {
        self.flamegraph_view.state.update_mode
    }

    /// Get a handle to the update mode for sharing with the profiling thread
    pub fn get_update_mode_handle(&self) -> Arc<Mutex<UpdateMode>> {
        self.update_mode_handle.clone()
    }

    pub fn get_pid_mode_handle(&self) -> Arc<AtomicBool> {
        self.pid_mode_handle.clone()
    }

    /// Update flamegraph with new data
    pub fn update_flamegraph(&self, data: String) {
        let tic = std::time::Instant::now();
        let flamegraph = FlameGraph::from_string(data, true);
        let parsed = ParsedFlameGraph {
            flamegraph,
            elapsed: tic.elapsed(),
            collected_at: Instant::now(),
        };
        *self.next_flamegraph.lock().unwrap() = Some(parsed);
    }

    /// Handles the tick event of the terminal.
    pub fn tick(&mut self) {
        // Sync update mode from the shared handle (in case it was changed by user)
        if let Ok(mode) = self.update_mode_handle.lock() {
            if self.flamegraph_view.state.update_mode != *mode {
                self.flamegraph_view.state.update_mode = *mode;
            }
        }

        if let Some(parsed) = self.next_flamegraph.lock().unwrap().take() {
            self.elapsed
                .insert("flamegraph".to_string(), parsed.elapsed);
            self.push_history(parsed.flamegraph.clone(), parsed.collected_at);
            if !self.flamegraph_view.state.freeze && self.history_cursor.is_none() {
                let tic = Instant::now();
                self.flamegraph_view.replace_flamegraph(parsed.flamegraph);
                self.elapsed
                    .insert("replacement".to_string(), tic.elapsed());
            }
            self.dirty = true;
        }

        // Check for new process output
        if let Some(ref buf) = self.process_output {
            match buf.lock() {
                Ok(buf) => {
                    let version = buf.version();
                    if version != self.output_state.last_seen_version {
                        self.output_state.adjust_for_new_lines(buf.len());
                        self.output_state.last_seen_version = version;
                        self.dirty = true;
                    }
                }
                Err(poisoned) => {
                    // Recover from a poisoned mutex — the monitor thread may
                    // have panicked, but the data is still usable.
                    let buf = poisoned.into_inner();
                    let version = buf.version();
                    if version != self.output_state.last_seen_version {
                        self.output_state.adjust_for_new_lines(buf.len());
                        self.output_state.last_seen_version = version;
                        self.dirty = true;
                    }
                }
            }
        }
    }

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn flamegraph(&self) -> &FlameGraph {
        &self.flamegraph_view.flamegraph
    }

    pub fn flamegraph_state(&self) -> &FlameGraphState {
        &self.flamegraph_view.state
    }

    pub fn add_elapsed(&mut self, name: &str, elapsed: Duration) {
        self.elapsed.insert(name.to_string(), elapsed);
    }

    pub fn search_selected(&mut self) {
        if self.flamegraph_view.is_root_selected() {
            return;
        }
        let short_name = self.flamegraph_view.get_selected_stack().map(|s| {
            self.flamegraph()
                .get_stack_short_name_from_info(s)
                .to_string()
        });
        if let Some(short_name) = short_name {
            self.set_manual_search_pattern(short_name.as_str(), false);
        }
    }

    pub fn search_selected_row(&mut self) {
        let short_name = self
            .flamegraph_view
            .get_selected_row_name()
            .map(|s| s.to_string());
        if let Some(short_name) = short_name {
            self.set_manual_search_pattern(short_name.as_str(), false);
        }
        self.flamegraph_view.state.toggle_view_kind();
    }

    pub fn set_manual_search_pattern(&mut self, pattern: &str, is_regex: bool) {
        match SearchPattern::new(pattern, is_regex, true) {
            Ok(p) => self.flamegraph_view.set_search_pattern(p),
            Err(_) => {
                self.set_transient_message(&format!("Invalid regex: {}", pattern));
            }
        }
    }

    pub fn set_transient_message(&mut self, message: &str) {
        self.transient_message = Some(message.to_string());
    }

    pub fn clear_transient_message(&mut self) {
        self.transient_message = None;
    }

    pub fn toggle_debug(&mut self) {
        self.debug = !self.debug;
    }

    pub fn toggle_freeze(&mut self) {
        let was_frozen = self.flamegraph_view.state.freeze;
        self.flamegraph_view.state.toggle_freeze();

        if was_frozen {
            self.history_cursor = None;
            self.apply_history_cursor();
        } else if self.history_cursor.is_none() && !self.history.is_empty() {
            self.history_cursor = Some(self.history.len().saturating_sub(1));
        }
    }

    pub fn show_previous_snapshot(&mut self) {
        if self.history.len() < 2 {
            return;
        }

        let next_cursor = match self.history_cursor {
            Some(cursor) => cursor.saturating_sub(1),
            None => self.history.len().saturating_sub(2),
        };
        self.history_cursor = Some(next_cursor);
        self.apply_history_cursor();
    }

    pub fn show_next_snapshot(&mut self) {
        let Some(cursor) = self.history_cursor else {
            return;
        };

        if cursor + 1 >= self.history.len().saturating_sub(1) {
            self.history_cursor = None;
        } else {
            self.history_cursor = Some(cursor + 1);
        }
        self.apply_history_cursor();
    }

    pub fn snapshot_status(&self) -> Option<String> {
        let snapshot_count = self.history.len();
        if snapshot_count == 0 {
            return None;
        }

        let (label, collected_at) = if let Some(cursor) = self.history_cursor {
            let entry = self.history.get(cursor)?;
            (format!("snapshot {}/{}", cursor + 1, snapshot_count), entry.collected_at)
        } else {
            let entry = self.history.back()?;
            (format!("live {}/{}", snapshot_count, snapshot_count), entry.collected_at)
        };

        let age = collected_at.elapsed().as_secs_f32();
        Some(format!("{label} ({age:.1}s ago)"))
    }

    fn push_history(&mut self, flamegraph: FlameGraph, collected_at: Instant) {
        self.history.push_back(HistoricalFlameGraph {
            flamegraph,
            collected_at,
        });
        if self.history.len() > LIVE_HISTORY_LIMIT {
            self.history.pop_front();
            if let Some(cursor) = self.history_cursor.as_mut() {
                *cursor = cursor.saturating_sub(1);
            }
        }
    }

    fn apply_history_cursor(&mut self) {
        let selected = match self.history_cursor {
            Some(cursor) => self.history.get(cursor),
            None => self.history.back(),
        };

        if let Some(entry) = selected {
            let tic = Instant::now();
            self.flamegraph_view
                .replace_flamegraph(entry.flamegraph.clone());
            self.elapsed
                .insert("replacement".to_string(), tic.elapsed());
            self.dirty = true;
        }
    }

    /// Find the stack at the given screen coordinates
    pub fn find_stack_at_position(&self, x: u16, y: u16) -> Option<StackIdentifier> {
        // Find the last (topmost) stack that contains this position
        // We iterate in reverse to get the most specific (deepest) stack
        self.stack_positions
            .iter()
            .rev()
            .find(|pos| {
                let end = pos.x.saturating_add(pos.width);
                x >= pos.x && x < end && y == pos.y
            })
            .map(|pos| pos.stack_id)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn collapsed(name: &str, count: u64) -> String {
            format!("{name} {count}")
        }

        #[test]
        fn stores_live_history_and_navigates_snapshots() {
            let mut app = App::with_live();

            app.update_flamegraph(collapsed("alpha", 1));
            app.tick();
            app.update_flamegraph(collapsed("beta", 2));
            app.tick();

            assert_eq!(app.history.len(), 2);
            assert!(app.history_cursor.is_none());
            assert!(app.flamegraph().get_stack_by_full_name("beta").is_some());

            app.show_previous_snapshot();
            assert_eq!(app.history_cursor, Some(0));
            assert!(app.flamegraph().get_stack_by_full_name("alpha").is_some());
            assert!(app.flamegraph().get_stack_by_full_name("beta").is_none());

            app.show_next_snapshot();
            assert_eq!(app.history_cursor, None);
            assert!(app.flamegraph().get_stack_by_full_name("beta").is_some());
        }
    }
}
