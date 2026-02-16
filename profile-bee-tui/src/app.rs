use crate::flame::{FlameGraph, SearchPattern, StackIdentifier};
use crate::state::{FlameGraphState, UpdateMode};
use crate::view::FlameGraphView;
use std::collections::HashMap;
use std::error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
}

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
    /// Shared update mode for the profiling thread
    update_mode_handle: Arc<Mutex<UpdateMode>>,
    /// Stack positions from last render (for mouse click handling)
    pub stack_positions: Vec<StackPosition>,
    /// Last click for double-click detection
    pub last_click: Option<(std::time::Instant, u16, u16)>,
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
            update_mode_handle: Arc::new(Mutex::new(UpdateMode::default())),
            stack_positions: Vec::new(),
            last_click: None,
        }
    }

    /// Constructs a new instance for live profiling mode
    pub fn with_live() -> Self {
        Self::with_live_and_mode(UpdateMode::default())
    }

    /// Constructs a new instance for live profiling mode with specified update mode
    pub fn with_live_and_mode(update_mode: UpdateMode) -> Self {
        let flamegraph = FlameGraph::from_string("".to_string(), true);
        let mut state = FlameGraphState::default();
        state.update_mode = update_mode;
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
            stack_positions: Vec::new(),
            last_click: None,
        }
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

    /// Update flamegraph with new data
    pub fn update_flamegraph(&self, data: String) {
        let tic = std::time::Instant::now();
        let flamegraph = FlameGraph::from_string(data, true);
        let parsed = ParsedFlameGraph {
            flamegraph,
            elapsed: tic.elapsed(),
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

        // Replace flamegraph
        if !self.flamegraph_view.state.freeze {
            if let Some(parsed) = self.next_flamegraph.lock().unwrap().take() {
                self.elapsed
                    .insert("flamegraph".to_string(), parsed.elapsed);
                let tic = std::time::Instant::now();
                self.flamegraph_view.replace_flamegraph(parsed.flamegraph);
                self.elapsed
                    .insert("replacement".to_string(), tic.elapsed());
                self.dirty = true;
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
}
