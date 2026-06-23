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
    pub bucket_flamegraph: FlameGraph,
    pub collapsed_data: String,
    pub elapsed: Duration,
    pub collected_at: Instant,
}

#[derive(Debug, Clone)]
struct HistoricalFlameGraph {
    flamegraph: FlameGraph,
    collected_at: Instant,
}

#[derive(Debug, Clone)]
struct HistoricalBucket {
    flamegraph: FlameGraph,
    collapsed_data: String,
    collected_at: Instant,
    sample_count: u64,
}

const LIVE_HISTORY_LIMIT: usize = 120;

#[derive(Debug)]
pub struct InputBuffer {
    pub buffer: tui_input::Input,
    pub cursor: Option<(u16, u16)>,
}

#[derive(Debug, Clone)]
pub struct HeatmapPosition {
    pub start_index: usize,
    pub end_index: usize,
    pub x: u16,
    pub y: u16,
    pub height: u16,
}

#[derive(Debug, Clone)]
pub struct HeatmapColumn {
    pub start_index: usize,
    pub end_index: usize,
    pub sample_count: u64,
}

#[derive(Debug, Clone)]
struct HeatmapState {
    follow_live: bool,
    cursor: Option<usize>,
    range: Option<(usize, usize)>,
}

impl Default for HeatmapState {
    fn default() -> Self {
        Self {
            follow_live: true,
            cursor: None,
            range: None,
        }
    }
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
    /// Per-refresh live buckets used by the heatmap view, oldest first.
    buckets: VecDeque<HistoricalBucket>,
    /// Snapshot being viewed in history mode. `None` means follow live/latest.
    history_cursor: Option<usize>,
    /// Heatmap selection state for the live heatmap view.
    heatmap_state: HeatmapState,
    /// Shared update mode for the profiling thread
    update_mode_handle: Arc<Mutex<UpdateMode>>,
    /// Shared pid-mode flag for the profiling thread (toggled with 'p')
    pid_mode_handle: Arc<AtomicBool>,
    /// Stack positions from last render (for mouse click handling)
    pub stack_positions: Vec<StackPosition>,
    /// Heatmap positions from last render (for mouse click handling)
    pub heatmap_positions: Vec<HeatmapPosition>,
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
            buckets: VecDeque::new(),
            history_cursor: None,
            heatmap_state: HeatmapState::default(),
            update_mode_handle: Arc::new(Mutex::new(UpdateMode::default())),
            pid_mode_handle: Arc::new(AtomicBool::new(false)),
            stack_positions: Vec::new(),
            heatmap_positions: Vec::new(),
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
            buckets: VecDeque::new(),
            history_cursor: None,
            heatmap_state: HeatmapState::default(),
            stack_positions: Vec::new(),
            heatmap_positions: Vec::new(),
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

    pub fn is_live(&self) -> bool {
        matches!(self.flamegraph_input, FlameGraphInput::Live)
    }

    /// Update flamegraph with new data
    pub fn update_flamegraph(&self, data: String) {
        let tic = std::time::Instant::now();
        let flamegraph = FlameGraph::from_string(data.clone(), true);
        let parsed = ParsedFlameGraph {
            bucket_flamegraph: flamegraph.clone(),
            flamegraph,
            collapsed_data: data,
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

        let next_flamegraph = self.next_flamegraph.lock().unwrap().take();
        if let Some(parsed) = next_flamegraph {
            let ParsedFlameGraph {
                flamegraph,
                bucket_flamegraph,
                collapsed_data,
                elapsed,
                collected_at,
            } = parsed;
            self.elapsed.insert("flamegraph".to_string(), elapsed);
            self.push_history(flamegraph.clone(), collected_at);
            self.push_bucket(bucket_flamegraph, collapsed_data, collected_at);
            if self.flamegraph_view.state.view_kind == crate::state::ViewKind::Heatmap {
                self.apply_heatmap_selection();
            } else if !self.flamegraph_view.state.freeze && self.history_cursor.is_none() {
                let tic = Instant::now();
                self.flamegraph_view.replace_flamegraph(flamegraph);
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
            (
                format!("snapshot {}/{}", cursor + 1, snapshot_count),
                entry.collected_at,
            )
        } else {
            let entry = self.history.back()?;
            (
                format!("live {}/{}", snapshot_count, snapshot_count),
                entry.collected_at,
            )
        };

        let age = collected_at.elapsed().as_secs_f32();
        Some(format!("{label} ({age:.1}s ago)"))
    }

    pub fn heatmap_status(&self) -> Option<String> {
        let bucket_count = self.buckets.len();
        if bucket_count == 0 {
            return None;
        }
        let (start, end) = self.current_heatmap_range()?;
        let sample_count = self
            .buckets
            .iter()
            .skip(start)
            .take(end - start + 1)
            .map(|bucket| bucket.sample_count)
            .sum::<u64>();
        let age = self.buckets.get(end)?.collected_at.elapsed().as_secs_f32();
        if self.heatmap_state.follow_live {
            Some(format!(
                "live bucket {}/{} ({sample_count} samples, {age:.1}s ago)",
                end + 1,
                bucket_count
            ))
        } else if start == end {
            Some(format!(
                "bucket {}/{} ({sample_count} samples, {age:.1}s ago)",
                start + 1,
                bucket_count
            ))
        } else {
            Some(format!(
                "range {}-{} / {} ({} buckets, {sample_count} samples, {age:.1}s ago)",
                start + 1,
                end + 1,
                bucket_count,
                end - start + 1,
            ))
        }
    }

    pub fn current_heatmap_range(&self) -> Option<(usize, usize)> {
        let len = self.buckets.len();
        if len == 0 {
            return None;
        }
        if self.heatmap_state.follow_live {
            return Some((len.saturating_sub(1), len.saturating_sub(1)));
        }
        if let Some((start, end)) = self.heatmap_state.range {
            let start = start.min(end).min(len.saturating_sub(1));
            let end = start.max(end.min(len.saturating_sub(1)));
            return Some((start, end));
        }
        let cursor = self
            .heatmap_state
            .cursor
            .unwrap_or_else(|| len.saturating_sub(1))
            .min(len.saturating_sub(1));
        Some((cursor, cursor))
    }

    pub fn heatmap_columns(&self, max_columns: usize) -> Vec<HeatmapColumn> {
        let len = self.buckets.len();
        if len == 0 || max_columns == 0 {
            return Vec::new();
        }
        let groups = len.min(max_columns);
        let group_size = len.div_ceil(groups);
        let mut start = 0;
        let mut columns = Vec::new();
        while start < len {
            let end = (start + group_size).min(len) - 1;
            let sample_count = self
                .buckets
                .iter()
                .skip(start)
                .take(end - start + 1)
                .map(|bucket| bucket.sample_count)
                .sum::<u64>();
            columns.push(HeatmapColumn {
                start_index: start,
                end_index: end,
                sample_count,
            });
            start = end + 1;
        }
        columns
    }

    pub fn move_heatmap_previous(&mut self) {
        let len = self.buckets.len();
        if len == 0 {
            return;
        }
        self.heatmap_state.follow_live = false;
        let next = self
            .heatmap_state
            .cursor
            .unwrap_or_else(|| len.saturating_sub(1))
            .saturating_sub(1);
        self.heatmap_state.cursor = Some(next);
        self.heatmap_state.range = None;
        self.apply_heatmap_selection();
    }

    pub fn move_heatmap_next(&mut self) {
        let len = self.buckets.len();
        if len == 0 {
            return;
        }
        self.heatmap_state.follow_live = false;
        let next = self
            .heatmap_state
            .cursor
            .unwrap_or_else(|| len.saturating_sub(1))
            .saturating_add(1)
            .min(len.saturating_sub(1));
        self.heatmap_state.cursor = Some(next);
        self.heatmap_state.range = None;
        self.apply_heatmap_selection();
    }

    pub fn expand_heatmap_left(&mut self) {
        let len = self.buckets.len();
        if len == 0 {
            return;
        }
        self.heatmap_state.follow_live = false;
        let cursor = self
            .heatmap_state
            .cursor
            .unwrap_or_else(|| len.saturating_sub(1))
            .min(len.saturating_sub(1));
        let (start, end) = self.heatmap_state.range.unwrap_or((cursor, cursor));
        self.heatmap_state.cursor = Some(cursor);
        self.heatmap_state.range = Some((start.saturating_sub(1), end));
        self.apply_heatmap_selection();
    }

    pub fn expand_heatmap_right(&mut self) {
        let len = self.buckets.len();
        if len == 0 {
            return;
        }
        self.heatmap_state.follow_live = false;
        let cursor = self
            .heatmap_state
            .cursor
            .unwrap_or_else(|| len.saturating_sub(1))
            .min(len.saturating_sub(1));
        let (start, end) = self.heatmap_state.range.unwrap_or((cursor, cursor));
        self.heatmap_state.cursor = Some(cursor);
        self.heatmap_state.range = Some((start, end.saturating_add(1).min(len.saturating_sub(1))));
        self.apply_heatmap_selection();
    }

    pub fn follow_heatmap_live(&mut self) {
        self.heatmap_state = HeatmapState::default();
        self.apply_heatmap_selection();
    }

    pub fn select_heatmap_range(&mut self, start_index: usize, end_index: usize) {
        let len = self.buckets.len();
        if len == 0 {
            return;
        }
        self.heatmap_state.follow_live = false;
        if start_index == end_index {
            self.heatmap_state.cursor = Some(start_index.min(len.saturating_sub(1)));
            self.heatmap_state.range = None;
        } else {
            self.heatmap_state.cursor = Some(start_index.min(end_index).min(len.saturating_sub(1)));
            self.heatmap_state.range = Some((
                start_index.min(end_index).min(len.saturating_sub(1)),
                start_index.max(end_index).min(len.saturating_sub(1)),
            ));
        }
        self.apply_heatmap_selection();
    }

    pub fn sync_active_flamegraph(&mut self) {
        if self.flamegraph_view.state.view_kind == crate::state::ViewKind::Heatmap {
            self.apply_heatmap_selection();
        } else {
            self.apply_history_cursor();
        }
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

    fn push_bucket(
        &mut self,
        flamegraph: FlameGraph,
        collapsed_data: String,
        collected_at: Instant,
    ) {
        let sample_count = flamegraph.total_count();
        self.buckets.push_back(HistoricalBucket {
            flamegraph,
            collapsed_data,
            collected_at,
            sample_count,
        });
        if self.buckets.len() > LIVE_HISTORY_LIMIT {
            self.buckets.pop_front();
            self.reindex_heatmap_state_after_trim();
        }
        if self.heatmap_state.follow_live {
            self.heatmap_state.cursor = self.buckets.len().checked_sub(1);
        }
    }

    fn reindex_heatmap_state_after_trim(&mut self) {
        let Some(last_index) = self.buckets.len().checked_sub(1) else {
            self.heatmap_state = HeatmapState::default();
            return;
        };
        if let Some(cursor) = self.heatmap_state.cursor.as_mut() {
            *cursor = cursor.saturating_sub(1).min(last_index);
        }
        if let Some((start, end)) = self.heatmap_state.range.as_mut() {
            *start = start.saturating_sub(1).min(last_index);
            *end = end.saturating_sub(1).min(last_index);
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

    fn apply_heatmap_selection(&mut self) {
        let Some(flamegraph) = self.build_heatmap_flamegraph() else {
            return;
        };
        let tic = Instant::now();
        self.flamegraph_view.replace_flamegraph(flamegraph);
        self.elapsed
            .insert("replacement".to_string(), tic.elapsed());
        self.dirty = true;
    }

    fn build_heatmap_flamegraph(&self) -> Option<FlameGraph> {
        let (start, end) = self.current_heatmap_range()?;
        if start == end {
            return self
                .buckets
                .get(start)
                .map(|bucket| bucket.flamegraph.clone());
        }
        let collapsed_data = self
            .buckets
            .iter()
            .skip(start)
            .take(end - start + 1)
            .map(|bucket| bucket.collapsed_data.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        Some(FlameGraph::from_string(collapsed_data, true))
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

    pub fn find_heatmap_at_position(&self, x: u16, y: u16) -> Option<(usize, usize)> {
        self.heatmap_positions
            .iter()
            .find(|pos| x == pos.x && y >= pos.y && y < pos.y.saturating_add(pos.height))
            .map(|pos| (pos.start_index, pos.end_index))
    }
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

    #[test]
    fn trims_heatmap_buckets_and_keeps_latest_selection() {
        let mut app = App::with_live();

        for idx in 0..(LIVE_HISTORY_LIMIT + 5) {
            app.update_flamegraph(collapsed(&format!("bucket-{idx}"), 1));
            app.tick();
        }

        assert_eq!(app.buckets.len(), LIVE_HISTORY_LIMIT);
        let (start, end) = app.current_heatmap_range().unwrap();
        assert_eq!(
            (start, end),
            (LIVE_HISTORY_LIMIT - 1, LIVE_HISTORY_LIMIT - 1)
        );
        assert!(app
            .buckets
            .front()
            .unwrap()
            .flamegraph
            .get_stack_by_full_name("bucket-5")
            .is_some());
    }

    #[test]
    fn builds_heatmap_range_flamegraph_from_multiple_buckets() {
        let mut app = App::with_live();

        app.update_flamegraph(collapsed("alpha;shared", 2));
        app.tick();
        app.update_flamegraph(collapsed("beta;shared", 3));
        app.tick();
        app.update_flamegraph(collapsed("gamma", 5));
        app.tick();

        app.select_heatmap_range(0, 1);

        assert!(app
            .flamegraph()
            .get_stack_by_full_name("alpha;shared")
            .is_some());
        assert!(app
            .flamegraph()
            .get_stack_by_full_name("beta;shared")
            .is_some());
        assert!(app.flamegraph().get_stack_by_full_name("gamma").is_none());
    }
}
