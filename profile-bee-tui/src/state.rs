use crate::flame::{FlameGraph, SearchPattern, StackIdentifier, ROOT_ID};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateMode {
    Reset,
    #[default]
    Accumulate,
    Decay,
}

impl UpdateMode {
    pub fn next(&self) -> Self {
        match self {
            UpdateMode::Reset => UpdateMode::Accumulate,
            UpdateMode::Accumulate => UpdateMode::Decay,
            UpdateMode::Decay => UpdateMode::Reset,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateMode::Reset => "Reset",
            UpdateMode::Accumulate => "Accumulate",
            UpdateMode::Decay => "Decay",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZoomState {
    pub stack_id: StackIdentifier,
    pub ancestors: Vec<StackIdentifier>,
    pub descendants: Vec<StackIdentifier>,
    pub zoom_factor: f64,
}

impl ZoomState {
    pub fn is_ancestor_or_descendant(&self, stack_id: &StackIdentifier) -> bool {
        self.ancestors.contains(stack_id) || self.descendants.contains(stack_id)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ViewKind {
    FlameGraph,
    Table,
    Output,
    ProcessList,
}

#[derive(Default, Debug, Clone)]
pub struct TableState {
    pub selected: usize,
    pub offset: usize,
}

impl TableState {
    pub fn reset(&mut self) {
        self.selected = 0;
        self.offset = 0;
    }
}

#[derive(Debug, Clone)]
pub struct FlameGraphState {
    pub selected: StackIdentifier,
    pub level_offset: usize,
    pub frame_height: Option<u16>,
    pub frame_width: Option<u16>,
    pub zoom: Option<ZoomState>,
    pub search_pattern: Option<SearchPattern>,
    pub freeze: bool,
    /// When true, stacks are prefixed with "process_name (pid)" root frames
    /// to split the flamegraph by process. Toggled with 'p'.
    pub pid_mode: bool,
    /// When true, the Top/Processes views show an expandable tree instead
    /// of a flat list. Toggled with 't'.
    pub tree_mode: bool,
    pub view_kind: ViewKind,
    pub table_state: TableState,
    pub process_list_state: TableState,
    pub tree_view_state: TreeViewState,
    pub update_mode: UpdateMode,
}

/// State for the expandable call-tree view (like `perf report`).
#[derive(Debug, Clone, Default)]
pub struct TreeViewState {
    /// Currently selected row in the flattened tree.
    pub selected: usize,
    /// Scroll offset for rendering.
    pub offset: usize,
    /// Set of expanded node IDs.
    pub expanded: std::collections::HashSet<StackIdentifier>,
}

impl TreeViewState {
    pub fn reset(&mut self) {
        self.selected = 0;
        self.offset = 0;
        self.expanded.clear();
    }

    pub fn toggle_expanded(&mut self, id: StackIdentifier) {
        if !self.expanded.remove(&id) {
            self.expanded.insert(id);
        }
    }
}

impl Default for FlameGraphState {
    fn default() -> Self {
        Self {
            selected: ROOT_ID,
            level_offset: 0,
            frame_height: None,
            frame_width: None,
            zoom: None,
            search_pattern: None,
            freeze: false,
            pid_mode: false,
            tree_mode: false,
            view_kind: ViewKind::FlameGraph,
            table_state: TableState::default(),
            process_list_state: TableState::default(),
            tree_view_state: TreeViewState::default(),
            update_mode: UpdateMode::default(),
        }
    }
}

impl FlameGraphState {
    pub fn select_root(&mut self) {
        self.selected = ROOT_ID;
    }

    pub fn select_id(&mut self, stack_id: &StackIdentifier) {
        self.selected.clone_from(stack_id);
    }

    pub fn set_zoom(&mut self, zoom: ZoomState) {
        self.zoom = Some(zoom);
    }

    pub fn unset_zoom(&mut self) {
        self.zoom = None;
    }

    pub fn set_search_pattern(&mut self, search_pattern: SearchPattern) {
        self.search_pattern = Some(search_pattern);
    }

    pub fn unset_search_pattern(&mut self) {
        self.search_pattern = None;
    }

    pub fn toggle_freeze(&mut self) {
        self.freeze = !self.freeze;
    }

    pub fn toggle_view_kind(&mut self) {
        self.view_kind = match self.view_kind {
            ViewKind::FlameGraph => ViewKind::Table,
            ViewKind::Table => ViewKind::ProcessList,
            ViewKind::ProcessList => ViewKind::FlameGraph,
            ViewKind::Output => ViewKind::FlameGraph,
        };
    }

    /// Cycle view kind including the Output tab (when a process output
    /// buffer is available).
    pub fn toggle_view_kind_with_output(&mut self) {
        self.view_kind = match self.view_kind {
            ViewKind::FlameGraph => ViewKind::Table,
            ViewKind::Table => ViewKind::ProcessList,
            ViewKind::ProcessList => ViewKind::Output,
            ViewKind::Output => ViewKind::FlameGraph,
        };
    }

    pub fn cycle_update_mode(&mut self) {
        self.update_mode = self.update_mode.next();
    }

    /// Update StackIdentifiers to point to the correct ones in the new flamegraph
    pub fn handle_flamegraph_replacement(&mut self, old: &FlameGraph, new: &mut FlameGraph) {
        if self.selected != ROOT_ID {
            if let Some(new_stack_id) = Self::get_new_stack_id(&self.selected, old, new) {
                self.selected = new_stack_id;
            } else {
                self.select_root();
            }
        }
        if let Some(zoom) = &mut self.zoom {
            if let Some(new_stack_id) = Self::get_new_stack_id(&zoom.stack_id, old, new) {
                zoom.stack_id = new_stack_id;
            } else {
                self.unset_zoom();
            }
        }
        // Preserve search pattern. If expensive, can move this to next flamegraph construction
        // thread and share SearchPattern via Arc but let's keep it simple for now.
        if let Some(p) = &self.search_pattern {
            new.set_hits(p);
        }

        // Remap expanded tree node IDs from old to new flamegraph.
        // Nodes are matched by full name so expanded state survives data refreshes.
        let old_expanded = std::mem::take(&mut self.tree_view_state.expanded);
        for old_id in old_expanded {
            if let Some(new_id) = Self::get_new_stack_id(&old_id, old, new) {
                self.tree_view_state.expanded.insert(new_id);
            }
        }
    }

    fn get_new_stack_id(
        stack_id: &StackIdentifier,
        old: &FlameGraph,
        new: &FlameGraph,
    ) -> Option<StackIdentifier> {
        old.get_stack(stack_id).and_then(|stack| {
            new.get_stack_by_full_name(old.get_stack_full_name_from_info(stack))
                .map(|stack| stack.id)
        })
    }
}
