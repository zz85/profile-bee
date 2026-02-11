# profile-bee-tui

Terminal-based interactive flamegraph viewer for profile-bee, forked and adapted from [flamelens](https://github.com/YS-L/flamelens).

## Overview

This crate provides an interactive TUI (Terminal User Interface) for viewing flamegraphs directly in the terminal. It's integrated into profile-bee via the `--tui` flag and supports real-time profiling updates.

## Attribution

This code is forked from flamelens by Yung Siang Liau:
- Original repository: https://github.com/YS-L/flamelens
- License: MIT License
- Copyright (c) 2024 Yung Siang Liau

## Changes from flamelens

- Removed Python-specific profiling features (py-spy integration)
- Added support for live flamegraph updates from profile-bee's profiling loop
- Simplified `FlameGraphInput` enum to support `File` and `Live` modes
- Added `App::with_live()` constructor and `update_flamegraph()` method for real-time updates
- Updated UI to show live profiling status and freeze state

## Key Features

- Interactive navigation with vim-style keybindings
- Real-time flamegraph updates during profiling
- Search and highlight frames using regex patterns
- Zoom into specific stack frames
- Freeze/unfreeze live updates
- Table view for sorted stack frame statistics

## Usage

This crate is not meant to be used directly. Instead, use it through profile-bee:

```bash
# Build profile-bee with TUI support
cargo build --release --features tui

# Use the TUI viewer
sudo ./target/release/profile-bee --tui --cmd "your-command"
```

## Architecture

- `flame.rs` - Flamegraph data structure and collapsed stack parsing
- `app.rs` - Application state and main loop
- `ui.rs` - Terminal UI rendering
- `view.rs` - Flamegraph view state management
- `state.rs` - UI state (zoom, search, view mode)
- `handler.rs` - Event handling
- `event.rs` - Terminal event types
- `tui.rs` - Terminal initialization and management

## Dependencies

- `ratatui` - Terminal UI framework
- `crossterm` - Cross-platform terminal handling
- `regex` - Search pattern matching
- `tui-input` - Text input handling

## License

MIT License (same as flamelens)
