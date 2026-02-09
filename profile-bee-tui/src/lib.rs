//! profile-bee-tui - Terminal-based flamegraph viewer for profile-bee
//!
//! This crate is a fork and adaptation of flamelens by Yung Siang Liau
//! Original repository: https://github.com/YS-L/flamelens
//! License: MIT License - Copyright (c) 2024 Yung Siang Liau

/// Application.
pub mod app;

/// Terminal events handler.
pub mod event;

/// Widget renderer.
pub mod ui;

/// Terminal user interface.
pub mod tui;

/// Event handler.
pub mod handler;

pub mod flame;

pub mod state;

pub mod view;
