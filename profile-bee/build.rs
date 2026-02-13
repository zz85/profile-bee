//! Build script for profile-bee.
//!
//! Selects the eBPF binary to embed at compile time:
//! - If a freshly-built binary exists under `target/bpfel-unknown-none/`,
//!   it is used (active development with `cargo xtask build-ebpf`).
//! - Otherwise, the prebuilt binary shipped in `ebpf-bin/` is used
//!   (end-user `cargo install` without nightly Rust).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("profile-bee.bpf.o");

    // Workspace root is one level up from the profile-bee crate directory.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();

    // Freshly-built eBPF binaries from `cargo xtask build-ebpf`.
    let fresh_release = workspace_root.join("target/bpfel-unknown-none/release/profile-bee");
    let fresh_debug = workspace_root.join("target/bpfel-unknown-none/debug/profile-bee");

    // Prebuilt binary checked into the repository.
    let prebuilt = manifest_dir.join("ebpf-bin/profile-bee.bpf.o");

    // Prefer the freshly-built binary matching the current profile,
    // then the other profile, then the prebuilt fallback.
    let profile = env::var("PROFILE").unwrap_or_default();
    let source = if profile == "debug" {
        pick_fresh(&fresh_debug)
            .or_else(|| pick_fresh(&fresh_release))
            .unwrap_or(&prebuilt)
    } else {
        pick_fresh(&fresh_release)
            .or_else(|| pick_fresh(&fresh_debug))
            .unwrap_or(&prebuilt)
    };

    // Tell cargo to re-run this script if any of the candidate files change.
    println!("cargo:rerun-if-changed={}", fresh_release.display());
    println!("cargo:rerun-if-changed={}", fresh_debug.display());
    println!("cargo:rerun-if-changed={}", prebuilt.display());

    fs::copy(source, &dest).unwrap_or_else(|e| {
        panic!(
            "Failed to copy eBPF binary from {} to {}: {}",
            source.display(),
            dest.display(),
            e
        )
    });

    let label = if source == &prebuilt {
        "prebuilt"
    } else {
        "freshly-built"
    };
    println!(
        "cargo:warning=Using {} eBPF binary: {}",
        label,
        source.display()
    );
}

/// Returns `Some(path)` if the file exists, `None` otherwise.
fn pick_fresh(path: &Path) -> Option<&Path> {
    if path.exists() {
        Some(path)
    } else {
        None
    }
}
