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

    // Prebuilt binary checked into the repository. The eBPF bytecode embeds
    // architecture-specific register offsets (pt_regs layout), so prefer an
    // arch-specific prebuilt (`profile-bee.<arch>.bpf.o`) when present. The
    // default `profile-bee.bpf.o` is x86_64 bytecode, so it is only a valid
    // fallback on x86_64 (or when the arch is unknown). On other arches, point
    // at the (possibly missing) arch-specific prebuilt instead of the x86_64
    // default — falling back to x86_64 bytecode there would produce a binary
    // that reads the wrong registers; a fresh `cargo xtask build-ebpf` or the
    // committed arch prebuilt is required.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let prebuilt_arch = manifest_dir.join(format!("ebpf-bin/profile-bee.{target_arch}.bpf.o"));
    let prebuilt_default = manifest_dir.join("ebpf-bin/profile-bee.bpf.o");
    let prebuilt = if prebuilt_arch.exists() {
        prebuilt_arch
    } else if target_arch == "x86_64" || target_arch.is_empty() {
        prebuilt_default
    } else {
        prebuilt_arch
    };

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
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    fs::copy(source, &dest).unwrap_or_else(|e| {
        panic!(
            "Failed to copy eBPF binary from {} to {}: {}",
            source.display(),
            dest.display(),
            e
        )
    });

    let label = if source == prebuilt {
        "prebuilt"
    } else {
        "freshly-built"
    };
    println!(
        "cargo:warning=Using {} eBPF binary: {}",
        label,
        source.display()
    );

    // Compile OTLP Profiles protobuf definitions when the `otlp` feature is enabled.
    #[cfg(feature = "otlp")]
    compile_otlp_protos(&manifest_dir);
}

#[cfg(feature = "otlp")]
fn compile_otlp_protos(manifest_dir: &Path) {
    let proto_dir = manifest_dir.join("proto");
    let protos = &[
        proto_dir
            .join("opentelemetry/proto/collector/profiles/v1development/profiles_service.proto"),
        proto_dir.join("opentelemetry/proto/profiles/v1development/profiles.proto"),
    ];

    // Re-run if any proto file changes.
    for proto in protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        proto_dir
            .join("opentelemetry/proto/common/v1/common.proto")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        proto_dir
            .join("opentelemetry/proto/resource/v1/resource.proto")
            .display()
    );

    // Use protox (pure-Rust protobuf compiler) to parse protos — no `protoc` binary needed.
    let file_descriptors = protox::compile(
        protos.iter().map(|p| p.to_str().unwrap()),
        [proto_dir.to_str().unwrap()],
    )
    .expect("failed to compile OTLP proto files with protox");

    tonic_build::configure()
        .build_server(false) // we only need the gRPC client
        .compile_fds(file_descriptors)
        .expect("failed to generate Rust code from OTLP protos");
}

/// Returns `Some(path)` if the file exists, `None` otherwise.
fn pick_fresh(path: &Path) -> Option<&Path> {
    if path.exists() {
        Some(path)
    } else {
        None
    }
}
