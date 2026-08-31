use std::env;

/// Emit the `bpf_target_arch` cfg for this crate.
///
/// aya-ebpf sets this cfg in its own build script, but `cargo:rustc-cfg` only
/// applies to the crate that emits it — it does not propagate to dependents.
/// We therefore mirror aya-ebpf's logic here so our `#[cfg(bpf_target_arch =
/// ...)]` gates select the same architecture aya used to generate `pt_regs`:
/// prefer `CARGO_CFG_BPF_TARGET_ARCH` (set for cross-builds), else derive it
/// from the host triple (the BPF `TARGET` is `bpf`, which is useless here).
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    let arch = env::var("CARGO_CFG_BPF_TARGET_ARCH").unwrap_or_else(|_| {
        let host = env::var("HOST").expect("HOST not set");
        host.split_once('-')
            .map(|(arch, _)| arch.to_owned())
            .unwrap_or(host)
    });
    println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    println!(
        "cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\",\"arm\",\"aarch64\",\"riscv64\",\"powerpc64\",\"s390x\"))"
    );
}
