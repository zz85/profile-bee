//! Category-based flamegraph frame coloring, shared across every renderer.
//!
//! profile-bee's TUI, SVG (via `inferno`), and HTML outputs all render the same
//! collapse-format frame names. Historically each colored a frame by hashing its
//! name into one warm palette, so a kernel frame, an I/O syscall, and application
//! code were visually indistinguishable.
//!
//! This module classifies a frame name into a [`FrameCategory`] and maps it to an
//! RGB color. The category selects a base color *band*; a hash of the name varies
//! the hue *within* that band, so frames stay individually distinguishable while
//! sharing a category-recognisable color — the same `base + range * namehash`
//! scheme used by `flamegraph.pl`'s language palettes.
//!
//! Category signals come entirely from the frame name string, which is the single
//! intermediate representation feeding all renderers:
//! - Kernel frames carry a `_k` suffix (see `trace_handler.rs`).
//! - V8/Node JavaScript frames carry a `[v8]` prefix or a `(file.js:line)` source.
//! - Java/HotSpot frames carry a `[jvm]` prefix (runtime stubs/interpreter) or a
//!   dotted method signature like `long Burn.fib(int)` (JIT perf-map names use
//!   `.`-separated packages, unlike C++/Rust which use `::`).
//! - Synthetic/meta frames are `cpu_NN`, `swapper/N`, `idle`, or `cmd (pid)` roots.
//!
//! Pure `core`: no `alloc`, no floats, no panics. Integer fixed-point keeps it
//! harmless under any build configuration.

/// The visual category a stack frame belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FrameCategory {
    /// Kernel code (frame name ends in `_k`) that is not I/O related.
    Kernel,
    /// Kernel code doing block / network / filesystem I/O.
    KernelIo,
    /// V8 / Node.js JavaScript frames.
    Js,
    /// Java / HotSpot JVM frames (JIT-compiled methods, interpreter, stubs).
    Java,
    /// Native userspace code — the default.
    User,
    /// Synthetic frames: per-CPU roots, the idle task, process roots.
    Meta,
}

/// Kernel-symbol segments that indicate I/O work. Matched against `_`/`:`-split
/// segments (via `starts_with`) rather than the whole string, so `kthread`
/// (which contains "read") is not misclassified as I/O.
const IO_SEGMENTS: &[&str] = &[
    "read", "write", "vfs", "blk", "bio", "ext4", "xfs", "btrfs", "tcp", "udp", "net", "sock",
    "skb", "nvme", "scsi", "napi",
];

/// Classify a frame name into a [`FrameCategory`]. First match wins.
pub fn categorize(name: &str) -> FrameCategory {
    // 1. Kernel frames carry a `_k` suffix (including synthetic context labels
    //    like `interrupt_k`, `softirq:net_rx_k`). Sub-classify I/O.
    if let Some(base) = name.strip_suffix("_k") {
        if base
            .split(['_', ':'])
            .any(|seg| IO_SEGMENTS.iter().any(|io| seg.starts_with(io)))
        {
            return FrameCategory::KernelIo;
        }
        return FrameCategory::Kernel;
    }

    // 2. Java/HotSpot runtime frames carry an explicit `[jvm] ` tag (interpreter,
    //    stubs, adapters). This is a definitive signal, so check it before JS.
    if name.starts_with("[jvm] ") {
        return FrameCategory::Java;
    }

    // 3. V8 / Node.js JavaScript frames.
    if name.starts_with("[v8] ")
        || (name.ends_with(')')
            && (name.contains(".js") || name.contains(".mjs") || name.contains(".cjs")))
    {
        return FrameCategory::Js;
    }

    // 4. Synthetic / meta frames.
    if name == "idle" || name.starts_with("cpu_") || name.starts_with("swapper/") {
        return FrameCategory::Meta;
    }
    // Process-root pattern: `cmd (1234)` — an all-digit parenthesised suffix.
    if let Some(inner) = name.strip_suffix(')').and_then(|s| s.rsplit_once(" (")) {
        let digits = inner.1;
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return FrameCategory::Meta;
        }
    }

    // 5. JIT-compiled Java methods from `/tmp/perf-<pid>.map` arrive as dotted
    //    signatures (`long Burn.fib(int)`, `java.lang.String.hashCode()`). Java
    //    uses `.`-separated packages; C++/Rust use `::`, so requiring a dotted
    //    call shape with no `::` keeps native frames out of this band.
    if looks_like_java_method(name) {
        return FrameCategory::Java;
    }

    // 6. Everything else is native user code.
    FrameCategory::User
}

/// Heuristic for a HotSpot JIT method name (post-demangling). True when the
/// name has a `Package.Class.method(...)` shape: a `(` with a `.`-containing
/// head and no `::` (which would mark it as C++/Rust). JS `(file.js:line)` and
/// `cmd (pid)` roots are handled by earlier rules, so they never reach here.
fn looks_like_java_method(name: &str) -> bool {
    if name.contains("::") {
        return false;
    }
    match name.find('(') {
        Some(paren) => name[..paren].contains('.'),
        None => false,
    }
}

// FNV-1a hash constants (64-bit).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv1a(name: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for &byte in name.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Per-channel `(base, range)` bands. Final channel = `base + range * frac`,
/// where `frac` is an independent 16-bit fraction of the name hash.
type Band = [(u8, u8); 3];

#[inline]
fn band(cat: FrameCategory) -> Band {
    match cat {
        FrameCategory::Kernel => [(215, 40), (95, 55), (0, 35)], // orange
        FrameCategory::KernelIo => [(35, 55), (105, 70), (200, 55)], // blue
        FrameCategory::Js => [(55, 55), (175, 65), (55, 50)],    // yellow-green
        FrameCategory::Java => [(40, 45), (140, 60), (95, 55)], // jade green (Gregg's --color=java)
        FrameCategory::User => [(205, 50), (0, 230), (0, 55)],  // warm (legacy look)
        FrameCategory::Meta => [(95, 30), (100, 30), (110, 30)], // dim gray
    }
}

/// Map a category + name to an RGB color: the band selects the base color, and
/// three independent 16-bit windows of the name hash vary the channels so frames
/// within a category still differ in hue/shade.
pub fn category_rgb(cat: FrameCategory, name: &str) -> (u8, u8, u8) {
    let h = fnv1a(name);
    let b = band(cat);
    // (range * v) >> 16  ==  range * (v / 65536), with v a 16-bit fraction.
    let ch = |(base, range): (u8, u8), v: u32| -> u8 {
        base.saturating_add(((range as u32 * v) >> 16) as u8)
    };
    (
        ch(b[0], (h & 0xFFFF) as u32),
        ch(b[1], ((h >> 16) & 0xFFFF) as u32),
        ch(b[2], ((h >> 32) & 0xFFFF) as u32),
    )
}

/// Convenience: classify `name` and return its category color.
pub fn color_for(name: &str) -> (u8, u8, u8) {
    category_rgb(categorize(name), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorize_kernel_vs_io() {
        assert_eq!(categorize("do_syscall_64_k"), FrameCategory::Kernel);
        assert_eq!(categorize("interrupt_k"), FrameCategory::Kernel);
        assert_eq!(categorize("softirq_k"), FrameCategory::Kernel);
        assert_eq!(categorize("nmi_k"), FrameCategory::Kernel);
        // `kthread` contains "read" but must NOT be classified as I/O.
        assert_eq!(categorize("kthread_k"), FrameCategory::Kernel);
        assert_eq!(categorize("finish_task_switch_k"), FrameCategory::Kernel);

        assert_eq!(categorize("__x64_sys_read_k"), FrameCategory::KernelIo);
        assert_eq!(categorize("vfs_read_k"), FrameCategory::KernelIo);
        assert_eq!(categorize("tcp_sendmsg_k"), FrameCategory::KernelIo);
        assert_eq!(categorize("blk_update_request_k"), FrameCategory::KernelIo);
        // Synthetic softirq label with a net handler.
        assert_eq!(categorize("softirq:net_rx_k"), FrameCategory::KernelIo);
    }

    #[test]
    fn categorize_js() {
        assert_eq!(
            categorize("[v8] ArgumentsAdaptorTrampoline"),
            FrameCategory::Js
        );
        assert_eq!(categorize("processData (server.js:42)"), FrameCategory::Js);
        assert_eq!(
            categorize("~handleRequest (handler.js:10)"),
            FrameCategory::Js
        );
        assert_eq!(categorize("foo (index.mjs)"), FrameCategory::Js);
        // A destructor-like `~Name` with no JS source is NOT JS.
        assert_eq!(categorize("~Widget"), FrameCategory::User);
    }

    #[test]
    fn categorize_java() {
        // Explicit `[jvm]` runtime tags.
        assert_eq!(categorize("[jvm] Interpreter"), FrameCategory::Java);
        assert_eq!(
            categorize("[jvm] StubRoutines (initial stubs)"),
            FrameCategory::Java
        );
        // JIT method signatures from Compiler.perfmap (dotted, no `::`).
        assert_eq!(categorize("long Burn.fib(int)"), FrameCategory::Java);
        assert_eq!(
            categorize("java.lang.String.hashCode()"),
            FrameCategory::Java
        );
        assert_eq!(
            categorize("void java.lang.Object.<init>()"),
            FrameCategory::Java
        );
        // Native C++/Rust use `::` and must NOT be classified as Java.
        assert_eq!(
            categorize("std::vector::push_back(int)"),
            FrameCategory::User
        );
        assert_eq!(categorize("core::fmt::write"), FrameCategory::User);
        assert_eq!(
            categorize("operator new(unsigned long)"),
            FrameCategory::User
        );
        // JS sources still win over the Java method heuristic.
        assert_eq!(categorize("processData (server.js:42)"), FrameCategory::Js);
        // Java gets a visibly different color band from JS.
        assert_ne!(
            band(FrameCategory::Java),
            band(FrameCategory::Js),
            "Java and JS bands must differ"
        );
    }

    #[test]
    fn categorize_meta() {
        assert_eq!(categorize("idle"), FrameCategory::Meta);
        assert_eq!(categorize("cpu_03"), FrameCategory::Meta);
        assert_eq!(categorize("swapper/0"), FrameCategory::Meta);
        assert_eq!(categorize("node (1234)"), FrameCategory::Meta);
        // A JS source in parens is JS, not a process root.
        assert_eq!(categorize("foo (server.js:42)"), FrameCategory::Js);
        // Parenthesised non-digits is not a process root.
        assert_eq!(categorize("call (inlined)"), FrameCategory::User);
    }

    #[test]
    fn categorize_user() {
        assert_eq!(categorize("main"), FrameCategory::User);
        assert_eq!(categorize("std::io::Read::read"), FrameCategory::User);
        assert_eq!(categorize("alloc::vec::Vec::push"), FrameCategory::User);
        assert_eq!(categorize("[unknown]"), FrameCategory::User);
    }

    #[test]
    fn color_is_deterministic() {
        assert_eq!(color_for("do_syscall_64_k"), color_for("do_syscall_64_k"));
    }

    #[test]
    fn color_varies_within_category() {
        // Two distinct kernel names should not produce the identical color.
        assert_ne!(color_for("schedule_k"), color_for("finish_task_switch_k"));
    }

    #[test]
    fn color_within_band_bounds() {
        // Spot-check that each channel stays inside its category band.
        let check = |name: &str, cat: FrameCategory| {
            let (r, g, b) = color_for(name);
            let bands = band(cat);
            let within = |v: u8, (base, range): (u8, u8)| {
                v >= base && v as u32 <= base as u32 + range as u32
            };
            assert!(within(r, bands[0]), "r out of band for {name}");
            assert!(within(g, bands[1]), "g out of band for {name}");
            assert!(within(b, bands[2]), "b out of band for {name}");
        };
        check("do_syscall_64_k", FrameCategory::Kernel);
        check("main", FrameCategory::User);
        check("cpu_03", FrameCategory::Meta);
        check("vfs_read_k", FrameCategory::KernelIo);
    }
}
