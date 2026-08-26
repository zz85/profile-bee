//! Kernel memory-layout resolution for `preempt_count`-based execution context
//! detection.
//!
//! The eBPF sampler wants to know whether a sampled stack ran in task, softirq,
//! hardirq, or NMI context. The kernel's canonical answer is `preempt_count`
//! (`include/linux/preempt.h`), but there is no BPF helper exposing it, and
//! CO-RE field relocation is not reachable from this codebase (aya-ebpf exposes
//! no `bpf_core_read` equivalent). So we resolve the necessary offsets in
//! userspace and inject them into eBPF as globals; the eBPF side then does the
//! `bpf_probe_read_kernel` calls.
//!
//! Two architectures are supported:
//!
//! * **x86_64** — `preempt_count` lives in the per-CPU variable `__preempt_count`.
//!   We resolve its per-CPU section offset from `/proc/kallsyms` (or BTF) and the
//!   absolute address of `__per_cpu_offset[]` from kallsyms. eBPF computes
//!   `*(u32 *)(__per_cpu_offset[cpu] + var_offset)`.
//!
//! * **aarch64** — `preempt_count` lives in `task_struct.thread_info.preempt_count`.
//!   We resolve the byte offset from `/sys/kernel/btf/vmlinux` and eBPF reads it
//!   via `bpf_get_current_task_btf()`.
//!
//! Every failure path degrades to [`PreemptSource::Unavailable`] carrying a
//! human-readable reason; `detect()` never returns an error and never aborts
//! startup. On an unavailable layout the eBPF side reports `EXEC_CTX_UNKNOWN`
//! and userspace falls back to symbol heuristics.

use std::fs;
use std::sync::OnceLock;

/// Environment variable that forces the feature off (mode 0), reproducing the
/// pre-feature symbol-heuristic behaviour. Used by tests and as an escape hatch.
pub const DISABLE_ENV: &str = "PROBEE_DISABLE_PREEMPT_CTX";

/// Where the eBPF side should read `preempt_count` from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreemptSource {
    /// x86_64: per-CPU variable. `per_cpu_offset_array` is the absolute kernel
    /// address of `__per_cpu_offset[]`; `var_offset` is the per-CPU section
    /// offset of `__preempt_count`.
    PerCpu {
        per_cpu_offset_array: u64,
        var_offset: u64,
    },
    /// aarch64: `task_struct` field at `byte_offset` from the task pointer.
    TaskStruct { byte_offset: u32 },
    /// Layout could not be resolved; carries the reason for logging.
    Unavailable(String),
}

/// Resolved kernel layout for `preempt_count` detection.
#[derive(Debug, Clone)]
pub struct KernelLayout {
    pub preempt: PreemptSource,
    /// False under `CONFIG_PREEMPT_RT`: softirq state is no longer tracked in
    /// `preempt_count`, so the eBPF side can only report hardirq/NMI and
    /// userspace must fall back to symbol heuristics for softirq.
    pub softirq_bits_valid: bool,
    /// Whether the kernel is a PREEMPT_RT build (for logging).
    pub is_preempt_rt: bool,
}

impl KernelLayout {
    /// The `PREEMPT_CTX_MODE` global value: 0 = disabled, 1 = x86 per-CPU var,
    /// 2 = arm64 task_struct field.
    pub fn mode(&self) -> u8 {
        match self.preempt {
            PreemptSource::PerCpu { .. } => 1,
            PreemptSource::TaskStruct { .. } => 2,
            PreemptSource::Unavailable(_) => 0,
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        KernelLayout {
            preempt: PreemptSource::Unavailable(reason.into()),
            softirq_bits_valid: false,
            is_preempt_rt: false,
        }
    }
}

/// Detect the kernel layout once and cache it for the process lifetime.
///
/// Honors [`DISABLE_ENV`]: when set, returns an `Unavailable` layout so the
/// profiler reproduces the pre-feature symbol-heuristic behaviour exactly.
pub fn detect_cached() -> &'static KernelLayout {
    static LAYOUT: OnceLock<KernelLayout> = OnceLock::new();
    LAYOUT.get_or_init(|| {
        if std::env::var_os(DISABLE_ENV).is_some() {
            return KernelLayout::unavailable(format!("{DISABLE_ENV} set"));
        }
        detect()
    })
}

/// Detect the kernel layout for the current architecture.
///
/// Never fails — always returns a `KernelLayout`, degrading to
/// `PreemptSource::Unavailable(reason)` when resolution is not possible.
pub fn detect() -> KernelLayout {
    let is_preempt_rt = detect_preempt_rt();
    // Under RT the softirq bits of preempt_count are not maintained.
    let softirq_bits_valid = !is_preempt_rt;

    let preempt = detect_preempt_source();

    KernelLayout {
        preempt,
        softirq_bits_valid,
        is_preempt_rt,
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_preempt_source() -> PreemptSource {
    detect_x86_64()
}

#[cfg(target_arch = "aarch64")]
fn detect_preempt_source() -> PreemptSource {
    detect_aarch64()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn detect_preempt_source() -> PreemptSource {
    PreemptSource::Unavailable(format!(
        "unsupported architecture ({})",
        std::env::consts::ARCH
    ))
}

// ---------------------------------------------------------------------------
// x86_64 resolution
// ---------------------------------------------------------------------------

/// Resolve the x86_64 per-CPU `preempt_count` source.
///
/// 1. `__preempt_count` (kallsyms type `A`) → per-CPU section offset.
/// 2. Fall back to BTF DATASEC offset of the `VAR '__preempt_count'`.
/// 3. `__per_cpu_offset` (kallsyms type `D`) → absolute address of the per-CPU
///    offset array (cannot come from BTF, which carries no addresses).
#[cfg(target_arch = "x86_64")]
fn detect_x86_64() -> PreemptSource {
    let kallsyms = match Kallsyms::load() {
        Ok(k) => k,
        Err(e) => return PreemptSource::Unavailable(format!("kallsyms unreadable: {e}")),
    };

    // The per-CPU offset array address must come from kallsyms.
    let Some(per_cpu_offset_array) = kallsyms.addr("__per_cpu_offset") else {
        return PreemptSource::Unavailable("__per_cpu_offset not in kallsyms".into());
    };
    if per_cpu_offset_array == 0 {
        return PreemptSource::Unavailable("kallsyms addresses masked (kptr_restrict=2?)".into());
    }

    // Prefer kallsyms for the per-CPU variable offset (runtime truth for the
    // loaded image); fall back to BTF.
    let var_offset = kallsyms
        .addr("__preempt_count")
        .filter(|&v| v != 0)
        .or_else(|| btf_percpu_var_offset("__preempt_count"));

    let Some(var_offset) = var_offset else {
        return PreemptSource::Unavailable(
            "__preempt_count offset not found in kallsyms or BTF".into(),
        );
    };

    PreemptSource::PerCpu {
        per_cpu_offset_array,
        var_offset,
    }
}

/// Look up the `.data..percpu` DATASEC offset of a per-CPU `VAR` in vmlinux BTF.
#[cfg(target_arch = "x86_64")]
fn btf_percpu_var_offset(var_name: &str) -> Option<u64> {
    let raw = fs::read("/sys/kernel/btf/vmlinux").ok()?;
    let btf = Btf::parse(&raw).ok()?;
    btf.percpu_var_offset(var_name)
}

// ---------------------------------------------------------------------------
// aarch64 resolution
// ---------------------------------------------------------------------------

/// Resolve the aarch64 `task_struct.thread_info.preempt_count` byte offset from
/// vmlinux BTF.
///
/// `byte_offset = offsetof(task_struct, thread_info) + offsetof(thread_info, preempt_count)`.
/// `thread_info.preempt_count` sits in an anonymous union; we prefer the
/// `preempt.count` union member and fall back to `preempt_count`.
#[cfg(target_arch = "aarch64")]
fn detect_aarch64() -> PreemptSource {
    #[cfg(target_endian = "big")]
    {
        return PreemptSource::Unavailable("big-endian aarch64 unsupported".into());
    }

    let raw = match fs::read("/sys/kernel/btf/vmlinux") {
        Ok(r) => r,
        Err(e) => {
            return PreemptSource::Unavailable(format!(
                "/sys/kernel/btf/vmlinux unreadable ({e}); CONFIG_DEBUG_INFO_BTF=n?"
            ))
        }
    };
    let btf = match Btf::parse(&raw) {
        Ok(b) => b,
        Err(e) => return PreemptSource::Unavailable(format!("BTF parse failed: {e}")),
    };

    let ti_off = match btf.member_offset("task_struct", "thread_info") {
        Some(o) => o,
        None => {
            return PreemptSource::Unavailable("task_struct.thread_info not found in BTF".into())
        }
    };

    // Prefer preempt.count (unambiguous under CONFIG_CPU_BIG_ENDIAN field
    // flipping), then the u64 preempt_count in the anonymous union.
    let pc_off = btf
        .member_offset("thread_info", "preempt.count")
        .or_else(|| btf.member_offset("thread_info", "preempt_count"));

    let Some(pc_off) = pc_off else {
        return PreemptSource::Unavailable("thread_info.preempt_count not found in BTF".into());
    };

    let byte_offset = ti_off + pc_off;
    // Plausibility guard: task_struct is large but this offset is small.
    if byte_offset > 0x10000 {
        return PreemptSource::Unavailable(format!(
            "implausible preempt_count offset {byte_offset:#x}"
        ));
    }

    PreemptSource::TaskStruct {
        byte_offset: byte_offset as u32,
    }
}

// ---------------------------------------------------------------------------
// PREEMPT_RT detection
// ---------------------------------------------------------------------------

/// Detect `CONFIG_PREEMPT_RT`.
///
/// Primary: BTF — `task_struct.softirq_disable_cnt` exists only under RT.
/// Secondary: `/boot/config-$(uname -r)`. Tertiary: `uname -v` contains
/// `PREEMPT_RT`.
fn detect_preempt_rt() -> bool {
    // Primary: BTF probe (works on any arch with BTF).
    if let Ok(raw) = fs::read("/sys/kernel/btf/vmlinux") {
        if let Ok(btf) = Btf::parse(&raw) {
            if btf
                .member_offset("task_struct", "softirq_disable_cnt")
                .is_some()
            {
                return true;
            }
        }
    }

    // Secondary: kernel config.
    if let Ok(release) = uname_release() {
        if let Ok(config) = fs::read_to_string(format!("/boot/config-{release}")) {
            if config.lines().any(|l| l.trim() == "CONFIG_PREEMPT_RT=y") {
                return true;
            }
        }
    }

    // Tertiary: uname version string.
    uname_version()
        .map(|v| v.contains("PREEMPT_RT"))
        .unwrap_or(false)
}

fn uname_release() -> std::io::Result<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string())
}

fn uname_version() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/version")
        .ok()
        .map(|s| s.trim().to_string())
}

// ---------------------------------------------------------------------------
// kallsyms
// ---------------------------------------------------------------------------

/// Minimal `/proc/kallsyms` reader: symbol name → address.
///
/// `/proc/kallsyms` has 100k+ lines but only two symbols are ever needed
/// (`__per_cpu_offset`, `__preempt_count`), so `load` streams the file and
/// retains only those rather than buffering the whole file and every symbol.
struct Kallsyms {
    map: std::collections::HashMap<String, u64>,
}

/// The only symbols the layout resolver looks up. Streaming `load` keeps just
/// these; other consumers should extend this list rather than retaining all.
const WANTED_SYMBOLS: [&str; 2] = ["__per_cpu_offset", "__preempt_count"];

impl Kallsyms {
    fn load() -> std::io::Result<Self> {
        use std::io::BufRead;
        let file = fs::File::open("/proc/kallsyms")?;
        let mut map = std::collections::HashMap::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if let Some((name, addr)) = Self::parse_line(&line) {
                if WANTED_SYMBOLS.contains(&name) {
                    // First definition wins; kernel symbols are unique enough
                    // for the two names we care about.
                    map.entry(name.to_string()).or_insert(addr);
                }
            }
        }
        Ok(Kallsyms { map })
    }

    /// Parse one `/proc/kallsyms` line into `(name, address)`.
    /// Format: "<hex addr> <type> <name>[\t<module>]".
    fn parse_line(line: &str) -> Option<(&str, u64)> {
        let mut parts = line.split_whitespace();
        let (addr, _ty, name) = (parts.next()?, parts.next()?, parts.next()?);
        let addr = u64::from_str_radix(addr, 16).ok()?;
        Some((name, addr))
    }

    #[cfg(test)]
    fn parse(text: &str) -> Self {
        let mut map = std::collections::HashMap::new();
        for line in text.lines() {
            if let Some((name, addr)) = Self::parse_line(line) {
                map.entry(name.to_string()).or_insert(addr);
            }
        }
        Kallsyms { map }
    }

    fn addr(&self, name: &str) -> Option<u64> {
        self.map.get(name).copied()
    }
}

// ---------------------------------------------------------------------------
// Minimal BTF reader
// ---------------------------------------------------------------------------

const BTF_MAGIC: u16 = 0xeb9f;

// BTF type kinds (subset we handle).
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FWD: u32 = 7;
const BTF_KIND_TYPEDEF: u32 = 8;
const BTF_KIND_VOLATILE: u32 = 9;
const BTF_KIND_CONST: u32 = 10;
const BTF_KIND_RESTRICT: u32 = 11;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_FLOAT: u32 = 16;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_TYPE_TAG: u32 = 18;
const BTF_KIND_ENUM64: u32 = 19;

#[derive(Debug)]
struct BtfMember {
    name_off: u32,
    type_id: u32,
    /// Bit offset of the member from the start of the composite; the caller
    /// divides by 8. For a `kind_flag` struct this is the low 24 bits of the
    /// encoded offset word (the high 8 bitfield-size bits are stripped at parse).
    offset: u32,
    /// True only for an actual bitfield (a `kind_flag` struct member whose
    /// encoded size is nonzero). Normal members of a `kind_flag` struct — size
    /// zero — are not bitfields.
    bitfield: bool,
}

#[derive(Debug)]
enum BtfType {
    /// STRUCT or UNION.
    Composite {
        name_off: u32,
        members: Vec<BtfMember>,
    },
    /// TYPEDEF / CONST / VOLATILE / RESTRICT / TYPE_TAG — a named or transparent
    /// wrapper around another type id.
    Modifier { type_id: u32 },
    /// VAR — a global variable referencing a type.
    Var { name_off: u32 },
    /// DATASEC — carries (var type_id, offset, size) entries.
    DataSec {
        name_off: u32,
        vars: Vec<(u32, u32, u32)>,
    },
    /// Any other kind we don't need to introspect.
    Other,
}

/// A parsed subset of a BTF blob: the string section plus decoded types.
pub struct Btf {
    strings: Vec<u8>,
    /// Indexed by type id. Index 0 is the void type (a placeholder).
    types: Vec<BtfType>,
}

impl Btf {
    /// Parse a BTF blob (`/sys/kernel/btf/vmlinux` contents).
    fn parse(data: &[u8]) -> Result<Btf, String> {
        if data.len() < 24 {
            return Err("BTF too short for header".into());
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        // Host is assumed little-endian (guarded on aarch64; x86_64 is always LE).
        if magic != BTF_MAGIC {
            return Err(format!("bad BTF magic {magic:#x}"));
        }
        let rd32 = |off: usize| {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let hdr_len = rd32(4) as usize;
        let type_off = rd32(8) as usize;
        let type_len = rd32(12) as usize;
        let str_off = rd32(16) as usize;
        let str_len = rd32(20) as usize;

        let type_start = hdr_len + type_off;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or("BTF type section overflow")?;
        let str_start = hdr_len + str_off;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or("BTF string section overflow")?;
        if type_end > data.len() || str_end > data.len() {
            return Err("BTF section out of bounds".into());
        }

        let strings = data[str_start..str_end].to_vec();
        let types = Self::parse_types(&data[type_start..type_end])?;

        Ok(Btf { strings, types })
    }

    fn parse_types(mut buf: &[u8]) -> Result<Vec<BtfType>, String> {
        // Type ids are 1-based; index 0 is the void type.
        let mut types = vec![BtfType::Other];

        let rd32 = |b: &[u8], off: usize| -> u32 {
            u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
        };

        while buf.len() >= 12 {
            let name_off = rd32(buf, 0);
            let info = rd32(buf, 4);
            let size_or_type = rd32(buf, 8);

            let kind = (info >> 24) & 0x1f;
            let vlen = info & 0xffff;
            let kind_flag = (info >> 31) & 1 == 1;

            let mut consumed = 12usize;

            let parsed = match kind {
                BTF_KIND_STRUCT | BTF_KIND_UNION => {
                    // vlen members follow, each is btf_member { name_off, type, offset } = 12 bytes.
                    let mut members = Vec::with_capacity(vlen as usize);
                    for i in 0..vlen as usize {
                        let base = consumed + i * 12;
                        if base + 12 > buf.len() {
                            return Err("truncated BTF member".into());
                        }
                        // For a `kind_flag` struct the offset word packs the
                        // bitfield size in the high 8 bits and the bit offset in
                        // the low 24. A member with size 0 is a *normal* field
                        // (only its bit offset is meaningful); a nonzero size
                        // marks an actual bitfield. Without kind_flag the whole
                        // word is the bit offset.
                        let raw_off = rd32(buf, base + 8);
                        let (offset, bitfield) = if kind_flag {
                            (raw_off & 0x00ff_ffff, (raw_off >> 24) != 0)
                        } else {
                            (raw_off, false)
                        };
                        members.push(BtfMember {
                            name_off: rd32(buf, base),
                            type_id: rd32(buf, base + 4),
                            offset,
                            bitfield,
                        });
                    }
                    consumed += vlen as usize * 12;
                    BtfType::Composite { name_off, members }
                }
                BTF_KIND_TYPEDEF | BTF_KIND_CONST | BTF_KIND_VOLATILE | BTF_KIND_RESTRICT
                | BTF_KIND_TYPE_TAG => {
                    // size_or_type is the referenced type id.
                    BtfType::Modifier {
                        type_id: size_or_type,
                    }
                }
                BTF_KIND_VAR => {
                    // Followed by struct btf_var { u32 linkage } (4 bytes).
                    consumed += 4;
                    BtfType::Var { name_off }
                }
                BTF_KIND_DATASEC => {
                    // vlen entries of btf_var_secinfo { type, offset, size } = 12 bytes.
                    let mut vars = Vec::with_capacity(vlen as usize);
                    for i in 0..vlen as usize {
                        let base = consumed + i * 12;
                        if base + 12 > buf.len() {
                            return Err("truncated BTF datasec".into());
                        }
                        vars.push((rd32(buf, base), rd32(buf, base + 4), rd32(buf, base + 8)));
                    }
                    consumed += vlen as usize * 12;
                    BtfType::DataSec { name_off, vars }
                }
                // Kinds with trailing data we must skip to stay aligned.
                BTF_KIND_INT => {
                    // Followed by a u32.
                    consumed += 4;
                    BtfType::Other
                }
                BTF_KIND_ENUM => {
                    // vlen entries of btf_enum { name_off, val } = 8 bytes.
                    consumed += vlen as usize * 8;
                    BtfType::Other
                }
                BTF_KIND_ENUM64 => {
                    // vlen entries of btf_enum64 { name_off, val_lo32, val_hi32 } = 12 bytes.
                    consumed += vlen as usize * 12;
                    BtfType::Other
                }
                BTF_KIND_FUNC_PROTO => {
                    // vlen entries of btf_param { name_off, type } = 8 bytes.
                    consumed += vlen as usize * 8;
                    BtfType::Other
                }
                BTF_KIND_DECL_TAG => {
                    // Followed by struct btf_decl_tag { s32 component_idx } (4 bytes).
                    consumed += 4;
                    BtfType::Other
                }
                BTF_KIND_PTR | BTF_KIND_ARRAY | BTF_KIND_FWD | BTF_KIND_FUNC | BTF_KIND_FLOAT => {
                    // ARRAY has a trailing btf_array (12 bytes); the others have none.
                    if kind == BTF_KIND_ARRAY {
                        consumed += 12;
                    }
                    BtfType::Other
                }
                _ => BtfType::Other,
            };

            types.push(parsed);
            if consumed > buf.len() {
                return Err("BTF type overran section".into());
            }
            buf = &buf[consumed..];
        }

        Ok(types)
    }

    fn string(&self, off: u32) -> &str {
        let off = off as usize;
        if off >= self.strings.len() {
            return "";
        }
        let end = self.strings[off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .unwrap_or(self.strings.len());
        std::str::from_utf8(&self.strings[off..end]).unwrap_or("")
    }

    /// Strip typedef/const/volatile/restrict/type_tag wrappers, returning the
    /// underlying type id.
    fn resolve(&self, mut type_id: u32) -> u32 {
        for _ in 0..16 {
            match self.types.get(type_id as usize) {
                Some(BtfType::Modifier { type_id: inner }) => type_id = *inner,
                _ => break,
            }
        }
        type_id
    }

    /// Find the byte offset of `member` within the named struct/union `type_name`.
    ///
    /// `member` may be a dotted path (e.g. `preempt.count`); each segment is
    /// resolved in turn, descending into the previous segment's type. A single
    /// segment (e.g. `preempt_count`) is resolved directly.
    ///
    /// Anonymous members (name_off == 0) are transparently descended when
    /// locating a segment — required for aarch64, where `preempt_count` lives in
    /// an anonymous union. Bitfields are rejected (returns None) rather than
    /// risk mis-handling them.
    pub fn member_offset(&self, type_name: &str, member: &str) -> Option<u64> {
        let mut type_id = self.find_composite(type_name)?;
        let mut acc_bits: u64 = 0;
        for segment in member.split('.') {
            let (seg_bits, seg_type) = self.find_segment(type_id, segment, 0, 0)?;
            acc_bits += seg_bits;
            type_id = self.resolve(seg_type);
        }
        // Not byte-aligned (a bitfield slipped through) — refuse.
        #[allow(clippy::manual_is_multiple_of)] // keep portable across toolchains
        if acc_bits % 8 != 0 {
            return None;
        }
        Some(acc_bits / 8)
    }

    fn find_composite(&self, name: &str) -> Option<u32> {
        for (id, ty) in self.types.iter().enumerate() {
            if let BtfType::Composite { name_off, .. } = ty {
                if self.string(*name_off) == name {
                    return Some(id as u32);
                }
            }
        }
        None
    }

    /// Locate a single named `segment` within composite `type_id`, descending
    /// transparently through anonymous members. Returns `(bit_offset_from_base,
    /// member_type_id)`.
    fn find_segment(
        &self,
        type_id: u32,
        segment: &str,
        base_bits: u64,
        depth: u32,
    ) -> Option<(u64, u32)> {
        if depth > 16 {
            return None;
        }
        let resolved = self.resolve(type_id);
        let BtfType::Composite { members, .. } = self.types.get(resolved as usize)? else {
            return None;
        };

        for m in members {
            if m.bitfield {
                // The offset field encodes a bit offset in the low 24 bits for
                // bitfield structs. Refuse a matching bitfield member outright;
                // don't recurse into an anonymous bitfield container.
                if self.string(m.name_off) == segment {
                    return None;
                }
                continue;
            }

            let member_bits = base_bits + m.offset as u64;
            let name = self.string(m.name_off);

            if name == segment {
                return Some((member_bits, m.type_id));
            }

            // Descend into anonymous struct/union members.
            if name.is_empty() {
                if let Some(found) = self.find_segment(m.type_id, segment, member_bits, depth + 1) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Return the `.data..percpu` DATASEC offset of the named per-CPU `VAR`.
    pub fn percpu_var_offset(&self, var_name: &str) -> Option<u64> {
        // Find the VAR type id by name.
        let mut var_id = None;
        for (id, ty) in self.types.iter().enumerate() {
            if let BtfType::Var { name_off } = ty {
                if self.string(*name_off) == var_name {
                    var_id = Some(id as u32);
                    break;
                }
            }
        }
        let var_id = var_id?;

        // Find the .data..percpu DATASEC and the entry for var_id.
        for ty in &self.types {
            if let BtfType::DataSec { name_off, vars } = ty {
                if self.string(*name_off) == ".data..percpu" {
                    for &(vid, off, _sz) in vars {
                        if vid == var_id {
                            return Some(off as u64);
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Little-endian BTF blob builder for tests.
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            // String section must start with a NUL (offset 0 == empty string).
            BtfBuilder {
                types: Vec::new(),
                strings: vec![0],
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        fn push32(&mut self, v: u32) {
            self.types.extend_from_slice(&v.to_le_bytes());
        }

        fn info(kind: u32, vlen: u32, kind_flag: bool) -> u32 {
            ((kind_flag as u32) << 31) | (kind << 24) | (vlen & 0xffff)
        }

        /// Add a STRUCT/UNION type. members: (name_off, type_id, bit_offset).
        fn composite(&mut self, kind: u32, name_off: u32, size: u32, members: &[(u32, u32, u32)]) {
            self.push32(name_off);
            self.push32(Self::info(kind, members.len() as u32, false));
            self.push32(size);
            for &(mn, mt, mo) in members {
                self.push32(mn);
                self.push32(mt);
                self.push32(mo);
            }
        }

        fn var(&mut self, name_off: u32, type_id: u32) {
            self.push32(name_off);
            self.push32(Self::info(BTF_KIND_VAR, 0, false));
            self.push32(type_id);
            self.push32(0); // linkage
        }

        fn datasec(&mut self, name_off: u32, entries: &[(u32, u32, u32)]) {
            self.push32(name_off);
            self.push32(Self::info(BTF_KIND_DATASEC, entries.len() as u32, false));
            self.push32(0); // size
            for &(t, o, s) in entries {
                self.push32(t);
                self.push32(o);
                self.push32(s);
            }
        }

        fn int(&mut self, name_off: u32) {
            self.push32(name_off);
            self.push32(Self::info(BTF_KIND_INT, 0, false));
            self.push32(4); // size
            self.push32(0); // int encoding word
        }

        fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            // Header: magic(u16) version(u8) flags(u8) hdr_len(u32)
            //         type_off(u32) type_len(u32) str_off(u32) str_len(u32)
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let bad = vec![0u8; 32];
        assert!(Btf::parse(&bad).is_err());
    }

    #[test]
    fn parse_rejects_truncated_header() {
        let short = vec![0x9f, 0xeb, 1, 0];
        assert!(Btf::parse(&short).is_err());
    }

    #[test]
    fn percpu_var_offset_resolves() {
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // type id 1
        let n_var = b.str("__preempt_count");
        b.var(n_var, 1); // type id 2
        let n_sec = b.str(".data..percpu");
        b.datasec(n_sec, &[(2, 126720, 4)]); // type id 3
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        assert_eq!(btf.percpu_var_offset("__preempt_count"), Some(126720));
        assert_eq!(btf.percpu_var_offset("nonexistent"), None);
    }

    #[test]
    fn member_offset_simple() {
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // id 1
        let n_ti = b.str("thread_info");
        let m_flags = b.str("flags");
        let m_count = b.str("preempt_count");
        // flags at bit 0, preempt_count at bit 64 (byte 8).
        b.composite(
            BTF_KIND_STRUCT,
            n_ti,
            16,
            &[(m_flags, 1, 0), (m_count, 1, 64)],
        );
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        assert_eq!(btf.member_offset("thread_info", "preempt_count"), Some(8));
        assert_eq!(btf.member_offset("thread_info", "flags"), Some(0));
        assert_eq!(btf.member_offset("thread_info", "missing"), None);
    }

    #[test]
    fn member_offset_recurses_anonymous_union() {
        // thread_info { u32 flags @0; anon union { u64 preempt_count; struct { u32 count; u32 need_resched } preempt } @64 }
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // id 1

        // inner struct "preempt": { count @0, need_resched @32 }
        let m_count = b.str("count");
        let m_nr = b.str("need_resched");
        b.composite(BTF_KIND_STRUCT, 0, 8, &[(m_count, 1, 0), (m_nr, 1, 32)]); // id 2 (anonymous name_off 0)

        // anon union { preempt_count @0 (id 1 int as placeholder), preempt @0 (id 2 struct) }
        let m_pc = b.str("preempt_count");
        let m_preempt = b.str("preempt");
        b.composite(BTF_KIND_UNION, 0, 8, &[(m_pc, 1, 0), (m_preempt, 2, 0)]); // id 3 (anonymous)

        // thread_info { flags @0, <anon union id 3> @64 }
        let n_ti = b.str("thread_info");
        let m_flags = b.str("flags");
        b.composite(BTF_KIND_STRUCT, n_ti, 16, &[(m_flags, 1, 0), (0, 3, 64)]); // id 4
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        // preempt.count: named member "preempt" (the anon-union member) then
        // "count" inside it — both land at byte 8.
        assert_eq!(btf.member_offset("thread_info", "preempt.count"), Some(8));
        // preempt_count (u64 in the anon union) also at byte 8, reached by
        // transparently descending the anonymous union.
        assert_eq!(btf.member_offset("thread_info", "preempt_count"), Some(8));
        // A bare "count" is NOT a direct member of thread_info (it lives under
        // the named "preempt"), so it must not resolve without the dotted path.
        assert_eq!(btf.member_offset("thread_info", "count"), None);
    }

    #[test]
    fn member_offset_follows_typedef_via_task_struct() {
        // task_struct { thread_info thread_info @0 } where thread_info has preempt_count @8.
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // id 1
        let n_ti = b.str("thread_info");
        let m_flags = b.str("flags");
        let m_count = b.str("preempt_count");
        b.composite(
            BTF_KIND_STRUCT,
            n_ti,
            16,
            &[(m_flags, 1, 0), (m_count, 1, 64)],
        ); // id 2
        let n_ts = b.str("task_struct");
        let m_ti = b.str("thread_info");
        b.composite(BTF_KIND_STRUCT, n_ts, 4096, &[(m_ti, 2, 0)]); // id 3, thread_info @0
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        assert_eq!(btf.member_offset("task_struct", "thread_info"), Some(0));
        assert_eq!(btf.member_offset("thread_info", "preempt_count"), Some(8));
    }

    #[test]
    fn member_offset_rejects_bitfield() {
        // A struct with kind_flag set (bitfield encoding) must refuse the member.
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // id 1
        let n_s = b.str("bitty");
        let m_x = b.str("x");
        // Manually emit a kind_flag struct with an actual bitfield member:
        // the offset word packs bitfield size in the high 8 bits (nonzero => a
        // real bitfield) and the bit offset in the low 24 bits (here zero).
        b.push32(n_s);
        b.push32(BtfBuilder::info(BTF_KIND_STRUCT, 1, true));
        b.push32(4);
        b.push32(m_x);
        b.push32(1);
        b.push32(4 << 24); // size=4 bits, bit offset=0 => bitfield
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        assert_eq!(btf.member_offset("bitty", "x"), None);
    }

    #[test]
    fn member_offset_normal_member_in_kind_flag_struct() {
        // A kind_flag struct may still contain normal (non-bitfield) members:
        // encoded size 0 means the offset word is a plain bit offset. Such a
        // member must resolve, not be refused.
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        b.int(n_int); // id 1
        let n_s = b.str("mixed");
        let m_y = b.str("y");
        // kind_flag struct, one member at bit offset 64 (byte 8), size 0.
        b.push32(n_s);
        b.push32(BtfBuilder::info(BTF_KIND_STRUCT, 1, true));
        b.push32(16);
        b.push32(m_y);
        b.push32(1);
        b.push32(64); // size=0, bit offset=64 => normal member
        let blob = b.build();

        let btf = Btf::parse(&blob).expect("parse");
        assert_eq!(btf.member_offset("mixed", "y"), Some(8));
    }

    #[test]
    fn kallsyms_parses_addr_and_type() {
        let text = "\
000000000001ef00 A __preempt_count
ffffffff823b6940 D __per_cpu_offset
ffffffff81000000 T _stext
";
        let k = Kallsyms::parse(text);
        assert_eq!(k.addr("__preempt_count"), Some(0x1ef00));
        assert_eq!(k.addr("__per_cpu_offset"), Some(0xffffffff823b6940));
        assert_eq!(k.addr("missing"), None);
    }

    #[test]
    fn kallsyms_handles_masked_addresses() {
        let text = "\
0000000000000000 A __preempt_count
0000000000000000 D __per_cpu_offset
";
        let k = Kallsyms::parse(text);
        assert_eq!(k.addr("__preempt_count"), Some(0));
    }

    #[test]
    fn detect_never_panics() {
        // Whatever the host looks like, detect() returns without panicking and
        // reports a valid mode. (Use `probee --print-kernel-layout` to inspect
        // the resolved layout on a real host.)
        let layout = detect();
        assert!(layout.mode() <= 2);
    }
}
