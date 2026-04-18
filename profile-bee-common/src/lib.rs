#![no_std]

use core::mem::size_of;

/// Stack trace information shared between eBPF and userspace
///
/// Contains the process ID, stack trace IDs for both kernel and user stacks,
/// process name, and CPU ID for a single stack sample collected by the profiler.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct StackInfo {
    pub tgid: u32,
    pub user_stack_id: i32,
    pub kernel_stack_id: i32,
    pub cmd: [u8; 16],
    pub cpu: u32,
    // for dev debugging
    pub bp: u64,
    pub ip: u64,
    pub sp: u64,
}

impl StackInfo {
    pub const STRUCT_SIZE: usize = size_of::<StackInfo>();
}

pub static EVENT_TRACE_ALWAYS: u8 = 1;
pub static EVENT_TRACE_NEW: u8 = 2;
pub static EVENT_TRACE_NONE: u8 = 3;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct FramePointers {
    /// Maximum stack depth supported (1024 frames * 8 bytes = 8KB)
    pub pointers: [u64; 1024],
    /// Describes depth of stack trace (number of frames)
    /// This could be optional because the array is 0 terminated
    pub len: usize,
    /// V8 SharedFunctionInfo tagged pointers, parallel to `pointers`.
    /// For frame i: if `v8_sfi[i] != 0`, the frame is V8 JIT/interpreter
    /// code and `v8_sfi[i]` is the tagged SharedFunctionInfo pointer
    /// extracted from the V8 FP context. Userspace uses this to resolve
    /// JavaScript function names via `process_vm_readv`.
    ///
    /// **Only the first `MAX_V8_FRAMES` (64) entries are populated.**
    /// The eBPF FP walker in `copy_stack_regs` (profile-bee-ebpf `lib.rs`)
    /// stops extracting V8 SFI data at `i >= MAX_V8_FRAMES`, so deep V8
    /// stacks (>64 JS frames) will have their tail frames degrade to
    /// `[unknown]` in the flamegraph.  V8 stacks rarely exceed 64 JS
    /// frames in practice.
    pub v8_sfi: [u64; MAX_V8_FRAMES],
}

/// Maximum V8 frames with metadata per stack sample.
/// V8 stacks rarely exceed 64 JS frames.
pub const MAX_V8_FRAMES: usize = 64;

impl FramePointers {
    pub const STRUCT_SIZE: usize = size_of::<FramePointers>();
}

/// Currently not used, but this would be used for
/// sending events to UserSpace via RingBuf
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct ProbeEvent {
    pub stack_info: StackInfo,
    pub frame_pointers: Option<FramePointers>,
}

impl ProbeEvent {
    pub const STRUCT_SIZE: usize = size_of::<ProbeEvent>();
}

/// Process exit notification sent from eBPF to userspace.
/// Deprecated: prefer `ProcessEvent` which carries both exec and exit events.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct ProcessExitEvent {
    pub pid: u32,
    pub exit_code: i32,
}

impl ProcessExitEvent {
    pub const STRUCT_SIZE: usize = size_of::<ProcessExitEvent>();
}

/// Process exec notification sent from eBPF to userspace when a process
/// calls execve(). Used for proactive DWARF table loading and cache invalidation.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub _pad: u32,
}

impl ProcessExecEvent {
    pub const STRUCT_SIZE: usize = size_of::<ProcessExecEvent>();
}

// --- Process Lifecycle Event Types ---

/// Process lifecycle event type: process exited.
pub const PROCESS_EVENT_EXIT: u32 = 0;
/// Process lifecycle event type: process called execve().
pub const PROCESS_EVENT_EXEC: u32 = 1;

/// Unified process lifecycle event sent from eBPF to userspace.
/// Carries both exec and exit notifications through a single ring buffer,
/// replacing the narrower `ProcessExitEvent`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct ProcessEvent {
    /// Event type: `PROCESS_EVENT_EXIT` or `PROCESS_EVENT_EXEC`.
    pub event_type: u32,
    /// The PID (tgid) of the process.
    pub pid: u32,
    /// For EXIT events: the exit code. For EXEC events: 0.
    pub exit_code: i32,
    pub _pad: u32,
}

impl ProcessEvent {
    pub const STRUCT_SIZE: usize = size_of::<ProcessEvent>();
}

// --- DWARF Unwind Table Types (used by eBPF-side unwinding) ---

/// How to compute the CFA (Canonical Frame Address)
pub const CFA_REG_RSP: u8 = 0;
pub const CFA_REG_RBP: u8 = 1;
pub const CFA_REG_EXPRESSION: u8 = 2;
/// PLT stub: CFA = RSP + offset + ((RIP & 15) >= 11 ? offset : 0)
pub const CFA_REG_PLT: u8 = 3;
/// Signal frame: CFA = *(RSP + offset)  (dereference)
pub const CFA_REG_DEREF_RSP: u8 = 4;

/// How to recover a register value
pub const REG_RULE_OFFSET: u8 = 0;
pub const REG_RULE_SAME_VALUE: u8 = 1;
pub const REG_RULE_UNDEFINED: u8 = 2;
pub const REG_RULE_REGISTER: u8 = 3;
pub const REG_RULE_EXPRESSION: u8 = 4;

/// Compact unwind table entry for eBPF-side stack unwinding.
///
/// On x86_64, the return address is always at CFA-8, so we don't store RA
/// rule/offset. Using u32 for PC (file-relative addresses fit in 4GB) and
/// i16 offsets gives us 12 bytes per entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UnwindEntry {
    pub pc: u32,
    pub cfa_offset: i16,
    pub rbp_offset: i16,
    pub cfa_type: u8,
    pub rbp_type: u8,
    pub _pad: [u8; 2],
}

impl UnwindEntry {
    pub const STRUCT_SIZE: usize = size_of::<UnwindEntry>();
}

/// Maximum frames to unwind per tail-call iteration
pub const FRAMES_PER_TAIL_CALL: usize = 5;
/// Maximum tail-call depth (kernel limit is 33)
pub const MAX_TAIL_CALLS: usize = 33;
/// Maximum total stack depth with tail-call chaining
pub const MAX_DWARF_STACK_DEPTH: usize = FRAMES_PER_TAIL_CALL * MAX_TAIL_CALLS; // 165 frames
/// Legacy single-loop depth limit (for non-perf_event program types where
/// tail-call chaining is unavailable: kprobe, uprobe, raw_tracepoint).
/// Reduced from 21 to 4 to stay within the BPF verifier's 1M instruction limit
/// on newer kernels (6.14+). The primary perf_event path uses tail-call chaining
/// for up to 165 frames; this limit only affects kprobe/uprobe/raw_tracepoint.
pub const LEGACY_MAX_DWARF_STACK_DEPTH: usize = 4;

pub const MAX_PROC_MAPS: usize = 8;

/// Maximum entries in the LPM trie for exec mappings.
/// Each memory mapping decomposes into ~10-20 LPM prefix entries.
/// 200K entries covers ~200 processes × ~50 mappings × ~20 entries each.
/// BPF_F_NO_PREALLOC means only inserted entries consume memory.
pub const MAX_EXEC_MAPPING_ENTRIES: u32 = 200_000;

/// Data portion of the LPM trie key for exec mapping lookups.
/// Combined with aya's Key<T> which prepends a u32 prefix_len field.
/// Total key: { prefix_len: u32, tgid: u32, _pad: u32, address: u64 } = 20 bytes.
///
/// Both fields are stored in **big-endian** because the LPM trie matches
/// bits from most-significant to least-significant. Big-endian ensures the
/// MSBs of the values are physically first in memory.
///
/// The explicit `_pad` field ensures `address` is 8-byte aligned (avoiding
/// unaligned 64-bit access from `#[repr(C, packed)]`). It must always be
/// set to 0 so the LPM trie bit-matching is consistent across the 32 padding
/// bits.
///
/// Full match prefix_len = 128 (32 bits tgid + 32 bits padding + 64 bits address).
///
/// Use `EXEC_MAPPING_KEY_BITS` instead of hard-coding 128 at LPM trie call sites.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ExecMappingKey {
    pub tgid: u32,    // big-endian
    pub _pad: u32,    // must be 0
    pub address: u64, // big-endian
}

/// Total bit-width of `ExecMappingKey` for LPM trie full-match prefix_len.
/// Derived from the struct size so it stays correct if the layout changes.
pub const EXEC_MAPPING_KEY_BITS: u32 = (size_of::<ExecMappingKey>() * 8) as u32;

/// Maximum number of inner shard maps in the outer ArrayOfMaps.
/// With array-of-maps, unused slots cost nothing (no pre-allocated kernel memory).
pub const MAX_UNWIND_SHARDS: usize = 512;
/// Maximum unwind entries per inner shard map.
/// With array-of-maps, each inner map is sized to the actual binary's table,
/// but we need an upper bound for the binary search depth (17 iterations covers 2^17 = 128K).
pub const MAX_SHARD_ENTRIES: u32 = 131_072;
/// Binary search iterations needed: ceil(log2(MAX_SHARD_ENTRIES)) = 17
pub const MAX_BIN_SEARCH_DEPTH: u32 = 17;
/// Sentinel value: no shard assigned to this mapping
pub const SHARD_NONE: u16 = 0xFFFF;

// --- V8 / Node.js Introspection ---

/// V8 FP context size: the eBPF V8 frame extractor reads this many bytes
/// below the frame pointer to find the JSFunction and bytecode offset.
pub const V8_FP_CONTEXT_SIZE: usize = 64;

/// Compact V8 introspection data shared between userspace and eBPF.
///
/// Userspace populates this from `v8dbg_*` ELF symbols in the Node.js binary
/// and loads it into the `v8_proc_info` eBPF map. The eBPF code uses these
/// offsets to read the JSFunction pointer from V8's FP context slots during
/// stack unwinding, without any V8-version-specific logic in eBPF.
///
/// Layout matches the OTel eBPF profiler's V8ProcInfo for compatibility.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct V8ProcInfo {
    /// V8 version: (major << 24) | (minor << 16) | patch
    pub version: u32,
    // Instance type ranges for type-checking heap objects
    pub type_jsfunction_first: u16,
    pub type_jsfunction_last: u16,
    pub type_code: u16,
    pub type_shared_function_info: u16,
    // Heap object field offsets
    pub off_heap_object_map: u8,
    pub off_map_instance_type: u8,
    pub off_jsfunction_shared: u8,
    /// Byte offset within the 64-byte FP context buffer for the JSFunction slot.
    /// The eBPF code reads [fp - V8_FP_CONTEXT_SIZE] and indexes at this offset.
    pub fp_function: u8,
    pub _pad: [u8; 4],
}

impl V8ProcInfo {
    pub const STRUCT_SIZE: usize = size_of::<V8ProcInfo>();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ProcInfoKey {
    pub tgid: u32,
    pub _pad: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ExecMapping {
    pub begin: u64,
    pub end: u64,
    pub load_bias: u64,
    pub shard_id: u16, // Which shard Array to search (0..MAX_UNWIND_SHARDS-1, or SHARD_NONE)
    pub _pad1: [u8; 2],
    pub table_count: u32, // Number of entries in this shard for this binary
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProcInfo {
    pub mapping_count: u32,
    pub _pad: u32,
    pub mappings: [ExecMapping; MAX_PROC_MAPS],
}

/// Per-CPU state for DWARF unwinding with tail-call support.
/// This structure is stored in a PerCpuArray and persists across tail calls.
/// It contains both unwinding state and finalization context so the tail-call
/// step program can complete the work started by collect_trace.
///
/// Also reused by the FP+V8 tail-call walker (PROG_ARRAY index 1) which
/// stores FP walk progress and V8 SFI extraction results in the same struct.
/// The two paths are mutually exclusive per-sample (DWARF vs FP), so sharing
/// the per-CPU state is safe.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct DwarfUnwindState {
    /// Stack trace frame pointers (RIP values)
    pub pointers: [u64; 1024],
    /// Current number of frames unwound
    pub frame_count: usize,
    /// Current instruction pointer (RIP for next frame to unwind)
    pub current_ip: u64,
    /// Current stack pointer
    pub sp: u64,
    /// Current base pointer
    pub bp: u64,
    /// Initial RIP (for StackInfo.ip after finalization)
    pub initial_ip: u64,
    /// Initial RBP (for StackInfo.bp after finalization)
    pub initial_bp: u64,
    /// Initial RSP (for StackInfo.sp after finalization)
    pub initial_sp: u64,
    /// Process ID for looking up unwind tables
    pub tgid: u32,
    /// Mapping count for the process
    pub mapping_count: u32,
    /// Saved user stack ID from bpf_get_stackid (for finalization)
    pub user_stack_id: i32,
    /// Saved kernel stack ID from bpf_get_stackid (for finalization)
    pub kernel_stack_id: i32,
    /// Saved process command name (for finalization)
    pub cmd: [u8; 16],
    /// Saved CPU ID (for finalization)
    pub cpu: u32,
    pub _pad2: u32,
    /// V8 SharedFunctionInfo tagged pointers extracted during FP+V8 tail-call
    /// walking. Parallel to `pointers[0..MAX_V8_FRAMES]`. Zero means "not a
    /// V8 frame" or "beyond V8 extraction limit".
    /// Only used by the FP+V8 step program (PROG_ARRAY index 1); the DWARF
    /// step program (index 0) ignores this field.
    pub v8_sfi: [u64; MAX_V8_FRAMES],
}
