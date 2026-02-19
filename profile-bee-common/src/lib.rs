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
}

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

/// Process exit notification sent from eBPF to userspace
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct ProcessExitEvent {
    pub pid: u32,
    pub exit_code: i32,
}

impl ProcessExitEvent {
    pub const STRUCT_SIZE: usize = size_of::<ProcessExitEvent>();
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

/// Maximum number of inner shard maps in the outer ArrayOfMaps.
/// With array-of-maps, unused slots cost nothing (no pre-allocated kernel memory).
pub const MAX_UNWIND_SHARDS: usize = 64;
/// Maximum unwind entries per inner shard map.
/// With array-of-maps, each inner map is sized to the actual binary's table,
/// but we need an upper bound for the binary search depth (17 iterations covers 2^17 = 128K).
pub const MAX_SHARD_ENTRIES: u32 = 131_072;
/// Binary search iterations needed: ceil(log2(MAX_SHARD_ENTRIES)) = 17
pub const MAX_BIN_SEARCH_DEPTH: u32 = 17;
/// Sentinel value: no shard assigned to this mapping
pub const SHARD_NONE: u8 = 0xFF;

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
    pub shard_id: u8, // Which shard Array to search (0..MAX_UNWIND_SHARDS-1, or SHARD_NONE)
    pub _pad1: [u8; 3],
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
}
