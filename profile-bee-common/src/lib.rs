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

pub const MAX_DWARF_STACK_DEPTH: usize = 16;
pub const MAX_UNWIND_TABLE_SIZE: u32 = 500_000;
pub const MAX_PROC_MAPS: usize = 8;

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
    pub table_start: u32,
    pub table_count: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProcInfo {
    pub mapping_count: u32,
    pub _pad: u32,
    pub mappings: [ExecMapping; MAX_PROC_MAPS],
}
