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

// --- DWARF Unwind Table Types ---

/// How to compute the CFA (Canonical Frame Address)
pub const CFA_REG_RSP: u8 = 0;
pub const CFA_REG_RBP: u8 = 1;
/// CFA rule uses a DWARF expression (unsupported in eBPF, skip)
pub const CFA_REG_EXPRESSION: u8 = 2;

/// How to recover a register value
pub const REG_RULE_OFFSET: u8 = 0; // Value at CFA + offset
pub const REG_RULE_SAME_VALUE: u8 = 1; // Register unchanged
pub const REG_RULE_UNDEFINED: u8 = 2; // Register not recoverable
pub const REG_RULE_REGISTER: u8 = 3; // Value is in another register
pub const REG_RULE_EXPRESSION: u8 = 4; // DWARF expression (unsupported)

/// Compact unwind table entry for a single PC range.
///
/// This is a simplified representation of DWARF CFI (Call Frame Information)
/// that can be efficiently used in eBPF programs for stack unwinding.
///
/// For x86_64:
/// - CFA is typically RSP+offset or RBP+offset
/// - Return address is at CFA-8
/// - RBP may need to be restored from the stack
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UnwindEntry {
    /// Start PC of this entry (relative to the binary base)
    pub pc: u64,
    /// CFA register type (CFA_REG_RSP, CFA_REG_RBP, CFA_REG_EXPRESSION)
    pub cfa_type: u8,
    pub _pad1: [u8; 3],
    /// CFA offset from the register
    pub cfa_offset: i32,
    /// How to find the return address (REG_RULE_*)
    pub ra_type: u8,
    pub _pad2: [u8; 3],
    /// Offset from CFA to the return address
    pub ra_offset: i32,
    /// How to find RBP (REG_RULE_*)
    pub rbp_type: u8,
    pub _pad3: [u8; 3],
    /// Offset from CFA to the saved RBP
    pub rbp_offset: i32,
}

impl UnwindEntry {
    pub const STRUCT_SIZE: usize = size_of::<UnwindEntry>();
}

/// Maximum stack depth for DWARF unwinding in eBPF
pub const MAX_DWARF_STACK_DEPTH: usize = 127;

/// Maximum number of unwind table entries (shared across all processes)
pub const MAX_UNWIND_TABLE_SIZE: u32 = 250_000;

/// Maximum number of executable mappings tracked per process
pub const MAX_PROC_MAPS: usize = 64;

/// Key for looking up a process's memory mapping info
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ProcInfoKey {
    /// Process ID (tgid)
    pub tgid: u32,
    pub _pad: u32,
}

/// An executable memory mapping within a process
///
/// Maps a virtual address range to a region of the global unwind table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ExecMapping {
    /// Start virtual address of the mapping
    pub begin: u64,
    /// End virtual address of the mapping
    pub end: u64,
    /// Load address bias (virtual addr - file offset)
    pub load_bias: u64,
    /// Index into the global unwind table where this mapping's entries begin
    pub table_start: u32,
    /// Number of unwind entries for this mapping
    pub table_count: u32,
}

/// Per-process info: list of executable mappings
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProcInfo {
    /// Number of valid executable mappings
    pub mapping_count: u32,
    pub _pad: u32,
    /// Executable mappings sorted by virtual address
    pub mappings: [ExecMapping; MAX_PROC_MAPS],
}
