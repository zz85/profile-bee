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
    /// Maximum raw stack snapshot size (1024 words * 8 bytes = 8 KiB) used for DWARF unwinding.
    pub pointers: [u64; 1024],
    /// Describes depth of captured raw stack words for DWARF unwinding
    pub len: usize,
    /// Stack pointer used for the snapshot
    pub stack_pointer: u64,
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
