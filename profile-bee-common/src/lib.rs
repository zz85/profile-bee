#![no_std]

use aya::Pod;
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
    pub bp: u64,
    pub ip: u64,
}

impl StackInfo {
    pub const STRUCT_SIZE: usize = size_of::<StackInfo>();
}

unsafe impl Pod for StackInfo {}

pub static EVENT_TRACE_ALWAYS: u8 = 1;
pub static EVENT_TRACE_NEW: u8 = 2;
pub static EVENT_TRACE_NONE: u8 = 3;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct FramePointers {
    pub pointers: [u64; 16],
    pub len: u64, // Changed from usize to u64 for consistent size across platforms
}

unsafe impl Pod for FramePointers {}

impl FramePointers {
    pub const STRUCT_SIZE: usize = size_of::<FramePointers>();
}

/// If we want to use a userspace buffer for longer stacks
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct StackPackage {
    stack_info: StackInfo,
    frame_pointers: Option<FramePointers>,
}

impl StackPackage {
    pub const STRUCT_SIZE: usize = size_of::<StackPackage>();
}
