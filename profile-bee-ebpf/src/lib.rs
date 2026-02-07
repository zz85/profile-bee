#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{pt_regs, BPF_F_USER_STACK},
    helpers::{bpf_get_smp_processor_id, bpf_probe_read},
    macros::map,
    maps::{HashMap, PerCpuArray, RingBuf, StackTrace},
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{FramePointers, StackInfo, EVENT_TRACE_ALWAYS, EVENT_TRACE_NEW};

pub const STACK_ENTRIES: u32 = 16392;
pub const STACK_SIZE: u32 = 2048;

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

#[no_mangle]
static NOTIFY_TYPE: u8 = EVENT_TRACE_ALWAYS;

#[inline]
unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);
    skip > 0
}

unsafe fn notify_type() -> u8 {
    core::ptr::read_volatile(&NOTIFY_TYPE)
}

/* Setup maps */
#[map]
static mut STORAGE: PerCpuArray<FramePointers> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "counts")]
pub static COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map(name = "stacked_pointers")]
pub static STACK_ID_TO_TRACES: HashMap<StackInfo, FramePointers> =
    HashMap::with_max_entries(STACK_SIZE, 0);

#[map]
static RING_BUF_STACKS: RingBuf = RingBuf::with_byte_size(STACK_SIZE, 0);

#[map(name = "stack_traces")]
pub static STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

#[inline(always)]
pub unsafe fn collect_trace<C: EbpfContext>(ctx: C) {
    let pid = ctx.pid();

    if pid == 0 && skip_idle() {
        // skip profiling idle traces
        return;
    }

    let cmd = ctx.command().unwrap_or_default();
    let tgid = ctx.tgid(); // thread group id
    let cpu = bpf_get_smp_processor_id();
    let user_stack_id = STACK_TRACES
        .get_stackid(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid(&ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    // Use CPU based storage so it doesn't occupy space on stack
    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;   
    };

    let pointer = &mut *pointer;
    let (ip, bp, stack_pointer, len) = copy_stack(&ctx, &mut pointer.pointers);
    pointer.len = len;
    pointer.stack_pointer = stack_pointer;

    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip: ip, // frame pointer
        bp: bp,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();

    // only assume true for "always mode"
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    // kernel space summarization
    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        // update hashmap with count and and only push new stack_infos to queue for symbol resolution
        let _ = COUNTS.insert(&stack_info, &1, 0); // BPF_F_NO_PREALLOC

        notify = true;
    }

    if notify {
        // notify user space of new stack information
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

const __START_KERNEL_MAP: u64 = 0xffffffff80000000;

/// puts the userspace stack in the target pointer slice
#[inline(always)]
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, u64, usize) {
    // reference pt_regs
    let regs =  ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;

    // instruction pointer
    let ip = regs.rip;

    // base pointer (frame pointer)
    let bp = regs.rbp;

    // stack pointer
    let stack_pointer = regs.rsp;
    if invalid_userspace_pointer(stack_pointer) {
        return (ip, bp, stack_pointer, 0);
    }

    let mut len = pointers.len();
    let mut addr = stack_pointer;
    // Read word-by-word since the helper reads typed values.
    for i in 0..pointers.len() {
        if invalid_userspace_pointer(addr) {
            len = i;
            break;
        }

        if let Some(value) = bpf_probe_read::<u64>(addr as *const u8 as _).ok() {
            pointers[i] = value;
        } else {
            len = i;
            break;
        }

        addr += core::mem::size_of::<u64>() as u64;
    }

    (ip, bp, stack_pointer, len)
}

#[inline(always)]
fn invalid_userspace_pointer(addr: u64) -> bool {
    addr == 0 || addr >= __START_KERNEL_MAP
}

// Make this simple now - checking for valid pointers can include
// checking with stack pointer address or getting valid ranges
// from from /proc/[pid]/maps
// void get_stack_bounds(u64 *stack_start, u64 *stack_end) {
//     struct task_struct *task;
//     task = (struct task_struct *)bpf_get_current_task();
//     // Read stack pointer and stack size from task_struct
//     bpf_probe_read(stack_start, sizeof(*stack_start), &task->stack);
//     *stack_end = *stack_start + THREAD_SIZE;  // THREAD_SIZE is typically 16KB on x86_64
// }
// bool valid_fp(u64 fp, u64 stack_start, u64 stack_end) {
//     // Check if frame pointer is within stack bounds and properly aligned
//     return (fp >= stack_start) &&
//            (fp < stack_end) &&
//            ((fp & 0x7) == 0);  // 8-byte aligned
// }
