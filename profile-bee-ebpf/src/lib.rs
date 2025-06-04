#![no_std]

use core::mem::offset_of;

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{pt_regs, BPF_FIB_LKUP_RET_NO_NEIGH, BPF_F_USER_STACK},
    helpers::{bpf_get_smp_processor_id, bpf_probe_read, bpf_probe_read_kernel},
    macros::map,
    maps::{HashMap, PerfEventArray, Queue, RingBuf, StackTrace},
    EbpfContext,
};

// mod pt_regs;
// pub use pt_regs::*;

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

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map(name = "custom_traces")]
pub static mut STACK_ID_TO_TRACES: HashMap<StackInfo, FramePointers> = HashMap::with_max_entries(STACK_SIZE, 0);

#[map]
static RING_BUF_STACKS: RingBuf = RingBuf::with_byte_size(STACK_SIZE, 0);

#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

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

    let mut pointers = [0u64; 16];
    let (ip, bp, len) = copy_stack(&ctx, &mut pointers);
    let pointer = FramePointers{ pointers, len };
    
    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip: ip, // frame pointer
        bp: bp,
    };

    STACK_ID_TO_TRACES.insert(&stack_info, &pointer, 0);

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
        if let Some(mut v) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = v.write(stack_info);
            v.submit(0);
        }
    }
}

const __START_KERNEL_MAP: u64 = 0xffffffff80000000;

#[inline(always)]
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, usize) {
    let ctx_ptr = ctx.as_ptr();
    let regs  = ctx_ptr as *const pt_regs;
    let regs = &*regs;

    // instruction pointer
    let ip = regs.rip;

    // base pointer (frame pointer)
    let bp = regs.rbp;

    pointers[0] = ip;

    let mut bp = bp;
    let mut len = pointers.len();
    for i in 1..pointers.len() {
        let Some(ret_addr) = get_frame(&mut bp) else {
            len = i;
            break;
        };

        pointers[i] = ret_addr;
    }

    (ip, bp, len)
}

#[inline(always)]
unsafe fn get_frame(fp: &mut u64) -> Option<u64> {
    let bp = *fp;
    if bp == 0 {
        return None;
    }

    let offset = 8; // x86_64 dependent!
    let ret_offset: u64 = bp + offset;

    // return address is the instruction pointer
    let ret_addr = bpf_probe_read::<u64>(ret_offset as *const u8 as _).ok()?;
    
    // base pointer is the frame pointer!
    let bp: u64 = bpf_probe_read(bp as *const u8 as _).unwrap_or_default();

    *fp = bp;

    // TODO santify check whether is the framepointer
    // if ret_addr < __START_KERNEL_MAP {
    //     return None;
    // }

    Some(ret_addr)
}


// void get_stack_bounds(u64 *stack_start, u64 *stack_end) {
//     struct task_struct *task;
//     task = (struct task_struct *)bpf_get_current_task();
    
//     // Read stack pointer and stack size from task_struct
//     bpf_probe_read(stack_start, sizeof(*stack_start), &task->stack);
//     *stack_end = *stack_start + THREAD_SIZE;  // THREAD_SIZE is typically 16KB on x86_64
// }
// or get from /proc/[pid]/maps
// bool valid_fp(u64 fp, u64 stack_start, u64 stack_end) {
//     // Check if frame pointer is within stack bounds and properly aligned
//     return (fp >= stack_start) && 
//            (fp < stack_end) && 
//            ((fp & 0x7) == 0);  // 8-byte aligned
// }

