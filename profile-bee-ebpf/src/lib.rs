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
    let (ip, bp, len, sp) = copy_stack(&ctx, &mut pointer.pointers);
    pointer.len = len;

    // // unwind 1 - hot
    // let cfa = sp + 8;
    // let Ok(ip) = bpf_probe_read::<u64>((cfa - 8) as *const u8 as _) else {
    //     return;
    // };
    // let sp = cfa;

    // // unwind 2 - func c
    // let cfa = sp + 8;
    // let Ok(ip) = bpf_probe_read::<u64>((cfa - 8) as *const u8 as _) else {
    //     return;
    // };
    // let sp = cfa;

    // // unwind 3 - func b
    // let cfa = sp + 8;
    // let Ok(ip) = bpf_probe_read::<u64>((cfa - 8) as *const u8 as _) else {
    //     return;
    // };
    // let sp = cfa;

    // // unwind 4 - func a
    // let cfa = sp + 8;
    // let Ok(ip) = bpf_probe_read::<u64>((cfa - 8) as *const u8 as _) else {
    //     return;
    // };
    // let sp = cfa;

    // // // unwind 5 - main
    // let cfa = sp + 8;
    // let Ok(ip) = bpf_probe_read::<u64>((cfa - 8) as *const u8 as _) else {
    //     return;
    // };
    // let sp = cfa;

    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip: ip, // frame pointer
        bp: bp,
        sp: sp, // stack pointer
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
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, usize, u64) {
    // refernce pt_regs
    let regs =  ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;

    // instruction pointer
    let ip = regs.rip;
    let sp = regs.rsp;

    // base pointer (frame pointer)
    let mut bp = regs.rbp;    

    pointers[0] = ip;

    let mut len = pointers.len();
    for i in 1..pointers.len() {
        let Some(ret_addr) = get_frame(&mut bp) else {
            len = i;
            break;
        };

        pointers[i] = ret_addr;
    }

    (ip, bp, len, sp)
}

/// unwind frame pointer
#[inline(always)]
unsafe fn get_frame(fp: &mut u64) -> Option<u64> {
    let bp = *fp;
    if bp == 0 {
        return None;
    }

    const RETURN_OFFSET: u64 = 8; // x86_64 offset to get return addr from the base pointer
    let return_addr: u64 = bp + RETURN_OFFSET;

    // return address is the instruction pointer
    let ip = bpf_probe_read::<u64>(return_addr as *const u8 as _).ok()?;

    // frame pointer points to the base pointer!
    let bp: u64 = bpf_probe_read(bp as *const u8 as _).unwrap_or_default();

    *fp = bp;

    // santity check whether is the framepointer
    if invalid_userspace_pointer(ip) {
        return None;
    }

    Some(ip)
}

#[inline(always)]
fn invalid_userspace_pointer(ip: u64) -> bool {
    ip == 0 || ip >= __START_KERNEL_MAP
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
