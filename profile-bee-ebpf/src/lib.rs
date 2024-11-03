#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    helpers::bpf_get_smp_processor_id,
    macros::map,
    maps::{HashMap, Queue, StackTrace, PerfEventArray, RingBuf},
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{StackInfo, EVENT_TRACE_NEW, EVENT_TRACE_ALWAYS};

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
    let user_stack_id = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()).map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES.get_stackid(&ctx, 0).map_or(-1, |stack_id| stack_id as i32);

    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
    };

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
            v.write(stack_info);
            v.submit(0);
        }
    }
}
