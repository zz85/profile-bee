#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_bpf::{
    bindings::BPF_F_USER_STACK,
    helpers::bpf_get_smp_processor_id,
    macros::map,
    maps::{HashMap, Queue, StackTrace},
    BpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::StackInfo;

pub const STACK_ENTRIES: u32 = 16392;
pub const STACK_SIZE: u32 = 2048;

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);
    skip > 0
}

/* Setup maps */

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map]
static STACKS: Queue<StackInfo> = Queue::with_max_entries(STACK_ENTRIES, 0);

#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

#[inline(always)]
pub unsafe fn collect_trace<C: BpfContext>(ctx: C) {
    let pid = ctx.pid();

    if skip_idle() && pid == 0 {
        // not profiling idle
        return;
    }

    let cmd = ctx.command().unwrap_or_default();
    let tgid = ctx.tgid(); // thread group id

    let mut key = StackInfo {
        tgid,
        user_stack_id: -1,
        kernel_stack_id: -1,
        cmd,
        cpu: u32::MAX,
    };

    key.cpu = bpf_get_smp_processor_id();

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
        key.user_stack_id = stack_id as i32;
    }

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, 0) {
        key.kernel_stack_id = stack_id as i32;
    }

    if let Some(count) = COUNTS.get_ptr_mut(&key) {
        *count += 1;
    } else {
        // update hashmap with count and and only push new keys to queue for symbol resolution
        let _ = COUNTS.insert(&key, &1, 0); // BPF_F_NO_PREALLOC

        // notify
        if let Err(_e) = STACKS.push(&key, 0) {
            // info!(&ctx, "Error pushing stack: {}", e);
        }
    }
}
