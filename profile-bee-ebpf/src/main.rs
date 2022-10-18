#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{BPF_F_USER_STACK, BPF_NOEXIST},
    macros::{kprobe, uprobe},
    macros::{map, perf_event, tracepoint},
    maps::{HashMap, Queue, StackTrace},
    programs::{PerfEventContext, TracePointContext},
    programs::ProbeContext,
    BpfContext,
};

use aya_log_ebpf::info;
use profile_bee_common::StackInfo;

pub const STACK_ENTRIES: u32 = 16392;
pub const STACK_SIZE: u32 = 16384;

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);
    skip > 0
}

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map]
static STACKS: Queue<StackInfo> = Queue::with_max_entries(STACK_ENTRIES, 0);

#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        collect_trace(ctx);
    }

    0
}

#[inline(always)]
unsafe fn collect_trace<C: BpfContext>(ctx: C) {
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
    };

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

        // 
        if let Err(e) = STACKS.push(&key, 0) {
            // info!(&ctx, "Error pushing stack: {}", e);
        }
    }

    // info!(&ctx, "try_profile_cpu {} {} user: {}, kernel: {}", pid, tgid, key.user_stack_id, key.kernel_stack_id);
}

#[kprobe(name="kprobe_profile")]
pub fn kprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[uprobe(name="uprobe_profile")]
pub fn uprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[tracepoint(name="tracepoint_profile")]
pub fn tracepoint_profile(ctx: TracePointContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
