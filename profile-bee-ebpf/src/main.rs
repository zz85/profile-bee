#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
    bindings::{BPF_F_USER_STACK, BPF_NOEXIST},
    maps::{HashMap, StackTrace, Queue},
    macros::{map, perf_event},
    programs::PerfEventContext,
    BpfContext,
};

use aya_log_ebpf::info;
use profile_bee_common::StackInfo;

pub const STACK_ENTRIES: u32 = 1024;
pub const STACK_SIZE: u32 = 127;

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);
    skip > 0
}


#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackInfo, u64> =
    HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map]
static STACKS: Queue<StackInfo> = Queue::with_max_entries(STACK_ENTRIES * STACK_ENTRIES, 0);


#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);


#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        try_profile_cpu(ctx);
    }

    0
}



#[inline(always)]
unsafe fn try_profile_cpu(ctx: PerfEventContext) {
    let pid = ctx.pid();
    
    if skip_idle() && pid == 0 {
        // not profiling idle
        return;
    }

    let cmd = ctx.command().unwrap();
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

    // TODO update hashmap with count and and only push new keys to queue for symbol resolution

    info!(&ctx, "try_profile_cpu {} {} user: {}, kernel: {}", pid, tgid, key.user_stack_id, key.kernel_stack_id);

    if let Err(e) = STACKS.push(&key, 0) {
        info!(&ctx, "Error pushing stack: {}", e);
    }
}

// #[kprobe(name="kprobe_profile")]
// pub fn kprobe_profile(ctx: ProbeContext) -> u32 {
//     match unsafe { try_kprobe_profile(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// unsafe fn try_kprobe_profile(ctx: ProbeContext) -> Result<u32, u32> {
//     info!(&ctx, "function try_profsample called");
//     Ok(0)
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
