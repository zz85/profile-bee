#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, uprobe},
    macros::{perf_event, tracepoint},
    programs::ProbeContext,
    programs::{PerfEventContext, TracePointContext},
};
use profile_bee_ebpf::collect_trace;

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        collect_trace(ctx);
    }

    0
}

#[kprobe(name = "kprobe_profile")]
pub fn kprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[uprobe(name = "uprobe_profile")]
pub fn uprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[tracepoint(name = "tracepoint_profile")]
pub fn tracepoint_profile(ctx: TracePointContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
