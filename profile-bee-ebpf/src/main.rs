#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, uprobe, uretprobe},
    macros::{perf_event, raw_tracepoint, tracepoint},
    programs::{PerfEventContext, RawTracePointContext, TracePointContext},
    programs::{ProbeContext, RetProbeContext},
};
use profile_bee_ebpf::{collect_trace, collect_trace_raw_syscall};

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        collect_trace(ctx);
    }

    0
}

#[kprobe]
pub fn kprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[uprobe]
pub fn uprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[uretprobe]
pub fn uretprobe_profile(ctx: RetProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[tracepoint]
pub fn tracepoint_profile(ctx: TracePointContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_tp_sys_enter(ctx: RawTracePointContext) -> u32 {
    unsafe { collect_trace_raw_syscall(ctx) }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
