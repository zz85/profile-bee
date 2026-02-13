#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, uprobe, uretprobe},
    macros::{perf_event, raw_tracepoint, tracepoint},
    programs::{PerfEventContext, RawTracePointContext, TracePointContext},
    programs::{ProbeContext, RetProbeContext},
};
use profile_bee_ebpf::{
    collect_trace, collect_trace_raw_syscall, collect_trace_raw_syscall_exit,
    collect_trace_raw_tp_with_task_regs, collect_trace_stackid_only, handle_process_exit,
};

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
    // TracePointContext.as_ptr() points to a tracepoint-specific data struct,
    // NOT pt_regs. Must use stackid-only path to avoid reading garbage registers.
    unsafe { collect_trace_stackid_only(ctx) }
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_tp_sys_enter(ctx: RawTracePointContext) -> u32 {
    unsafe { collect_trace_raw_syscall(ctx) }
    0
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn raw_tp_sys_exit(ctx: RawTracePointContext) -> u32 {
    unsafe { collect_trace_raw_syscall_exit(ctx) }
    0
}

/// Generic raw tracepoint for non-syscall events (sched, block, net, tcp, etc.).
/// No hardcoded tracepoint name — userspace picks it at attach time.
/// Uses bpf_get_stackid() only (no custom FP/DWARF unwinding).
#[raw_tracepoint]
pub fn raw_tp_generic(ctx: RawTracePointContext) -> u32 {
    unsafe { collect_trace_stackid_only(ctx) }
    0
}

/// Raw tracepoint with task pt_regs for non-syscall events.
/// Uses bpf_get_current_task_btf() + bpf_task_pt_regs() for full
/// FP/DWARF unwinding. Requires kernel >= 5.15; will fail to load
/// on older kernels, falling back to raw_tp_generic.
#[raw_tracepoint]
pub fn raw_tp_with_regs(ctx: RawTracePointContext) -> u32 {
    unsafe { collect_trace_raw_tp_with_task_regs(ctx) }
    0
}

/// Tracepoint for monitoring process exit events.
/// This allows us to detect when a monitored PID exits without polling.
#[tracepoint(tracepoint = "sched:sched_process_exit")]
pub fn tracepoint_process_exit(ctx: TracePointContext) -> u32 {
    unsafe { handle_process_exit(ctx) }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
