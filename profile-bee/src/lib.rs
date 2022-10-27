use aya::maps::{MapRef, StackTraceMap};
use profile_bee_common::StackInfo;
use symbols::{StackFrameInfo, StackInfoExt, SymbolFinder};

pub mod process;
pub mod symbols;

/// converts pointers from bpf to usable, symbol resolved stack information
pub fn format_stack_trace(
    stack_info: &StackInfo,
    stack_traces: &StackTraceMap<MapRef>,
    symbols: &mut SymbolFinder,
    group_by_cpu: bool,
) -> Vec<StackFrameInfo> {
    let ktrace_id = stack_info.kernel_stack_id;
    let utrace_id = stack_info.user_stack_id;

    if stack_info.tgid == 0 {
        let mut idle = StackFrameInfo::prepare(stack_info);
        idle.symbol = Some("idle".into());
        let mut idle_cpu = StackFrameInfo::process_only(stack_info);

        if let Some(cpu_id) = stack_info.get_cpu_id() {
            idle_cpu.symbol = Some(format!("cpu_{:02}", cpu_id));
        } else {
            idle_cpu.symbol = idle_cpu.symbol.map(|s| s.replace("swapper/", "cpu_"));
        }

        if group_by_cpu {
            if let Some(cpu_id) = stack_info.get_cpu_id() {
                idle_cpu.symbol = Some(format!("cpu_{:02}", cpu_id));
                return vec![idle_cpu, idle];
            }
        }

        return vec![idle, idle_cpu];
    }

    let kernel_stacks = if ktrace_id > -1 {
        stack_traces
            .get(&(ktrace_id as u32), 0)
            .map(|mut trace| symbols.resolve_kernel_trace(&mut trace, stack_info))
            .ok()
    } else {
        None
    };

    let user_stacks = if utrace_id > -1 {
        stack_traces
            .get(&(utrace_id as u32), 0)
            .map(|trace| symbols.resolve_user_trace(&trace, stack_info))
            .ok()
    } else {
        None
    };

    let mut combined = match (kernel_stacks, user_stacks) {
        (Some(kernel_stacks), None) => kernel_stacks,
        (None, Some(user_stacks)) => user_stacks,
        (Some(kernel_stacks), Some(user_stacks)) => kernel_stacks
            .into_iter()
            .chain(user_stacks.into_iter())
            .collect::<Vec<_>>(),
        _ => Default::default(),
    };

    let pid_info = StackFrameInfo::process_only(stack_info);
    combined.push(pid_info);

    if group_by_cpu {
        if let Some(cpu_id) = stack_info.get_cpu_id() {
            let frame = StackFrameInfo {
                symbol: Some(format!("cpu_{:02}", cpu_id)),
                ..Default::default()
            };

            combined.push(frame);
        }
    }

    combined.reverse();

    combined
}
