use crate::{cache::PointerStackFramesCache, types::StackFrameInfo, types::StackInfoExt};
use aya::maps::MapData;
use aya::maps::StackTraceMap;
use blazesym::symbolize::source::Kernel;
use blazesym::symbolize::source::Process;
use blazesym::symbolize::source::Source;
use blazesym::symbolize::Input;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::Pid;
use profile_bee_common::FramePointers;
use profile_bee_common::StackInfo;

pub struct SymbolFormatter;

impl SymbolFormatter {
    /// Simple symbol kernel name only
    fn map_kernel_sym_to_stack(sym: Symbolized) -> StackFrameInfo {
        let sym = match sym {
            Symbolized::Sym(sym) => sym,
            Symbolized::Unknown(_reason) => {
                return StackFrameInfo {
                    symbol: Some(format!("[unknown]")), // {reason}
                    ..Default::default()
                };
            }
        };

        StackFrameInfo {
            symbol: Some(format!("{}_k", sym.name)),
            ..Default::default()
        }
    }

    /// Simple symbol name only
    fn map_user_sym_to_stack(sym: Symbolized) -> StackFrameInfo {
        let sym = match sym {
            Symbolized::Sym(sym) => sym,
            Symbolized::Unknown(_reason) => {
                return StackFrameInfo {
                    symbol: Some(format!("[unknown]")), // {reason}
                    ..Default::default()
                };
            }
        };

        StackFrameInfo {
            symbol: Some(format!("{}", sym.name)),
            ..Default::default()
        }
    }
}

/// Trace Handler convert address into proper stacktraces, apply necessary caching
///
/// Main entry point for the trace handler that manages symbol resolution and caching
/// for efficient stack trace processing and visualization.
pub struct TraceHandler {
    /// blazesym Symbolizer that internally handles caching
    symbolizer: Symbolizer,
    /// Simple Cache
    cache: PointerStackFramesCache,
}

impl TraceHandler {
    pub fn new() -> Self {
        TraceHandler {
            symbolizer: Symbolizer::new(),
            cache: Default::default(),
        }
    }

    pub fn print_stats(&self) {
        println!("{}", self.cache.stats());
    }

    /// converts kernel stacked frames into symbols
    fn symbolize_kernel_stack(&self, addrs: &[Addr]) -> Result<Vec<StackFrameInfo>, &str> {
        let src = Source::Kernel(Kernel::default());
        let syms = self
            .symbolizer
            .symbolize(&src, Input::AbsAddr(&addrs))
            .map_err(|e| {
                tracing::error!("Failed to symbolize {:?}", e);
                "failed to run symbolize"
            })?
            .into_iter()
            .map(SymbolFormatter::map_kernel_sym_to_stack)
            .collect::<Vec<_>>();

        Ok(syms)
    }

    /// convert user mode stacked frames into symbols
    fn symbolize_user_stack(&self, pid: u32, addrs: &[Addr]) -> Result<Vec<StackFrameInfo>, &str> {
        let src: Source<'_> = Source::Process(Process::new(Pid::from(pid)));

        let syms = self
            .symbolizer
            .symbolize(&src, Input::AbsAddr(addrs))
            .map_err(|e| {
                tracing::trace!("Failed to symbolize {:?}", e);
                "failed to run symbolize"
            })?
            .into_iter()
            .map(SymbolFormatter::map_user_sym_to_stack)
            .collect::<Vec<_>>();

        Ok(syms)
    }

    /// Converts stacks traces into StackFrameInfo structs
    pub fn get_exp_stacked_frames(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        group_by_cpu: bool,
        stacked_pointers: &aya::maps::HashMap<MapData, StackInfo, FramePointers>,
    ) -> Vec<StackFrameInfo> {
        let (kernel_stack, user_stack) = self.get_instruction_pointers(stack_info, stack_traces);

        // println!("User stack: {}", utrace_id);
        // println!("Addrs: {:?}", user_stack);
        // println!("IP (instruction pointer): {}", stack_info.ip);
        // println!("BP (base pointer aka Frame pointer): {}", stack_info.bp);

        let pointers = stacked_pointers.get(stack_info, 0).unwrap();

        let pid = stack_info.tgid;
        let src: Source<'_> = Source::Process(Process::new(Pid::from(pid)));
        let addrs = &pointers.pointers[..pointers.len as usize];

        println!("User stack: {:?}", user_stack);
        println!("addrs: {:?}", addrs);

        let syms = self.symbolizer.symbolize(&src, Input::AbsAddr(addrs));
        println!("What's IP {syms:?}");

        let stacks = self.format_stack_trace(stack_info, kernel_stack, user_stack, group_by_cpu);

        stacks
    }

    /// Converts stacks traces into StackFrameInfo structs
    pub fn get_stacked_frames(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        group_by_cpu: bool,
    ) -> Vec<StackFrameInfo> {
        let (kernel_stack, user_stack) = self.get_instruction_pointers(stack_info, stack_traces);
        let stacks = self.format_stack_trace(stack_info, kernel_stack, user_stack, group_by_cpu);
        stacks
    }

    // /// Converts stacks traces into StackFrameInfo structs
    // pub fn cached_stacked_frames(
    //     &mut self,
    //     stack_info: &StackInfo,
    //     stack_traces: &StackTraceMap<MapData>,
    //     group_by_cpu: bool,
    // ) -> Vec<StackFrameInfo> {
    //     let ktrace_id = stack_info.kernel_stack_id;
    //     let utrace_id = stack_info.user_stack_id;
    //     if let Some(stacks) = self.cache.get(ktrace_id, utrace_id) {
    //         return stacks;
    //     }

    //     let stacks = self.get_stacked_frames(stack_info, stack_traces, group_by_cpu);

    //     self.cache.insert(ktrace_id, utrace_id, stacks.clone());

    //     stacks
    // }

    /// Extract stacks from StackTraceMaps (kernel's implementation only support FP unwinding)
    pub fn get_instruction_pointers(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
    ) -> (Option<Vec<u64>>, Option<Vec<u64>>) {
        let ktrace_id = stack_info.kernel_stack_id;
        let utrace_id = stack_info.user_stack_id;

        let kernel_stack = if ktrace_id > -1 {
            stack_traces.get(&(ktrace_id as u32), 0).ok().map(|stack| {
                let addrs: Vec<Addr> = stack
                    .frames()
                    .iter()
                    .map(|frame| {
                        let instruction_pointer = frame.ip;
                        instruction_pointer
                    })
                    .collect();

                addrs
            })
        } else {
            None
        };

        let user_stack = if utrace_id > -1 {
            stack_traces.get(&(utrace_id as u32), 0).ok().map(|stack| {
                let addrs: Vec<Addr> = stack
                    .frames()
                    .iter()
                    .map(|frame| {
                        let instruction_pointer = frame.ip;
                        instruction_pointer
                    })
                    .collect();

                addrs
            })
        } else {
            None
        };

        (kernel_stack, user_stack)
    }

    /// converts pointers from bpf to usable, symbol resolved stack information
    /// Return is an array sorted from the bottom (root) to the top (inner most function)
    /// Looks up symbolization
    fn format_stack_trace(
        &self,
        stack_info: &StackInfo,
        kernel_stack: Option<Vec<u64>>,
        user_stack: Option<Vec<u64>>,
        // stacked_pointers: &StackFrameInfo
        group_by_cpu: bool,
    ) -> Vec<StackFrameInfo> {
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

        let pid = stack_info.tgid;

        let addrs = user_stack.unwrap_or_default();
        let user_syms = self
            .symbolize_user_stack(pid, &addrs)
            .ok()
            .unwrap_or_default();

        let kernel_addrs = kernel_stack.unwrap_or_default();
        let kernel_syms = self
            .symbolize_kernel_stack(&kernel_addrs)
            .ok()
            .unwrap_or_default();

        let mut combined = kernel_syms
            .into_iter()
            .chain(user_syms.into_iter())
            .collect::<Vec<_>>();

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
}
