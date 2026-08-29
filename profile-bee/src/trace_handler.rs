use crate::ebpf::{FramePointersPod, StackInfoPod};
use crate::v8::{V8HeapReader, V8IntrospectionData};
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
use profile_bee_common::{StackInfo, MAX_V8_FRAMES};
use std::collections::HashMap;
use std::path::Path;

/// V8 perf-map symbol prefixes and their meanings.
/// V8 emits symbols like `LazyCompile:*functionName /path/file.js:10:5`
/// where the prefix indicates the compilation tier and `*` means optimized,
/// `~` means interpreted (unoptimized).
const V8_PREFIXES: &[&str] = &[
    "LazyCompile:",
    "Script:",
    "Eval:",
    "Function:",
    "Builtin:",
    "Stub:",
    "BytecodeHandler:",
    "Handler:",
    "RegExp:",
];

/// Format a V8 perf-map symbol into a clean display name.
///
/// Input:  `LazyCompile:*processData /home/user/app/server.js:42:5`
/// Output: `processData (server.js:42)` for optimized or
///         `~processData (server.js:42)` for interpreted
///
/// For builtins/stubs without source: `Builtin:ArgumentsAdaptorTrampoline`
/// Output: `[v8] ArgumentsAdaptorTrampoline`
fn format_v8_symbol(raw: &str) -> Option<String> {
    // Find which prefix matches
    let (prefix, rest) = V8_PREFIXES
        .iter()
        .find_map(|p| raw.strip_prefix(p).map(|rest| (*p, rest)))?;

    let is_builtin = matches!(
        prefix,
        "Builtin:" | "Stub:" | "BytecodeHandler:" | "Handler:"
    );

    // Parse optimization marker: * = optimized, ~ = interpreted
    let (opt_marker, name_and_source) = if rest.starts_with('*') || rest.starts_with('~') {
        (&rest[..1], &rest[1..])
    } else {
        ("", rest)
    };

    // Split name from source location (separated by space, source starts with /)
    // e.g. "processData /home/user/app/server.js:42:5"
    let (func_name, source_loc) = if let Some(space_idx) = name_and_source.rfind(" /") {
        (
            &name_and_source[..space_idx],
            Some(&name_and_source[space_idx + 1..]),
        )
    } else if let Some(space_idx) = name_and_source.find(' ') {
        // Source might not start with / (e.g. relative paths or URLs)
        (
            &name_and_source[..space_idx],
            Some(&name_and_source[space_idx + 1..]),
        )
    } else {
        (name_and_source, None)
    };

    if func_name.is_empty() && source_loc.is_none() {
        return None;
    }

    // For builtins/stubs, use a simpler format
    if is_builtin {
        return Some(format!("[v8] {}", func_name));
    }

    // Build clean display name
    let display_name = if opt_marker == "~" {
        format!("~{}", func_name)
    } else {
        func_name.to_string()
    };

    // Format source location: extract basename and line number
    // "/home/user/app/server.js:42:5" -> "server.js:42"
    if let Some(src) = source_loc {
        let short_source = format_short_source(src);
        Some(format!("{} ({})", display_name, short_source))
    } else {
        Some(display_name)
    }
}

/// Shorten a V8 source location for display.
/// Input:  `/home/user/app/server.js:42:5`
/// Output: `server.js:42`
///
/// Splits from the right so that paths containing colons are handled
/// correctly (e.g. `node:internal/modules/cjs/loader.js:42:5`).
fn format_short_source(source: &str) -> String {
    // Split from the right: at most 3 parts → [path, line, column]
    // e.g. "node:internal/modules/cjs/loader.js:42:5"
    //    → ["node:internal/modules/cjs/loader.js", "42", "5"]
    let parts: Vec<&str> = source.rsplitn(3, ':').collect();
    // rsplitn yields parts in reverse order: [column, line, path]
    let (file_path, line) = match parts.len() {
        3 => (parts[2], Some(parts[1])),
        2 => {
            // Could be "path:line" or "path:something" — check if the
            // last segment looks like a line number
            if parts[0].bytes().all(|b| b.is_ascii_digit()) {
                (parts[1], Some(parts[0]))
            } else {
                // Not a line number, treat entire string as path
                (source, None)
            }
        }
        _ => (source, None),
    };

    let basename = Path::new(file_path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(file_path);

    if let Some(line) = line {
        format!("{}:{}", basename, line)
    } else {
        basename.to_string()
    }
}

/// Check if a symbol name looks like a V8 perf-map entry.
fn is_v8_symbol(name: &str) -> bool {
    V8_PREFIXES.iter().any(|p| name.starts_with(p))
}

pub struct SymbolFormatter;

impl SymbolFormatter {
    /// Simple symbol kernel name only
    fn map_kernel_sym_to_stack(sym: Symbolized) -> StackFrameInfo {
        let sym = match sym {
            Symbolized::Sym(sym) => sym,
            Symbolized::Unknown(_reason) => {
                return StackFrameInfo {
                    symbol: Some("[unknown]".to_string()), // {reason}
                    ..Default::default()
                };
            }
        };

        StackFrameInfo {
            symbol: Some(format!("{}_k", sym.name)),
            ..Default::default()
        }
    }

    fn kernel_symbol_name(frame: &StackFrameInfo) -> Option<&str> {
        frame
            .symbol
            .as_deref()
            .and_then(|sym| sym.strip_suffix("_k"))
    }

    fn classify_softirq_symbol(symbol: &str) -> Option<&'static str> {
        match symbol {
            "net_rx_action" => Some("softirq:net_rx_k"),
            "net_tx_action" => Some("softirq:net_tx_k"),
            "run_timer_softirq" => Some("softirq:timer_k"),
            "hrtimer_run_softirq" => Some("softirq:hrtimer_k"),
            "tasklet_action" => Some("softirq:tasklet_k"),
            "tasklet_hi_action" => Some("softirq:tasklet_hi_k"),
            "blk_done_softirq" => Some("softirq:block_k"),
            "blk_iopoll_softirq" | "irq_poll_softirq" => Some("softirq:block_iopoll_k"),
            "rcu_core_si" | "rcu_process_callbacks" => Some("softirq:rcu_k"),
            "run_rebalance_domains" => Some("softirq:sched_k"),
            _ => None,
        }
    }

    fn is_generic_softirq_symbol(symbol: &str) -> bool {
        matches!(
            symbol,
            "__softirqentry_text_start"
                | "__do_softirq"
                | "handle_softirqs"
                | "do_softirq"
                | "run_ksoftirqd"
                // aarch64: do_softirq_own_stack hands ____do_softirq to
                // call_on_irq_stack as a signature-matching trampoline.
                | "____do_softirq"
        )
    }

    fn classify_interrupt_symbol(symbol: &str) -> Option<&'static str> {
        match symbol {
            "sysvec_apic_timer_interrupt"
            | "asm_sysvec_apic_timer_interrupt"
            | "local_apic_timer_interrupt" => Some("interrupt:timer_k"),
            "sysvec_reschedule_ipi" | "asm_sysvec_reschedule_ipi" => {
                Some("interrupt:reschedule_ipi_k")
            }
            "sysvec_call_function_single" | "sysvec_call_function_single_interrupt" => {
                Some("interrupt:call_function_single_k")
            }
            "sysvec_call_function" | "sysvec_call_function_interrupt" => {
                Some("interrupt:call_function_k")
            }
            "sysvec_irq_work" => Some("interrupt:irq_work_k"),
            "sysvec_thermal" => Some("interrupt:thermal_k"),
            "sysvec_error_interrupt" => Some("interrupt:error_k"),
            "sysvec_spurious_apic_interrupt" => Some("interrupt:spurious_k"),
            // aarch64 has no per-vector entry symbols the way x86 does — the EL1
            // IRQ vector dispatches every interrupt through one path, so these
            // can only yield the generic label.
            "el1h_64_irq"
            | "el1h_64_irq_handler"
            | "el1_interrupt"
            | "__el1_irq"
            | "el0t_64_irq"
            | "el0t_64_irq_handler"
            | "el0_interrupt"
            | "do_interrupt_handler"
            | "gic_handle_irq"
            | "common_interrupt"
            | "__common_interrupt"
            | "asm_common_interrupt"
            | "handle_irq_event"
            | "handle_irq_event_percpu"
            | "__handle_irq_event_percpu"
            | "handle_edge_irq"
            | "handle_level_irq"
            | "handle_domain_irq"
            | "__handle_domain_irq"
            | "do_IRQ" => Some("interrupt_k"),
            _ => None,
        }
    }

    /// Interrupt *entry* trampolines — the frames the CPU passes through on its
    /// way into an interrupt handler, before any handler work runs.
    ///
    /// These carry no work of their own, which is what makes them useful for
    /// recognising a sample that landed on interrupt entry itself. See
    /// [`Self::is_sampling_induced_interrupt`].
    fn is_interrupt_entry_symbol(symbol: &str) -> bool {
        matches!(
            symbol,
            // x86_64
            "asm_sysvec_apic_timer_interrupt"
                | "sysvec_apic_timer_interrupt"
                | "local_apic_timer_interrupt"
                | "asm_common_interrupt"
                | "common_interrupt"
                | "__common_interrupt"
                | "asm_call_irq_on_stack"
                | "error_entry"
                | "error_return"
                // aarch64 EL1 (kernel-mode) IRQ vector and its dispatch layer
                | "el1h_64_irq"
                | "el1h_64_irq_handler"
                | "el1_interrupt"
                | "__el1_irq"
                | "call_on_irq_stack"
                // architecture-neutral hardirq enter/exit
                | "irq_enter_rcu"
                | "irq_exit_rcu"
                | "__irq_exit_rcu"
                | "irq_exit"
                | "do_softirq_own_stack"
        )
    }

    /// Whether an interrupt classification at `entry_idx` is an artifact of the
    /// profiler's own sampling rather than real interrupt work.
    ///
    /// `kernel_syms` is leaf-first, as returned by `bpf_get_stackid` — index 0 is
    /// the innermost frame and larger indices walk out toward the root. Anything
    /// the interrupt handler actually *did* therefore sits at indices strictly
    /// below `entry_idx`.
    ///
    /// profile-bee samples via a perf timer interrupt, so on a timer tick the
    /// interrupt entry trampoline appears in the captured stack unconditionally —
    /// it is how the sample was taken, not something the workload was doing. The
    /// kernel unwind begins at the interrupted context, so the sampler's own
    /// frames (`perf_swevent_hrtimer`, `__perf_event_overflow`, `bpf_get_stackid`)
    /// are never present to key off; the entry trampoline is the only trace it
    /// leaves.
    ///
    /// The distinction that matters is whether the interrupt went on to do work.
    /// When every frame deeper than the entry point is itself an entry trampoline,
    /// the sample landed on bare interrupt entry and attributing it to
    /// `interrupt:timer_k` would invent CPU time that the workload never spent.
    /// When real frames sit beneath it, the interrupt did genuine work and the
    /// label is earned.
    ///
    /// The frame at `entry_idx` must itself be an interrupt entry symbol — this
    /// prevents dispatch functions (e.g. `gic_handle_irq`) that classify as
    /// `interrupt_k` but are not entry trampolines from being suppressed when
    /// they appear as the leaf frame (where the prefix `[..0]` is empty).
    fn is_sampling_induced_interrupt(kernel_syms: &[StackFrameInfo], entry_idx: usize) -> bool {
        // The classified frame itself must be an entry trampoline.
        let dominated = Self::kernel_symbol_name(&kernel_syms[entry_idx])
            .is_some_and(Self::is_interrupt_entry_symbol);
        if !dominated {
            return false;
        }

        kernel_syms[..entry_idx].iter().all(|frame| {
            Self::kernel_symbol_name(frame).is_none_or(Self::is_interrupt_entry_symbol)
        })
    }

    fn infer_kernel_context_label(kernel_syms: &[StackFrameInfo]) -> Option<&'static str> {
        for frame in kernel_syms {
            if let Some(symbol) = Self::kernel_symbol_name(frame) {
                if let Some(label) = Self::classify_softirq_symbol(symbol) {
                    return Some(label);
                }
            }
        }

        for frame in kernel_syms {
            if let Some(symbol) = Self::kernel_symbol_name(frame) {
                if Self::is_generic_softirq_symbol(symbol) {
                    return Some("softirq_k");
                }
            }
        }

        // Softirq work is checked first (above) because softirqs run nested inside
        // interrupt exit, so a softirq stack also contains interrupt entry frames
        // and the softirq label is the more specific of the two.
        for (idx, frame) in kernel_syms.iter().enumerate() {
            if let Some(symbol) = Self::kernel_symbol_name(frame) {
                if let Some(label) = Self::classify_interrupt_symbol(symbol) {
                    if Self::is_sampling_induced_interrupt(kernel_syms, idx) {
                        // Bare sampling-timer entry with no handler work beneath.
                        return None;
                    }
                    return Some(label);
                }
            }
        }

        None
    }

    /// Symbol name with V8 perf-map formatting applied when detected.
    fn map_user_sym_to_stack(sym: Symbolized) -> StackFrameInfo {
        let sym = match sym {
            Symbolized::Sym(sym) => sym,
            Symbolized::Unknown(_reason) => {
                return StackFrameInfo {
                    symbol: Some("[unknown]".to_string()), // {reason}
                    ..Default::default()
                };
            }
        };

        let name = sym.name.to_string();
        let display_name = if is_v8_symbol(&name) {
            format_v8_symbol(&name).unwrap_or(name)
        } else {
            name
        };

        StackFrameInfo {
            symbol: Some(display_name),
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
    /// V8 heap readers per PID, for resolving JavaScript function names
    /// from SFI pointers extracted by the eBPF V8 frame extractor.
    v8_readers: HashMap<u32, V8HeapReader>,
}

impl Default for TraceHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceHandler {
    fn stack_cache_key(
        tgid: u32,
        ktrace_id: i32,
        utrace_id: i32,
        cpu: u32,
    ) -> Option<(u32, i32, i32)> {
        if tgid == 0 {
            // Idle-task output depends on the kernel stack *and* the CPU: every
            // formatted idle stack carries CPU-specific frames (`cpu_NN`,
            // `swapper/N`). All CPUs idle through the same code path, so they
            // share one kernel stack hash — keying on the hash alone would let
            // one CPU's frames be served for every other CPU's idle samples.
            //
            // User stack IDs are negative error codes here (swapper has no user
            // stack), so the third slot is free to carry the CPU instead.
            (ktrace_id >= 0).then_some((tgid, ktrace_id, cpu as i32))
        } else if ktrace_id >= 0 && utrace_id >= 0 {
            Some((tgid, ktrace_id, utrace_id))
        } else {
            None
        }
    }

    fn populate_frame_addresses(frames: &mut [StackFrameInfo], addrs: &[u64]) {
        for (frame, &addr) in frames.iter_mut().zip(addrs.iter()) {
            frame.address = addr;
        }
    }

    fn format_idle_context_stack(
        stack_info: &StackInfo,
        mut kernel_syms: Vec<StackFrameInfo>,
        kernel_addrs: &[u64],
        context_label: &str,
        group_by_cpu: bool,
    ) -> Vec<StackFrameInfo> {
        Self::populate_frame_addresses(&mut kernel_syms, kernel_addrs);

        let mut combined = kernel_syms;
        combined.push(StackFrameInfo {
            symbol: Some(context_label.to_string()),
            ..Default::default()
        });

        // Label as swapper/idle process context
        let mut proc_frame = StackFrameInfo::process_only(stack_info);
        if let Some(cpu_id) = stack_info.get_cpu_id() {
            proc_frame.symbol = Some(format!("swapper/{}", cpu_id));
        }
        combined.push(proc_frame);

        if group_by_cpu {
            if let Some(cpu_id) = stack_info.get_cpu_id() {
                combined.push(StackFrameInfo {
                    symbol: Some(format!("cpu_{:02}", cpu_id)),
                    ..Default::default()
                });
            }
        }

        combined.reverse();
        combined
    }

    pub fn new() -> Self {
        TraceHandler {
            symbolizer: Symbolizer::new(),
            cache: Default::default(),
            v8_readers: HashMap::new(),
        }
    }

    /// Pre-warm kernel symbol resolution by triggering the initial parse of
    /// `/proc/kallsyms`. This avoids a latency spike when the first kernel
    /// stack is symbolized. The parsed data is cached internally by blazesym's
    /// `FileCache` for all subsequent calls.
    pub fn prewarm_kernel_symbols(&self) {
        let start = std::time::Instant::now();
        let src = Source::Kernel(Kernel::default());
        match self.symbolizer.symbolize(&src, Input::AbsAddr(&[])) {
            Ok(_) => {
                tracing::debug!("Pre-warmed kernel symbol resolver in {:?}", start.elapsed());
            }
            Err(e) => {
                tracing::warn!("Failed to pre-warm kernel symbols: {:?}", e);
            }
        }
    }

    /// Invalidate all cached symbol resolutions for a specific process.
    ///
    /// Called when a process calls execve() — the binary image changed so
    /// all cached address-to-symbol mappings for that PID are stale.
    pub fn invalidate_caches_for_pid(&mut self, tgid: u32) {
        self.cache.invalidate_pid(tgid);
        self.v8_readers.remove(&tgid);
        tracing::debug!("invalidated symbol caches for pid {}", tgid);
    }

    /// Invalidate address symbols after a runtime rewrites its JIT perf map.
    pub fn invalidate_symbol_cache_for_pid(&mut self, tgid: u32) {
        self.cache.invalidate_pid(tgid);
        tracing::debug!("invalidated symbol cache for pid {}", tgid);
    }

    /// Register a V8 heap reader for a Node.js process.
    /// The reader uses the V8 introspection data to resolve SFI pointers
    /// from the eBPF V8 frame extractor to JavaScript function names.
    pub fn register_v8_reader(&mut self, tgid: u32, data: V8IntrospectionData) {
        tracing::info!(
            "registered V8 heap reader for pid {} (V8 {}.{}.{})",
            tgid,
            data.version.0,
            data.version.1,
            data.version.2,
        );
        self.v8_readers.insert(tgid, V8HeapReader::new(tgid, data));
    }

    pub fn print_stats(&self) {
        tracing::info!("{}", self.cache.stats());
    }

    /// Return a summary of profiling statistics as a string.
    pub fn stats_summary(&self) -> String {
        self.cache.stats()
    }

    /// converts kernel stacked frames into symbols
    fn symbolize_kernel_stack(&self, addrs: &[Addr]) -> Result<Vec<StackFrameInfo>, &str> {
        let src = Source::Kernel(Kernel::default());
        let syms = self
            .symbolizer
            .symbolize(&src, Input::AbsAddr(addrs))
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

    /// Converts stacks traces into StackFrameInfo structs.
    /// Prefers custom-unwound frames from the stacked_pointers eBPF map
    /// (populated by either FP walking or DWARF unwinding) when they
    /// contain more frames than bpf_get_stackid.
    /// Results are cached by a derived stack key to avoid redundant BPF map
    /// lookups and blazesym symbolization on repeated stacks.
    ///
    /// For normal user processes, caching is only safe when both stack IDs are
    /// non-negative, meaning `bpf_get_stackid` succeeded and the IDs are actual
    /// hashes of the stack frames. When negative (FP walking failed), the ID is
    /// an error code and many distinct stacks share the same value.
    ///
    /// For the idle task (`tgid == 0`), the user stack ID is always a negative
    /// error code (swapper has no user stack), so that slot is replaced by the
    /// sample's CPU. The CPU must be part of the key: idle output carries
    /// CPU-specific frames (`cpu_NN`, `swapper/N`) while all CPUs idle through
    /// the same kernel path and therefore share one kernel stack hash.
    pub fn get_exp_stacked_frames(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        group_by_cpu: bool,
        group_by_process: bool,
        stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    ) -> Vec<StackFrameInfo> {
        let tgid = stack_info.tgid;
        let ktrace_id = stack_info.kernel_stack_id;
        let utrace_id = stack_info.user_stack_id;

        let cache_key = Self::stack_cache_key(tgid, ktrace_id, utrace_id, stack_info.cpu);

        if let Some((cache_tgid, cache_ktrace_id, cache_utrace_id)) = cache_key {
            if let Some(cached) = self.cache.get(cache_tgid, cache_ktrace_id, cache_utrace_id) {
                return cached.clone();
            }
        }

        let (kernel_stack, fp_user_stack) = self.get_instruction_pointers(stack_info, stack_traces);

        let key = StackInfoPod(*stack_info);

        // Try to use custom-unwound frame pointers from eBPF (FP or DWARF path)
        let (user_stack, v8_sfi) = if let Ok(pointers) = stacked_pointers.get(&key, 0) {
            let pointers = pointers.0;
            let len = pointers.len.min(pointers.pointers.len());
            let fp_len = fp_user_stack.as_ref().map_or(0, |v| v.len());
            if len > fp_len {
                let addrs: Vec<u64> = pointers.pointers[..len].to_vec();
                // Extract V8 SFI pointers (parallel to user addresses)
                let sfi_len = len.min(MAX_V8_FRAMES);
                let v8_sfi: Vec<u64> = pointers.v8_sfi[..sfi_len].to_vec();
                tracing::debug!(
                    "Using custom-unwound stack ({} frames, vs {} from stackid) for pid {}",
                    addrs.len(),
                    fp_len,
                    stack_info.tgid,
                );
                (Some(addrs), v8_sfi)
            } else {
                (fp_user_stack, Vec::new())
            }
        } else {
            (fp_user_stack, Vec::new())
        };

        let result = self.format_stack_trace(
            stack_info,
            kernel_stack,
            user_stack,
            &v8_sfi,
            group_by_cpu,
            group_by_process,
        );

        if let Some((cache_tgid, cache_ktrace_id, cache_utrace_id)) = cache_key {
            self.cache
                .insert(cache_tgid, cache_ktrace_id, cache_utrace_id, result.clone());
        }

        result
    }

    /// Extract raw instruction pointer addresses without symbolization.
    ///
    /// Returns `(kernel_addrs, user_addrs)` — the same raw `u64` addresses that
    /// [`get_exp_stacked_frames`] would pass to blazesym, but without the
    /// symbolization step. Used by the raw/offline output mode to capture
    /// addresses for post-hoc symbolization.
    ///
    /// Follows the same logic as `get_exp_stacked_frames` for selecting the
    /// best user stack (stacked_pointers vs bpf_get_stackid).
    ///
    /// **Note:** Unlike `get_exp_stacked_frames`, this does NOT read
    /// `pointers.v8_sfi` — the produced `.raw` files will not carry V8
    /// JavaScript frame names. V8 JS frames will appear as `[unknown]` or
    /// hex addresses in the re-symbolized output. Use the live symbolized
    /// pipeline (e.g. `-o output.svg`) for full V8 JS symbol resolution.
    pub fn get_raw_addresses(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        stacked_pointers: &aya::maps::HashMap<MapData, StackInfoPod, FramePointersPod>,
    ) -> (Vec<u64>, Vec<u64>) {
        let (kernel_stack, fp_user_stack) = self.get_instruction_pointers(stack_info, stack_traces);

        let key = StackInfoPod(*stack_info);

        // Same stacked_pointers preference logic as get_exp_stacked_frames
        let user_stack = if let Ok(pointers) = stacked_pointers.get(&key, 0) {
            let pointers = pointers.0;
            let len = pointers.len.min(pointers.pointers.len());
            let fp_len = fp_user_stack.as_ref().map_or(0, |v| v.len());
            if len > fp_len {
                pointers.pointers[..len].to_vec()
            } else {
                fp_user_stack.unwrap_or_default()
            }
        } else {
            fp_user_stack.unwrap_or_default()
        };

        (kernel_stack.unwrap_or_default(), user_stack)
    }

    /// Converts stacks traces into StackFrameInfo structs
    pub fn get_stacked_frames(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        group_by_cpu: bool,
        group_by_process: bool,
    ) -> Vec<StackFrameInfo> {
        let (kernel_stack, user_stack) = self.get_instruction_pointers(stack_info, stack_traces);
        self.format_stack_trace(
            stack_info,
            kernel_stack,
            user_stack,
            &[], // no V8 metadata in this path
            group_by_cpu,
            group_by_process,
        )
    }

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
                stack
                    .frames()
                    .iter()
                    .map(|frame| frame.ip)
                    .collect::<Vec<Addr>>()
            })
        } else {
            None
        };

        let user_stack = if utrace_id > -1 {
            stack_traces.get(&(utrace_id as u32), 0).ok().map(|stack| {
                let addrs: Vec<Addr> = stack.frames().iter().map(|frame| frame.ip).collect();
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
        &mut self,
        stack_info: &StackInfo,
        kernel_stack: Option<Vec<u64>>,
        user_stack: Option<Vec<u64>>,
        v8_sfi: &[u64],
        group_by_cpu: bool,
        group_by_process: bool,
    ) -> Vec<StackFrameInfo> {
        if stack_info.tgid == 0 {
            // The idle task (swapper) has tgid==0. However, softirqs and interrupts
            // can fire while the CPU is idle and execute real work (e.g., network RX,
            // timers) before returning to idle. We must check the kernel stack to
            // distinguish true idle from softirq/interrupt work on an idle CPU.
            let kernel_addrs = kernel_stack.unwrap_or_default();
            let kernel_syms = self
                .symbolize_kernel_stack(&kernel_addrs)
                .ok()
                .unwrap_or_default();

            let context_label = SymbolFormatter::infer_kernel_context_label(&kernel_syms);

            if let Some(label) = context_label {
                // This is softirq/interrupt work on an idle CPU — show the real stack.
                return Self::format_idle_context_stack(
                    stack_info,
                    kernel_syms,
                    &kernel_addrs,
                    label,
                    group_by_cpu,
                );
            }

            // True idle — no softirq/interrupt detected in kernel stack.
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
        let mut user_syms = self
            .symbolize_user_stack(pid, &addrs)
            .ok()
            .unwrap_or_default();

        // Populate raw instruction pointer addresses on each symbolized frame.
        // These are used by the OTLP exporter to send real addresses to devfiler.
        debug_assert!(
            user_syms.len() <= addrs.len(),
            "symbolize_user_stack returned more frames ({}) than input addresses ({})",
            user_syms.len(),
            addrs.len()
        );
        for (frame, &addr) in user_syms.iter_mut().zip(addrs.iter()) {
            frame.address = addr;
        }

        // Override symbols for V8 frames using the heap reader.
        // The v8_sfi array is parallel to the user addresses — if v8_sfi[i] != 0,
        // frame i is a V8 JavaScript frame and we can resolve the SFI pointer
        // to a function name + source file via process_vm_readv.
        if let Some(reader) = self.v8_readers.get_mut(&pid) {
            for (i, sfi) in v8_sfi.iter().enumerate() {
                if *sfi == 0 {
                    continue;
                }
                // The v8_sfi array is indexed by frame position in the stacked_pointers.
                // user_syms is in the same order as addrs (which matches pointers[]).
                if i < user_syms.len() {
                    if let Some(v8sym) = reader.resolve_sfi(*sfi) {
                        let display = if let Some(ref src) = v8sym.source_file {
                            let basename = Path::new(src)
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or(src);
                            format!("{} ({})", v8sym.function_name, basename)
                        } else {
                            v8sym.function_name.clone()
                        };
                        user_syms[i].symbol = Some(display);
                    }
                }
            }
        }

        let kernel_addrs = kernel_stack.unwrap_or_default();
        let mut kernel_syms = self
            .symbolize_kernel_stack(&kernel_addrs)
            .ok()
            .unwrap_or_default();

        // Populate raw kernel addresses on each symbolized frame.
        Self::populate_frame_addresses(&mut kernel_syms, &kernel_addrs);

        // Infer context label from kernel frames only (before combining) to avoid
        // false-positives from userspace symbols that happen to end in `_k`.
        let context_label = SymbolFormatter::infer_kernel_context_label(&kernel_syms);

        let mut combined = kernel_syms.into_iter().chain(user_syms).collect::<Vec<_>>();
        if let Some(label) = context_label {
            combined.push(StackFrameInfo {
                symbol: Some(label.to_string()),
                ..Default::default()
            });
        }

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

        if group_by_process {
            let cmd = stack_info.get_cmd();
            let frame = StackFrameInfo {
                symbol: Some(format!("{} ({})", cmd, stack_info.tgid)),
                ..Default::default()
            };
            combined.push(frame);
        }

        combined.reverse();

        combined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v8_optimized_with_source() {
        let result = format_v8_symbol("LazyCompile:*processData /home/user/app/server.js:42:5");
        assert_eq!(result, Some("processData (server.js:42)".to_string()));
    }

    #[test]
    fn test_v8_interpreted_with_source() {
        let result = format_v8_symbol("LazyCompile:~handleRequest /home/user/app/handler.js:10:3");
        assert_eq!(result, Some("~handleRequest (handler.js:10)".to_string()));
    }

    #[test]
    fn test_v8_script() {
        let result = format_v8_symbol("Script: /home/user/app/main.js:1:1");
        assert_eq!(result, Some(" (main.js:1)".to_string()));
    }

    #[test]
    fn test_v8_builtin() {
        let result = format_v8_symbol("Builtin:ArgumentsAdaptorTrampoline");
        assert_eq!(result, Some("[v8] ArgumentsAdaptorTrampoline".to_string()));
    }

    #[test]
    fn test_v8_stub() {
        let result = format_v8_symbol("Stub:CEntry");
        assert_eq!(result, Some("[v8] CEntry".to_string()));
    }

    #[test]
    fn test_v8_regex() {
        let result = format_v8_symbol("RegExp:foo[a-z]+bar");
        assert_eq!(result, Some("foo[a-z]+bar".to_string()));
    }

    #[test]
    fn test_v8_no_source() {
        let result = format_v8_symbol("LazyCompile:*someFunction");
        assert_eq!(result, Some("someFunction".to_string()));
    }

    #[test]
    fn test_not_v8() {
        assert!(!is_v8_symbol("std::io::Read::read"));
        assert!(!is_v8_symbol("[unknown]"));
        assert!(!is_v8_symbol("main"));
    }

    #[test]
    fn test_is_v8_symbol() {
        assert!(is_v8_symbol("LazyCompile:*foo"));
        assert!(is_v8_symbol("Builtin:bar"));
        assert!(is_v8_symbol("Stub:CEntry"));
        assert!(is_v8_symbol("Script:baz"));
    }

    #[test]
    fn test_v8_eval() {
        let result = format_v8_symbol("Eval:*evalFunc eval:1:10");
        assert_eq!(result, Some("evalFunc (eval:1)".to_string()));
    }

    #[test]
    fn test_format_short_source() {
        assert_eq!(
            format_short_source("/home/user/app/server.js:42:5"),
            "server.js:42"
        );
        assert_eq!(format_short_source("/app/index.js"), "index.js");
        assert_eq!(format_short_source("server.js:10:1"), "server.js:10");
    }

    #[test]
    fn test_format_short_source_node_internal() {
        // V8 emits paths like "node:internal/modules/cjs/loader.js:42:5"
        // for built-in modules — the colon in "node:" must not be treated
        // as a line-number separator.
        assert_eq!(
            format_short_source("node:internal/modules/cjs/loader.js:42:5"),
            "loader.js:42"
        );
        assert_eq!(
            format_short_source("node:internal/main/run_main_module.js:1:1"),
            "run_main_module.js:1"
        );
    }

    #[test]
    fn test_format_short_source_no_line() {
        // Path with no line/column at all
        assert_eq!(format_short_source("/app/index.js"), "index.js");
    }

    #[test]
    fn test_format_short_source_path_only_with_colon() {
        // A path with colon but no numeric suffix — should not split
        assert_eq!(
            format_short_source("node:internal/modules/cjs/loader.js"),
            "loader.js"
        );
    }

    fn kernel_frame(symbol: &str) -> StackFrameInfo {
        StackFrameInfo {
            symbol: Some(symbol.to_string()),
            ..Default::default()
        }
    }

    fn stack_info(tgid: u32, ktrace_id: i32, utrace_id: i32, cpu: u32, cmd: &str) -> StackInfo {
        let mut cmd_buf = [0u8; 16];
        let bytes = cmd.as_bytes();
        let len = bytes.len().min(cmd_buf.len().saturating_sub(1));
        cmd_buf[..len].copy_from_slice(&bytes[..len]);

        StackInfo {
            tgid,
            user_stack_id: utrace_id,
            kernel_stack_id: ktrace_id,
            cmd: cmd_buf,
            cpu,
            bp: 0,
            ip: 0,
            sp: 0,
        }
    }

    #[test]
    fn test_stack_cache_key_allows_idle_kernel_only_caching() {
        assert_eq!(
            TraceHandler::stack_cache_key(0, 42, -libc::EFAULT, 3),
            Some((0, 42, 3))
        );
        assert_eq!(TraceHandler::stack_cache_key(0, -1, -libc::EFAULT, 3), None);
        assert_eq!(
            TraceHandler::stack_cache_key(1234, 42, -libc::EFAULT, 3),
            None
        );
        assert_eq!(
            TraceHandler::stack_cache_key(1234, 42, 7, 3),
            Some((1234, 42, 7))
        );
    }

    #[test]
    fn test_stack_cache_key_distinguishes_idle_cpus() {
        // All CPUs idle through the same kernel path, so they share one kernel
        // stack hash. Since idle output carries CPU-specific frames, samples
        // from different CPUs must not collide on the same cache key.
        let cpu0 = TraceHandler::stack_cache_key(0, 42, -libc::EFAULT, 0);
        let cpu1 = TraceHandler::stack_cache_key(0, 42, -libc::EFAULT, 1);
        assert_ne!(cpu0, cpu1);
        assert_eq!(cpu0, Some((0, 42, 0)));
        assert_eq!(cpu1, Some((0, 42, 1)));
    }

    #[test]
    fn test_idle_cross_cpu_samples_retain_own_cpu_frames() {
        // A cache keyed without the CPU would serve cpu_00's frames for cpu_01's
        // idle samples, since both share kernel stack id 42.
        let mut cache = PointerStackFramesCache::default();

        for cpu in 0..4u32 {
            let info = stack_info(0, 42, -libc::EFAULT, cpu, "swapper/0");
            let frames = TraceHandler::format_idle_context_stack(
                &info,
                vec![kernel_frame("net_rx_action_k")],
                &[0x1000],
                "softirq:net_rx_k",
                true,
            );
            let key = TraceHandler::stack_cache_key(0, 42, -libc::EFAULT, cpu)
                .expect("idle sample with a valid kernel stack id should be cacheable");
            cache.insert(key.0, key.1, key.2, frames);
        }

        for cpu in 0..4u32 {
            let key = TraceHandler::stack_cache_key(0, 42, -libc::EFAULT, cpu).unwrap();
            let cached = cache
                .get(key.0, key.1, key.2)
                .expect("each CPU should have its own cache entry");
            let symbols: Vec<&str> = cached
                .iter()
                .map(|f| f.symbol.as_deref().unwrap_or("[missing]"))
                .collect();
            assert_eq!(
                symbols,
                vec![
                    format!("cpu_{:02}", cpu).as_str(),
                    format!("swapper/{}", cpu).as_str(),
                    "softirq:net_rx_k",
                    "net_rx_action_k",
                ],
                "cpu {} served frames belonging to another CPU",
                cpu
            );
        }
    }

    #[test]
    fn test_format_idle_context_stack_preserves_kernel_addresses() {
        let stack_info = stack_info(0, 42, -libc::EFAULT, 3, "swapper/3");
        let kernel_syms = vec![kernel_frame("net_rx_action_k"), kernel_frame("napi_poll_k")];
        let frames = TraceHandler::format_idle_context_stack(
            &stack_info,
            kernel_syms,
            &[0x1000, 0x2000],
            "softirq:net_rx_k",
            true,
        );

        let symbols: Vec<&str> = frames
            .iter()
            .map(|f| f.symbol.as_deref().unwrap_or("[missing]"))
            .collect();
        assert_eq!(
            symbols,
            vec![
                "cpu_03",
                "swapper/3",
                "softirq:net_rx_k",
                "napi_poll_k",
                "net_rx_action_k",
            ]
        );
        assert_eq!(frames[3].address, 0x2000);
        assert_eq!(frames[4].address, 0x1000);
    }

    #[test]
    fn test_infer_kernel_context_label_prefers_softirq() {
        let frames = vec![
            kernel_frame("common_interrupt_k"),
            kernel_frame("__softirqentry_text_start_k"),
            kernel_frame("net_rx_action_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq:net_rx_k")
        );
    }

    #[test]
    fn test_infer_kernel_context_label_detects_interrupt() {
        // Leaf-first: scheduler_tick is called *by* the timer interrupt, so it is
        // the inner frame. (This test previously listed the two in the opposite
        // order, which no real capture produces.)
        let frames = vec![
            kernel_frame("scheduler_tick_k"),
            kernel_frame("asm_sysvec_apic_timer_interrupt_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("interrupt:timer_k")
        );
    }

    #[test]
    fn test_bare_sampling_timer_entry_is_not_labeled_interrupt() {
        // Leaf-first: the sample landed on interrupt entry itself, with nothing
        // beneath it but more entry trampolines. This is the profiler's own timer
        // tick, so labeling it interrupt:timer_k would invent CPU time.
        let frames = vec![
            kernel_frame("asm_sysvec_apic_timer_interrupt_k"),
            kernel_frame("default_idle_k"),
            kernel_frame("default_idle_call_k"),
            kernel_frame("cpuidle_idle_call_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(SymbolFormatter::infer_kernel_context_label(&frames), None);
    }

    #[test]
    fn test_sampling_entry_with_real_handler_work_is_still_labeled() {
        // Same timer entry, but real handler work sits beneath it (leaf-first), so
        // the interrupt genuinely consumed CPU and the label is earned.
        let frames = vec![
            kernel_frame("tick_sched_handle_k"),
            kernel_frame("update_process_times_k"),
            kernel_frame("sysvec_apic_timer_interrupt_k"),
            kernel_frame("default_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("interrupt:timer_k")
        );
    }

    #[test]
    fn test_device_interrupt_work_is_unaffected() {
        // A device IRQ doing real work must keep its label — the suppression is
        // scoped to bare entry, not to interrupts generally.
        let frames = vec![
            kernel_frame("ena_io_poll_k"),
            kernel_frame("handle_irq_event_k"),
            kernel_frame("common_interrupt_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("interrupt_k")
        );
    }

    #[test]
    fn test_softirq_under_sampling_timer_entry_still_wins() {
        // Real RCU softirq work nested inside timer-interrupt exit. Softirq is
        // checked first, so this keeps its specific label and never reaches the
        // sampling-induced check. This is the common shape on a live system.
        let frames = vec![
            kernel_frame("kmem_cache_free_k"),
            kernel_frame("rcu_do_batch_k"),
            kernel_frame("rcu_core_k"),
            kernel_frame("__do_softirq_k"),
            kernel_frame("asm_call_irq_on_stack_k"),
            kernel_frame("do_softirq_own_stack_k"),
            kernel_frame("irq_exit_rcu_k"),
            kernel_frame("sysvec_apic_timer_interrupt_k"),
            kernel_frame("default_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq_k")
        );
    }

    #[test]
    fn test_unresolved_frames_above_entry_do_not_earn_a_label() {
        // Unsymbolized frames ([unknown], no _k suffix) carry no evidence of work,
        // so they must not be mistaken for real handler activity.
        let frames = vec![
            StackFrameInfo {
                symbol: Some("[unknown]".to_string()),
                ..Default::default()
            },
            kernel_frame("asm_sysvec_apic_timer_interrupt_k"),
            kernel_frame("default_idle_k"),
        ];
        assert_eq!(SymbolFormatter::infer_kernel_context_label(&frames), None);
    }

    #[test]
    fn test_arm64_idle_net_rx_softirq_stack() {
        // Real aarch64 capture (leaf-first). Reaches the specific softirq label via
        // net_rx_action, which is architecture-neutral generic code.
        let frames = vec![
            kernel_frame("napi_alloc_skb_k"),
            kernel_frame("ena_alloc_skb_k"),
            kernel_frame("ena_rx_skb_k"),
            kernel_frame("ena_clean_rx_irq_k"),
            kernel_frame("ena_io_poll_k"),
            kernel_frame("__napi_poll_k"),
            kernel_frame("net_rx_action_k"),
            kernel_frame("handle_softirqs_k"),
            kernel_frame("__do_softirq_k"),
            kernel_frame("____do_softirq_k"),
            kernel_frame("call_on_irq_stack_k"),
            kernel_frame("do_softirq_own_stack_k"),
            kernel_frame("__irq_exit_rcu_k"),
            kernel_frame("irq_exit_rcu_k"),
            kernel_frame("el1_interrupt_k"),
            kernel_frame("el1h_64_irq_handler_k"),
            kernel_frame("el1h_64_irq_k"),
            kernel_frame("default_idle_call_k"),
            kernel_frame("cpuidle_idle_call_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq:net_rx_k")
        );
    }

    #[test]
    fn test_arm64_generic_softirq_via_arch_trampoline() {
        // ____do_softirq is arm64's stack-switching trampoline. Without it in the
        // generic-softirq list, this stack would fall through to no label at all.
        let frames = vec![
            kernel_frame("some_unlisted_handler_k"),
            kernel_frame("____do_softirq_k"),
            kernel_frame("do_softirq_own_stack_k"),
            kernel_frame("el1_interrupt_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq_k")
        );
    }

    #[test]
    fn test_arm64_device_irq_work_is_labeled() {
        // An aarch64 device IRQ doing real work, no softirq involved. Before the
        // arm64 symbols were added this matched nothing and fell through to "idle".
        let frames = vec![
            kernel_frame("ena_intr_msix_io_k"),
            kernel_frame("__handle_irq_event_percpu_k"),
            kernel_frame("handle_irq_event_k"),
            kernel_frame("gic_handle_irq_k"),
            kernel_frame("el1_interrupt_k"),
            kernel_frame("el1h_64_irq_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("interrupt_k")
        );
    }

    #[test]
    fn test_arm64_bare_irq_entry_is_not_labeled_interrupt() {
        // aarch64 counterpart of the sampling-timer guard: bare EL1 IRQ entry with
        // no handler work beneath it earns no label.
        let frames = vec![
            kernel_frame("el1_interrupt_k"),
            kernel_frame("el1h_64_irq_handler_k"),
            kernel_frame("el1h_64_irq_k"),
            kernel_frame("default_idle_call_k"),
            kernel_frame("cpuidle_idle_call_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(SymbolFormatter::infer_kernel_context_label(&frames), None);
    }

    #[test]
    fn test_leaf_dispatch_symbol_not_suppressed_by_empty_prefix() {
        // gic_handle_irq is a real dispatch function (classifies as interrupt_k)
        // but is NOT an interrupt entry trampoline. When it appears as the leaf
        // frame (idx=0), the empty prefix [..0] must NOT trigger the
        // sampling-induced suppression — the frame is doing real work.
        let frames = vec![
            kernel_frame("gic_handle_irq_k"),
            kernel_frame("el1_interrupt_k"),
            kernel_frame("el1h_64_irq_handler_k"),
            kernel_frame("el1h_64_irq_k"),
            kernel_frame("do_idle_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("interrupt_k")
        );
    }

    #[test]
    fn test_infer_kernel_context_label_none_for_regular_kernel_stack() {
        let frames = vec![
            kernel_frame("finish_task_switch_k"),
            kernel_frame("schedule_k"),
        ];
        assert_eq!(SymbolFormatter::infer_kernel_context_label(&frames), None);
    }

    #[test]
    fn test_infer_kernel_context_label_do_softirq_legacy() {
        // __do_softirq is the older kernel name (pre-5.19)
        let frames = vec![
            kernel_frame("__do_softirq_k"),
            kernel_frame("some_handler_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq_k")
        );
    }

    #[test]
    fn test_infer_kernel_context_label_sched_softirq() {
        let frames = vec![
            kernel_frame("handle_softirqs_k"),
            kernel_frame("run_rebalance_domains_k"),
        ];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&frames),
            Some("softirq:sched_k")
        );
    }

    #[test]
    fn test_infer_kernel_context_label_ignores_userspace_frames() {
        // A userspace function that happens to end in _k should NOT trigger
        // classification when only kernel frames are passed.
        let user_frames = vec![kernel_frame("net_rx_action_k")];
        // If this were mistakenly passed with user frames mixed in, it would
        // match. But since we now only pass kernel_syms, this test validates
        // the function works correctly on kernel-only input.
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&user_frames),
            Some("softirq:net_rx_k")
        );

        // Frames without _k suffix (actual userspace symbols) are ignored
        let user_only = vec![StackFrameInfo {
            symbol: Some("net_rx_action".to_string()),
            ..Default::default()
        }];
        assert_eq!(
            SymbolFormatter::infer_kernel_context_label(&user_only),
            None
        );
    }
}
