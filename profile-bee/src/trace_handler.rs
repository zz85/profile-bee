use crate::ebpf::{FramePointersPod, StackInfoPod};
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
use profile_bee_common::StackInfo;
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
}

impl Default for TraceHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceHandler {
    pub fn new() -> Self {
        TraceHandler {
            symbolizer: Symbolizer::new(),
            cache: Default::default(),
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
        tracing::debug!("invalidated symbol caches for pid {}", tgid);
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
    /// Results are cached by (tgid, kernel_stack_id, user_stack_id) to avoid
    /// redundant BPF map lookups and blazesym symbolization on repeated stacks.
    ///
    /// Caching is only safe when both stack IDs are non-negative, meaning
    /// `bpf_get_stackid` succeeded and the IDs are actual hashes of the stack
    /// frames. When negative (FP walking failed), the ID is an error code and
    /// many distinct stacks share the same value — caching would be incorrect.
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

        // Only cache when both stack IDs are valid hashes (non-negative).
        // Negative IDs are error codes from bpf_get_stackid — many different
        // stacks map to the same negative value, so caching would be incorrect.
        let cacheable = ktrace_id >= 0 && utrace_id >= 0;

        if cacheable {
            if let Some(cached) = self.cache.get(tgid, ktrace_id, utrace_id) {
                return cached.clone();
            }
        }

        let (kernel_stack, fp_user_stack) = self.get_instruction_pointers(stack_info, stack_traces);

        let key = StackInfoPod(*stack_info);

        // Try to use custom-unwound frame pointers from eBPF (FP or DWARF path)
        let user_stack = if let Ok(pointers) = stacked_pointers.get(&key, 0) {
            let pointers = pointers.0;
            let len = pointers.len.min(pointers.pointers.len());
            let fp_len = fp_user_stack.as_ref().map_or(0, |v| v.len());
            if len > fp_len {
                let addrs: Vec<u64> = pointers.pointers[..len].to_vec();
                tracing::debug!(
                    "Using custom-unwound stack ({} frames, vs {} from stackid) for pid {}",
                    addrs.len(),
                    fp_len,
                    stack_info.tgid,
                );
                Some(addrs)
            } else {
                fp_user_stack
            }
        } else {
            fp_user_stack
        };

        let result = self.format_stack_trace(
            stack_info,
            kernel_stack,
            user_stack,
            group_by_cpu,
            group_by_process,
        );

        if cacheable {
            self.cache
                .insert(tgid, ktrace_id, utrace_id, result.clone());
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
        &self,
        stack_info: &StackInfo,
        kernel_stack: Option<Vec<u64>>,
        user_stack: Option<Vec<u64>>,
        group_by_cpu: bool,
        group_by_process: bool,
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

        let mut combined = kernel_syms.into_iter().chain(user_syms).collect::<Vec<_>>();

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
}
