use crate::ebpf::{FramePointersPod, StackInfoPod};
use crate::jitdump::{self, JitSymbolTable};
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

/// Demangle a Zig symbol name by stripping compiler-generated suffixes.
///
/// Zig symbols are already fairly human-readable (e.g. `io.reader.Reader.readAll`)
/// but the compiler appends hash/type suffixes for internal disambiguation:
///
/// - `__anon_<hex>` — anonymous function/closure instantiation hash
/// - `__struct_<hex>` — struct instantiation hash
/// - `__<hex>` — trailing hex hash (generic instantiation, e.g. `func__a1b2c3d4`)
///
/// This function strips these suffixes when detected, returning `Some(cleaned)`
/// if the name was modified, or `None` if it doesn't look like a Zig symbol.
///
/// No existing `zig-demangle` crate exists in the Rust ecosystem. OTel eBPF
/// Profiler and Parca/LightSwitch have zero Zig-specific demangling code —
/// they rely on standard C++/Rust demanglers only.
fn demangle_zig(name: &str) -> Option<String> {
    // Zig symbols use dots as namespace separators (e.g. `std.mem.Allocator.alloc`).
    // C and C++ symbols don't contain dots (they use `::` or `_Z` mangling).
    // Rust mangled symbols start with `_ZN` or `_R`. If the name doesn't
    // contain a dot, it's unlikely to be a Zig symbol.
    if !name.contains('.') {
        return None;
    }

    // Also skip C++ mangled names that somehow contain dots
    if name.starts_with("_Z") || name.starts_with("_R") {
        return None;
    }

    let mut cleaned = name;

    // Strip __anon_<hex> suffix
    if let Some(pos) = cleaned.rfind("__anon_") {
        let suffix = &cleaned[pos + 7..]; // after "__anon_"
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            cleaned = &cleaned[..pos];
        }
    }

    // Strip __struct_<hex> suffix
    if let Some(pos) = cleaned.rfind("__struct_") {
        let suffix = &cleaned[pos + 9..]; // after "__struct_"
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            cleaned = &cleaned[..pos];
        }
    }

    // Strip trailing __<hex> hash (generic instantiation suffix).
    // Only match if the suffix after the last `__` is pure hex and
    // at least 4 chars (to avoid false positives on short names).
    if let Some(pos) = cleaned.rfind("__") {
        let suffix = &cleaned[pos + 2..];
        if suffix.len() >= 4 && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            cleaned = &cleaned[..pos];
        }
    }

    if cleaned != name {
        Some(cleaned.to_string())
    } else {
        None
    }
}

/// Strip GCC/LLVM clone suffixes from symbol names.
///
/// Compilers append suffixes like `.cold`, `.constprop.0`, `.isra.0`,
/// `.part.0`, `.clone.0`, and `.llvm.<hex>` to distinguish compiler-generated
/// variants of functions. These are noise in profiler output.
///
/// Matches the approach used by OTel eBPF Profiler's `strip_clone_suffixes`.
fn strip_clone_suffixes(name: &str) -> &str {
    let mut result = name;
    loop {
        let prev = result;
        for suffix in &[".cold", ".constprop", ".isra", ".part", ".clone"] {
            if let Some(pos) = result.rfind(suffix) {
                let after = &result[pos + suffix.len()..];
                // Accept ".suffix" or ".suffix.N" where N is digits
                if after.is_empty()
                    || after.starts_with('.')
                        && after[1..].bytes().all(|b| b.is_ascii_digit())
                {
                    result = &result[..pos];
                }
            }
        }
        // Strip .llvm.<hex> suffix
        if let Some(pos) = result.rfind(".llvm.") {
            let after = &result[pos + 6..];
            if !after.is_empty() && after.bytes().all(|b| b.is_ascii_hexdigit()) {
                result = &result[..pos];
            }
        }
        if result == prev {
            break;
        }
    }
    result
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

        let name = strip_clone_suffixes(&sym.name);
        StackFrameInfo {
            symbol: Some(format!("{}_k", name)),
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
        } else if let Some(demangled) = demangle_zig(&name) {
            demangled
        } else {
            strip_clone_suffixes(&name).to_string()
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
    /// JITDump symbol tables per PID, for resolving JIT-compiled function
    /// names from runtimes that write `/tmp/jit-<pid>.dump` (Bun/JSC,
    /// Java HotSpot, LuaJIT, etc.).
    jit_tables: HashMap<u32, JitSymbolTable>,
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
            v8_readers: HashMap::new(),
            jit_tables: HashMap::new(),
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
        self.jit_tables.remove(&tgid);
        tracing::debug!("invalidated symbol caches for pid {}", tgid);
    }

    /// Invalidate the symbol resolution cache for a PID without removing
    /// runtime-specific readers (V8, JITDump).
    ///
    /// Used when JIT symbols are reloaded — the cached stacks with `[unknown]`
    /// entries need to be re-resolved, but the JIT table itself should be kept.
    pub fn invalidate_symbol_cache_for_pid(&mut self, tgid: u32) {
        self.cache.invalidate_pid(tgid);
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

    /// Register a JITDump symbol table for a process.
    ///
    /// Used for resolving JIT-compiled function names from runtimes
    /// that write `/tmp/jit-<pid>.dump` (Bun/JSC, Java HotSpot, LuaJIT).
    pub fn register_jit_table(&mut self, tgid: u32, table: JitSymbolTable) {
        tracing::info!(
            "registered JITDump symbol table for pid {} ({} symbols)",
            tgid,
            table.len(),
        );
        self.jit_tables.insert(tgid, table);
    }

    /// Check if a JITDump symbol table is registered for a process.
    pub fn has_jit_table(&self, tgid: u32) -> bool {
        self.jit_tables.contains_key(&tgid)
    }

    /// Get a mutable reference to the JITDump symbol table for a process.
    ///
    /// Used by streaming modes (TUI/serve) to incrementally reload
    /// JITDump files for newly-compiled functions.
    pub fn jit_table_mut(&mut self, tgid: u32) -> Option<&mut JitSymbolTable> {
        self.jit_tables.get_mut(&tgid)
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

        // Override remaining [unknown] symbols using JITDump if available.
        // JITDump provides address-to-symbol mappings for JIT-compiled code
        // from runtimes like Bun (JSC), Java HotSpot, and LuaJIT.
        // This runs after V8 SFI resolution: V8 heap reader takes priority
        // for Node.js (richer data), JITDump is for non-V8 runtimes.
        if let Some(jit_table) = self.jit_tables.get(&pid) {
            for (i, sym) in user_syms.iter_mut().enumerate() {
                if sym.symbol.as_deref() == Some("[unknown]") {
                    if let Some(addr) = addrs.get(i) {
                        if let Some(jit_sym) = jit_table.resolve(*addr) {
                            sym.symbol = Some(jitdump::format_jit_symbol(jit_sym));
                        }
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
        for (frame, &addr) in kernel_syms.iter_mut().zip(kernel_addrs.iter()) {
            frame.address = addr;
        }

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

    // ── Zig demangling tests ──

    #[test]
    fn test_demangle_zig_anon_suffix() {
        assert_eq!(
            demangle_zig("io.reader.Reader.readAll__anon_abc123"),
            Some("io.reader.Reader.readAll".to_string())
        );
    }

    #[test]
    fn test_demangle_zig_struct_suffix() {
        assert_eq!(
            demangle_zig("hash_map.HashMap.put__struct_5678abcd"),
            Some("hash_map.HashMap.put".to_string())
        );
    }

    #[test]
    fn test_demangle_zig_hex_hash() {
        assert_eq!(
            demangle_zig("mem.Allocator.alloc__a1b2c3d4"),
            Some("mem.Allocator.alloc".to_string())
        );
    }

    #[test]
    fn test_demangle_zig_no_suffix() {
        // Already clean Zig symbol — should return None
        assert_eq!(demangle_zig("debug.dumpStackTrace"), None);
    }

    #[test]
    fn test_demangle_zig_not_zig() {
        // C symbol — no dots, should return None
        assert_eq!(demangle_zig("malloc"), None);
        // C++ mangled — should return None
        assert_eq!(demangle_zig("_ZN3std4main"), None);
        // Rust mangled — should return None
        assert_eq!(demangle_zig("_RNvC3std4main"), None);
    }

    #[test]
    fn test_demangle_zig_short_hex_not_stripped() {
        // Only 2 hex chars after __ — too short, don't strip
        assert_eq!(demangle_zig("std.io.read__ab"), None);
    }

    // ── Clone suffix stripping tests ──

    #[test]
    fn test_strip_clone_cold() {
        assert_eq!(strip_clone_suffixes("func.cold"), "func");
    }

    #[test]
    fn test_strip_clone_constprop() {
        assert_eq!(strip_clone_suffixes("func.constprop.0"), "func");
    }

    #[test]
    fn test_strip_clone_isra() {
        assert_eq!(strip_clone_suffixes("func.isra.0"), "func");
    }

    #[test]
    fn test_strip_clone_llvm() {
        assert_eq!(strip_clone_suffixes("func.llvm.12345678"), "func");
    }

    #[test]
    fn test_strip_clone_multiple() {
        assert_eq!(
            strip_clone_suffixes("func.constprop.0.isra.0"),
            "func"
        );
    }

    #[test]
    fn test_strip_clone_none() {
        assert_eq!(strip_clone_suffixes("normal_func"), "normal_func");
    }

    #[test]
    fn test_strip_clone_preserves_name() {
        // Don't strip if "cold" is part of the actual name
        assert_eq!(strip_clone_suffixes("get_cold_data"), "get_cold_data");
    }
}
