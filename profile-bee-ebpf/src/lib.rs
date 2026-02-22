#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{bpf_raw_tracepoint_args, pt_regs, BPF_F_USER_STACK},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_get_smp_processor_id,
        bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_task_pt_regs,
    },
    macros::map,
    maps::lpm_trie::{Key as LpmKey, LpmTrie},
    maps::{Array, ArrayOfMaps, HashMap, PerCpuArray, ProgramArray, RingBuf, StackTrace},
    programs::RawTracePointContext,
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{
    DwarfUnwindState, ExecMapping, ExecMappingKey, FramePointers, StackInfo, UnwindEntry,
    CFA_REG_DEREF_RSP, CFA_REG_PLT, CFA_REG_RBP, CFA_REG_RSP, EVENT_TRACE_ALWAYS,
    FRAMES_PER_TAIL_CALL, LEGACY_MAX_DWARF_STACK_DEPTH, MAX_BIN_SEARCH_DEPTH,
    MAX_DWARF_STACK_DEPTH, MAX_EXEC_MAPPING_ENTRIES, MAX_SHARD_ENTRIES, MAX_UNWIND_SHARDS,
    REG_RULE_OFFSET, REG_RULE_SAME_VALUE, SHARD_NONE,
};

pub const STACK_ENTRIES: u32 = 16392;
pub const STACK_SIZE: u32 = 2048;

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

#[no_mangle]
static NOTIFY_TYPE: u8 = EVENT_TRACE_ALWAYS;

/// Whether to use DWARF-based unwinding (1) or frame-pointer based (0)
#[no_mangle]
static DWARF_ENABLED: u8 = 0;

/// Whether off-CPU profiling is enabled (1) or disabled (0).
/// When enabled, the offcpu_profile kprobe traces context switches via
/// finish_task_switch() and accumulates blocked time (in microseconds)
/// instead of sample counts.
#[no_mangle]
static OFF_CPU_ENABLED: u8 = 0;

/// Minimum off-CPU block time in microseconds to record (default 1us).
/// Context switches shorter than this are filtered out to reduce noise.
#[no_mangle]
static MIN_BLOCK_US: u64 = 1;

/// Maximum off-CPU block time in microseconds to record (default u64::MAX).
/// Context switches longer than this are filtered out (e.g., idle threads).
#[no_mangle]
static MAX_BLOCK_US: u64 = 0xFFFFFFFFFFFFFFFF;

/// Target syscall number to filter for raw tracepoint mode.
/// -1 = match all syscalls (no filtering)
#[no_mangle]
static TARGET_SYSCALL_NR: i64 = -1;

/// Target PID to profile (0 = profile all processes)
/// Stored in an Array map so userspace can update it after process spawn.
#[map(name = "target_pid_map")]
static TARGET_PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

/// PID to monitor for exit (0 = don't monitor any process exit)
/// Stored in an Array map so userspace can update it dynamically.
#[map(name = "monitor_exit_pid_map")]
static MONITOR_EXIT_PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

#[inline]
unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);
    skip > 0
}

unsafe fn notify_type() -> u8 {
    core::ptr::read_volatile(&NOTIFY_TYPE)
}

#[inline]
unsafe fn dwarf_enabled() -> bool {
    let enabled = core::ptr::read_volatile(&DWARF_ENABLED);
    enabled > 0
}

#[inline]
unsafe fn target_syscall_nr() -> i64 {
    core::ptr::read_volatile(&TARGET_SYSCALL_NR)
}

#[inline]
unsafe fn min_block_us() -> u64 {
    core::ptr::read_volatile(&MIN_BLOCK_US)
}

#[inline]
unsafe fn max_block_us() -> u64 {
    core::ptr::read_volatile(&MAX_BLOCK_US)
}

#[inline]
unsafe fn target_pid() -> u32 {
    match TARGET_PID_MAP.get(0) {
        Some(&pid) => pid,
        None => 0,
    }
}

#[inline]
unsafe fn monitor_exit_pid() -> u32 {
    match MONITOR_EXIT_PID_MAP.get(0) {
        Some(&pid) => pid,
        None => 0,
    }
}

/* Setup maps */
#[map]
static mut STORAGE: PerCpuArray<FramePointers> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "counts")]
pub static COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_ENTRIES, 0);

#[map(name = "stacked_pointers")]
pub static STACK_ID_TO_TRACES: HashMap<StackInfo, FramePointers> =
    HashMap::with_max_entries(STACK_SIZE, 0);

#[map]
static RING_BUF_STACKS: RingBuf = RingBuf::with_byte_size(STACK_SIZE, 0);

#[map(name = "process_exit_events")]
static RING_BUF_PROCESS_EXIT: RingBuf = RingBuf::with_byte_size(4096, 0);

#[map(name = "stack_traces")]
pub static STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);
// DWARF unwind maps — single outer ArrayOfMaps containing per-binary inner Array maps.
// Each inner map holds UnwindEntry values, keyed by u32 index.
// The outer map is indexed by shard_id (0..MAX_UNWIND_SHARDS-1).
// Userspace creates inner maps of the exact size needed per binary, then inserts
// their FDs into this outer map. This eliminates the old 8-shard / 65K-entry caps.

#[map(name = "unwind_shards", inner = "UNWIND_SHARD_TEMPLATE")]
pub static UNWIND_SHARDS: ArrayOfMaps<Array<UnwindEntry>> =
    ArrayOfMaps::with_max_entries(MAX_UNWIND_SHARDS as u32, 0);

/// Inner map template for the UNWIND_SHARDS ArrayOfMaps.
/// This template defines the shape (key/value sizes, max_entries) that all inner
/// maps must match (required on kernel <5.14). Userspace creates inner Array maps
/// matching this template and inserts their FDs into UNWIND_SHARDS.
#[map]
static UNWIND_SHARD_TEMPLATE: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);

/// LPM trie for exec mapping lookups: maps (tgid, virtual_address) → ExecMapping.
/// Replaces the old proc_info HashMap + linear scan with O(log n) longest prefix match.
/// Userspace decomposes each memory mapping's address range into aligned power-of-2
/// blocks and inserts each as a separate LPM trie entry.
#[map(name = "exec_mappings")]
pub static EXEC_MAPPINGS: LpmTrie<ExecMappingKey, ExecMapping> =
    LpmTrie::with_max_entries(MAX_EXEC_MAPPING_ENTRIES, 0);

/// Per-CPU state for DWARF tail-call unwinding
#[map(name = "unwind_state")]
pub static UNWIND_STATE: PerCpuArray<DwarfUnwindState> = PerCpuArray::with_max_entries(1, 0);

/// Program array for tail-call chaining during DWARF unwinding
#[map(name = "prog_array")]
pub static PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

/// Counters for DWARF unwinding diagnostics.
/// Index 0: tail-call fallback count (times tail_call failed and legacy path was used)
/// Index 1: tail-call success implied (program loaded via tail-call path — not incremented here)
#[map(name = "dwarf_stats")]
pub static DWARF_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// --- Off-CPU profiling maps ---

/// Tracks when each thread (by kernel PID = thread ID) went off-CPU.
/// Key: thread PID (u32), Value: bpf_ktime_get_ns() timestamp (u64).
#[map(name = "off_cpu_start")]
pub static OFF_CPU_START: HashMap<u32, u64> = HashMap::with_max_entries(16384, 0);

/// Per-CPU tracking of which thread PID was last running on each CPU.
/// Used to identify the "prev" thread during context switches without
/// needing to read task_struct fields at unknown offsets.
/// Key: CPU index, Value: thread PID (u32).
/// Max entries = 1024 (sufficient for up to 1024 CPUs).
#[map(name = "last_pid_on_cpu")]
pub static LAST_PID_ON_CPU: Array<u32> = Array::with_max_entries(1024, 0);

/// Collect trace with custom FP/DWARF stack unwinding via pt_regs.
///
/// SAFETY: ctx.as_ptr() MUST point to a valid pt_regs struct. This is true for:
/// - PerfEventContext (bpf_perf_event_data, kernel rewrites field access to pt_regs)
/// - ProbeContext / RetProbeContext (context IS pt_regs)
///
/// NOT valid for TracePointContext or RawTracePointContext — use
/// collect_trace_stackid_only for those.
#[inline(always)]
pub unsafe fn collect_trace<C: EbpfContext>(ctx: C) {
    let pid = ctx.pid();

    if pid == 0 && skip_idle() {
        // skip profiling idle traces
        return;
    }

    let tgid = ctx.tgid(); // thread group id

    // Filter by target PID if specified
    let filter_pid = target_pid();
    if filter_pid != 0 && tgid != filter_pid {
        return;
    }

    let cpu = bpf_get_smp_processor_id();
    let user_stack_id = STACK_TRACES
        .get_stackid::<C>(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid::<C>(&ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    // Use CPU based storage so it doesn't occupy space on stack
    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };

    let pointer = &mut *pointer;

    let regs = ctx.as_ptr() as *const pt_regs;

    // Try tail-call-based DWARF unwinding for deep stacks (up to 165 frames).
    // If the tail call succeeds, execution transfers to dwarf_unwind_step and
    // this function never continues past this point.
    // If it fails (program not registered, wrong program type, etc.),
    // we fall through to the legacy inline DWARF path below.
    if dwarf_enabled() {
        dwarf_try_tail_call(&ctx, &*regs, tgid, user_stack_id, kernel_stack_id, cpu);
        // If we reach here, the tail call failed — track it for diagnostics
        if let Some(counter) = DWARF_STATS.get_ptr_mut(0) {
            *counter += 1;
        }
    }

    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack_regs(&*regs, &mut pointer.pointers, tgid);
        (ip, bp, len, (*regs).rsp)
    } else {
        copy_stack_regs(&*regs, &mut pointer.pointers)
    };
    pointer.len = len;

    let cmd = ctx.command().unwrap_or_default();
    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip: ip, // frame pointer
        bp: bp,
        sp: sp, // stack pointer
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();

    // only assume true for "always mode"
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    // kernel space summarization
    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        // update hashmap with count and and only push new stack_infos to queue for symbol resolution
        let _ = COUNTS.insert(&stack_info, &1, 0); // BPF_F_NO_PREALLOC

        notify = true;
    }

    if notify {
        // notify user space of new stack information
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

/// Collect trace for raw tracepoint attached to sys_enter.
///
/// Raw tracepoint args for sys_enter: args[0] = struct pt_regs *, args[1] = syscall id
#[inline(always)]
pub unsafe fn collect_trace_raw_syscall(ctx: RawTracePointContext) {
    let args = ctx.as_ptr() as *const bpf_raw_tracepoint_args;
    let args_ptr = (*args).args.as_ptr();

    // args[0] = struct pt_regs *
    let regs_ptr = args_ptr.read() as *const pt_regs;
    // args[1] = long syscall_id (for sys_enter this IS the syscall number)
    let syscall_nr = args_ptr.add(1).read() as i64;

    // Filter by target syscall number (-1 = match all)
    let target = target_syscall_nr();
    if target >= 0 && syscall_nr != target {
        return;
    }

    let Ok(regs) = bpf_probe_read_kernel(regs_ptr) else {
        return;
    };

    collect_trace_with_regs_and_ctx(ctx, &regs);
}

/// Collect trace for raw tracepoint attached to sys_exit.
///
/// Raw tracepoint args for sys_exit: args[0] = struct pt_regs *, args[1] = return value
/// The syscall number is NOT in args[1] (that's the return value), so we read
/// it from pt_regs.orig_rax which the kernel preserves across the syscall.
#[inline(always)]
pub unsafe fn collect_trace_raw_syscall_exit(ctx: RawTracePointContext) {
    let args = ctx.as_ptr() as *const bpf_raw_tracepoint_args;
    let args_ptr = (*args).args.as_ptr();

    // args[0] = struct pt_regs *
    let regs_ptr = args_ptr.read() as *const pt_regs;

    let Ok(regs) = bpf_probe_read_kernel(regs_ptr) else {
        return;
    };

    // For sys_exit, get the syscall number from pt_regs.orig_rax
    let syscall_nr = regs.orig_rax as i64;

    let target = target_syscall_nr();
    if target >= 0 && syscall_nr != target {
        return;
    }

    collect_trace_with_regs_and_ctx(ctx, &regs);
}

/// Shared body for raw syscall tracepoint collection.
/// Called after syscall NR filtering with the already-read pt_regs.
#[inline(always)]
unsafe fn collect_trace_with_regs_and_ctx(ctx: RawTracePointContext, regs: &pt_regs) {
    let pid = ctx.pid();

    if pid == 0 && skip_idle() {
        return;
    }

    let tgid = ctx.tgid();

    let filter_pid = target_pid();
    if filter_pid != 0 && tgid != filter_pid {
        return;
    }

    let cpu = bpf_get_smp_processor_id();
    let user_stack_id = STACK_TRACES
        .get_stackid::<RawTracePointContext>(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid::<RawTracePointContext>(&ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };

    let pointer = &mut *pointer;

    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack_regs(regs, &mut pointer.pointers, tgid);
        (ip, bp, len, regs.rsp)
    } else {
        copy_stack_regs(regs, &mut pointer.pointers)
    };
    pointer.len = len;

    let cmd = ctx.command().unwrap_or_default();
    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip,
        bp,
        sp,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        let _ = COUNTS.insert(&stack_info, &1, 0);
        notify = true;
    }

    if notify {
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

/// Collect trace using bpf_get_stackid() only — no custom FP/DWARF unwinding.
///
/// Used for contexts where ctx.as_ptr() does NOT point to pt_regs:
/// - TracePointContext (points to tracepoint-specific data struct)
/// - RawTracePointContext (points to bpf_raw_tracepoint_args)
///
/// bpf_get_stackid() still works because the kernel internally synthesizes
/// pt_regs from the current call stack. ip/bp/sp are set to 0.
#[inline(always)]
pub unsafe fn collect_trace_stackid_only<C: EbpfContext>(ctx: C) {
    let pid = ctx.pid();

    if pid == 0 && skip_idle() {
        return;
    }

    let tgid = ctx.tgid();

    let filter_pid = target_pid();
    if filter_pid != 0 && tgid != filter_pid {
        return;
    }

    let cpu = bpf_get_smp_processor_id();
    let user_stack_id = STACK_TRACES
        .get_stackid::<C>(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid::<C>(&ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };
    let pointer = &mut *pointer;
    pointer.len = 0;

    let cmd = ctx.command().unwrap_or_default();
    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip: 0,
        bp: 0,
        sp: 0,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        let _ = COUNTS.insert(&stack_info, &1, 0);
        notify = true;
    }

    if notify {
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

/// Collect trace for generic raw tracepoint programs using task pt_regs.
///
/// Uses bpf_get_current_task_btf() + bpf_task_pt_regs() to obtain the
/// interrupted userspace registers, enabling full frame-pointer/DWARF
/// unwinding even for non-syscall tracepoints (sched, block, net, tcp, etc.).
///
/// Requires kernel >= 5.15 for bpf_task_pt_regs(). Programs using this
/// function will fail to load on older kernels, falling back to
/// collect_trace_raw_tp_generic (bpf_get_stackid only).
#[inline(always)]
pub unsafe fn collect_trace_raw_tp_with_task_regs(ctx: RawTracePointContext) {
    let pid = ctx.pid();

    if pid == 0 && skip_idle() {
        return;
    }

    let tgid = ctx.tgid();

    let filter_pid = target_pid();
    if filter_pid != 0 && tgid != filter_pid {
        return;
    }

    // Get pt_regs from current task (kernel >= 5.15)
    let task = bpf_get_current_task_btf();
    let regs_ptr = bpf_task_pt_regs(task) as *const pt_regs;
    if regs_ptr.is_null() {
        return;
    }

    let cpu = bpf_get_smp_processor_id();
    let user_stack_id = STACK_TRACES
        .get_stackid::<RawTracePointContext>(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid::<RawTracePointContext>(&ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };
    let pointer = &mut *pointer;

    // bpf_task_pt_regs returns a kernel pointer — read with bpf_probe_read_kernel
    let Ok(regs) = bpf_probe_read_kernel(regs_ptr) else {
        // Fallback: no custom unwinding, just use stack IDs
        pointer.len = 0;
        let cmd = ctx.command().unwrap_or_default();
        let stack_info = StackInfo {
            tgid,
            user_stack_id,
            kernel_stack_id,
            cmd,
            cpu,
            ip: 0,
            bp: 0,
            sp: 0,
        };
        let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);
        let notify_code = notify_type();
        let mut notify = notify_code == EVENT_TRACE_ALWAYS;
        if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
            *count += 1;
        } else {
            let _ = COUNTS.insert(&stack_info, &1, 0);
            notify = true;
        }
        if notify {
            if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
                let _writable = entry.write(stack_info);
                entry.submit(0);
            }
        }
        return;
    };

    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack_regs(&regs, &mut pointer.pointers, tgid);
        (ip, bp, len, regs.rsp)
    } else {
        copy_stack_regs(&regs, &mut pointer.pointers)
    };
    pointer.len = len;

    let cmd = ctx.command().unwrap_or_default();
    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip,
        bp,
        sp,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        let _ = COUNTS.insert(&stack_info, &1, 0);
        notify = true;
    }

    if notify {
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

const __START_KERNEL_MAP: u64 = 0xffffffff80000000;

/// Perform one frame of DWARF unwinding, updating state in place.
/// Returns true if unwinding should continue, false if done.
/// Uses LPM trie lookup to find the exec mapping containing current_ip.
#[inline(always)]
unsafe fn dwarf_unwind_one_frame(state: &mut DwarfUnwindState) -> bool {
    let current_ip = state.current_ip;
    let sp = state.sp;
    let bp = state.bp;
    let frame_idx = state.frame_count;

    if frame_idx >= state.pointers.len() {
        return false;
    }
    if invalid_userspace_pointer(current_ip) {
        return false;
    }

    // LPM trie lookup: find the exec mapping containing (tgid, current_ip)
    let key = LpmKey::new(
        96,
        ExecMappingKey {
            tgid: state.tgid.to_be(),
            address: current_ip.to_be(),
        },
    );
    let (shard_id, table_count, load_bias) = match EXEC_MAPPINGS.get(&key) {
        Some(mapping) if current_ip >= mapping.begin && current_ip < mapping.end => {
            (mapping.shard_id, mapping.table_count, mapping.load_bias)
        }
        _ => {
            // No mapping found or LPM prefix extends beyond actual range — FP fallback
            if let Some((ra, nbp)) = try_fp_step(bp) {
                state.pointers[frame_idx] = ra;
                state.frame_count = frame_idx + 1;
                state.current_ip = ra;
                state.sp = bp + 16;
                state.bp = nbp;
                return true;
            }
            return false;
        }
    };

    if table_count == 0 || shard_id == SHARD_NONE {
        // No DWARF info — try FP-based step as fallback
        if let Some((ra, nbp)) = try_fp_step(bp) {
            state.pointers[frame_idx] = ra;
            state.frame_count = frame_idx + 1;
            state.current_ip = ra;
            state.sp = bp + 16;
            state.bp = nbp;
            return true;
        }
        return false;
    }

    // Convert virtual address to file-relative address for table lookup
    let relative_pc = (current_ip - load_bias) as u32;

    // Binary search for the unwind entry covering this PC
    let entry = match binary_search_unwind_entry(shard_id, table_count, relative_pc) {
        Some(e) => e,
        None => {
            // No unwind entry — try FP-based step as fallback
            if let Some((ra, nbp)) = try_fp_step(bp) {
                state.pointers[frame_idx] = ra;
                state.frame_count = frame_idx + 1;
                state.current_ip = ra;
                state.sp = bp + 16;
                state.bp = nbp;
                return true;
            }
            return false;
        }
    };

    // Compute CFA (Canonical Frame Address) based on rule type
    let is_signal = entry.cfa_type == CFA_REG_DEREF_RSP;

    let cfa = match entry.cfa_type {
        CFA_REG_RSP => sp.wrapping_add(entry.cfa_offset as i64 as u64),
        CFA_REG_RBP => bp.wrapping_add(entry.cfa_offset as i64 as u64),
        CFA_REG_PLT => {
            let base = sp.wrapping_add(entry.cfa_offset as i64 as u64);
            if (current_ip & 15) >= 11 {
                base.wrapping_add(8)
            } else {
                base
            }
        }
        // Signal frame: CFA = saved RSP = *(RSP + 160)
        CFA_REG_DEREF_RSP => match bpf_probe_read_user((sp + 160) as *const u64) {
            Ok(val) => val,
            Err(_) => return false,
        },
        _ => return false,
    };

    if cfa == 0 {
        return false;
    }

    // Return address: CFA-8 for normal frames, *(RSP+168) for signal frames
    let ra_addr = if is_signal {
        sp + 168
    } else {
        cfa.wrapping_sub(8)
    };
    let return_addr = match bpf_probe_read_user(ra_addr as *const u64) {
        Ok(val) => val,
        Err(_) => return false,
    };

    if return_addr == 0 {
        return false;
    }

    // Restore RBP: for signal frames read from *(RSP+120),
    // otherwise use normal CFA-relative offset rule
    let new_bp = if is_signal {
        match bpf_probe_read_user((sp + 120) as *const u64) {
            Ok(val) => val,
            Err(_) => bp,
        }
    } else {
        match entry.rbp_type {
            REG_RULE_OFFSET => {
                let bp_addr = (cfa as i64 + entry.rbp_offset as i64) as u64;
                match bpf_probe_read_user(bp_addr as *const u64) {
                    Ok(val) => val,
                    Err(_) => bp,
                }
            }
            REG_RULE_SAME_VALUE => bp,
            _ => bp,
        }
    };

    state.pointers[frame_idx] = return_addr;
    state.frame_count = frame_idx + 1;
    state.current_ip = return_addr;
    state.sp = cfa;
    state.bp = new_bp;

    true
}

/// DWARF-based stack unwinding using pre-loaded unwind tables (from pt_regs directly)
#[inline(always)]
unsafe fn dwarf_copy_stack_regs(
    regs: &pt_regs,
    pointers: &mut [u64],
    tgid: u32,
) -> (u64, u64, usize) {
    let ip = regs.rip;
    let mut sp = regs.rsp;
    let mut bp = regs.rbp;

    pointers[0] = ip;

    // Quick check: try LPM for initial IP. If no mapping found,
    // this process likely has no DWARF info — use full FP unwinding.
    let first_key = LpmKey::new(
        96,
        ExecMappingKey {
            tgid: tgid.to_be(),
            address: ip.to_be(),
        },
    );
    if EXEC_MAPPINGS.get(&first_key).is_none() {
        let (ip, bp, len, _sp) = copy_stack_regs(regs, pointers);
        return (ip, bp, len);
    }

    let mut current_ip = ip;
    let mut len = 1usize;

    let mut i = 1usize;
    for _ in 1..LEGACY_MAX_DWARF_STACK_DEPTH {
        if i >= pointers.len() {
            break;
        }
        if invalid_userspace_pointer(current_ip) {
            break;
        }

        // LPM trie lookup for this frame's IP
        let key = LpmKey::new(
            96,
            ExecMappingKey {
                tgid: tgid.to_be(),
                address: current_ip.to_be(),
            },
        );
        let (shard_id, table_count, load_bias) = match EXEC_MAPPINGS.get(&key) {
            Some(mapping) if current_ip >= mapping.begin && current_ip < mapping.end => {
                (mapping.shard_id, mapping.table_count, mapping.load_bias)
            }
            _ => {
                // No mapping — FP fallback for this frame
                if let Some((ra, nbp)) = try_fp_step(bp) {
                    pointers[i] = ra;
                    len = i + 1;
                    current_ip = ra;
                    sp = bp + 16;
                    bp = nbp;
                    i += 1;
                    continue;
                }
                break;
            }
        };

        if table_count == 0 || shard_id == SHARD_NONE {
            // No DWARF info — try FP-based step as fallback
            if let Some((ra, nbp)) = try_fp_step(bp) {
                pointers[i] = ra;
                len = i + 1;
                current_ip = ra;
                sp = bp + 16;
                bp = nbp;
                i += 1;
                continue;
            }
            break;
        }

        // Convert virtual address to file-relative address for table lookup
        let relative_pc = (current_ip - load_bias) as u32;

        // Binary search for the unwind entry covering this PC
        let entry = match binary_search_unwind_entry(shard_id, table_count, relative_pc) {
            Some(e) => e,
            None => {
                // No unwind entry — try FP-based step as fallback
                if let Some((ra, nbp)) = try_fp_step(bp) {
                    pointers[i] = ra;
                    len = i + 1;
                    current_ip = ra;
                    sp = bp + 16;
                    bp = nbp;
                    i += 1;
                    continue;
                }
                break;
            }
        };

        // Compute CFA (Canonical Frame Address) based on rule type
        //
        // Signal frames (CFA_REG_DEREF_RSP) are handled specially: we read
        // RIP/RSP/RBP directly from the ucontext_t on the stack at fixed
        // offsets, then continue unwinding from the interrupted frame.
        //
        // x86_64 Linux signal frame layout (from __restore_rt DWARF):
        //   RBP at *(RSP + 120), RSP at *(RSP + 160), RIP at *(RSP + 168)
        let is_signal = entry.cfa_type == CFA_REG_DEREF_RSP;

        let cfa = match entry.cfa_type {
            CFA_REG_RSP => sp.wrapping_add(entry.cfa_offset as i64 as u64),
            CFA_REG_RBP => bp.wrapping_add(entry.cfa_offset as i64 as u64),
            CFA_REG_PLT => {
                let base = sp.wrapping_add(entry.cfa_offset as i64 as u64);
                if (current_ip & 15) >= 11 {
                    base.wrapping_add(8)
                } else {
                    base
                }
            }
            // Signal frame: CFA = saved RSP = *(RSP + 160)
            CFA_REG_DEREF_RSP => match bpf_probe_read_user((sp + 160) as *const u64) {
                Ok(val) => val,
                Err(_) => break,
            },
            _ => break,
        };

        if cfa == 0 {
            break;
        }

        // Return address: CFA-8 for normal frames, *(RSP+168) for signal frames
        let ra_addr = if is_signal {
            sp + 168
        } else {
            cfa.wrapping_sub(8)
        };
        let return_addr = match bpf_probe_read_user(ra_addr as *const u64) {
            Ok(val) => val,
            Err(_) => break,
        };

        if return_addr == 0 {
            break;
        }

        // Restore RBP: for signal frames read from *(RSP+120),
        // otherwise use normal CFA-relative offset rule
        let new_bp = if is_signal {
            match bpf_probe_read_user((sp + 120) as *const u64) {
                Ok(val) => val,
                Err(_) => bp,
            }
        } else {
            match entry.rbp_type {
                REG_RULE_OFFSET => {
                    let bp_addr = (cfa as i64 + entry.rbp_offset as i64) as u64;
                    match bpf_probe_read_user(bp_addr as *const u64) {
                        Ok(val) => val,
                        Err(_) => bp,
                    }
                }
                REG_RULE_SAME_VALUE => bp,
                _ => bp,
            }
        };

        pointers[i] = return_addr;
        len = i + 1;

        // Update for next iteration
        current_ip = return_addr;
        sp = cfa;
        bp = new_bp;

        i += 1;
    }

    (ip, bp, len)
}

/// Initialize DWARF unwind state and attempt to tail-call into the step program.
/// If the tail call succeeds, execution transfers to dwarf_unwind_step and this
/// function never returns. If it fails (step program not registered, wrong program
/// type for kprobe/uprobe, or max tail calls reached), we return to the caller
/// which falls through to the legacy 21-frame inline DWARF path.
#[inline(always)]
unsafe fn dwarf_try_tail_call<C: EbpfContext>(
    ctx: &C,
    regs: &pt_regs,
    tgid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
    cpu: u32,
) {
    let Some(state) = UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };

    // Initialize unwind state with first frame
    (*state).pointers[0] = regs.rip;
    (*state).frame_count = 1;
    (*state).current_ip = regs.rip;
    (*state).sp = regs.rsp;
    (*state).bp = regs.rbp;
    (*state).tgid = tgid;
    (*state).mapping_count = 0; // Unused with LPM trie, kept for struct layout compat

    // Save finalization context so the step program can complete the work
    (*state).user_stack_id = user_stack_id;
    (*state).kernel_stack_id = kernel_stack_id;
    (*state).cmd = ctx.command().unwrap_or_default();
    (*state).cpu = cpu;
    (*state).initial_ip = regs.rip;
    (*state).initial_bp = regs.rbp;
    (*state).initial_sp = regs.rsp;

    // Attempt tail call. If successful, we never return.
    // If it fails (wrong program type, index not populated), we return.
    let _ = PROG_ARRAY.tail_call(ctx, 0);
}

/// Finalize DWARF unwinding: copy results from per-CPU state to STORAGE,
/// build StackInfo, and submit to maps/ring buffer.
/// Called from dwarf_unwind_step when the tail-call chain is complete.
#[inline(always)]
unsafe fn dwarf_finalize_stack(state: &DwarfUnwindState) {
    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };
    let pointer = &mut *pointer;

    // Copy unwound frame pointers from state to STORAGE
    let len = state.frame_count;
    for i in 0..MAX_DWARF_STACK_DEPTH {
        if i >= len || i >= pointer.pointers.len() {
            break;
        }
        pointer.pointers[i] = state.pointers[i];
    }
    pointer.len = len;

    let stack_info = StackInfo {
        tgid: state.tgid,
        user_stack_id: state.user_stack_id,
        kernel_stack_id: state.kernel_stack_id,
        cmd: state.cmd,
        cpu: state.cpu,
        ip: state.initial_ip,
        bp: state.initial_bp,
        sp: state.initial_sp,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += 1;
    } else {
        let _ = COUNTS.insert(&stack_info, &1, 0);
        notify = true;
    }

    if notify {
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

/// DWARF unwind step program body. Called via tail-call from collect_trace.
/// Unwinds FRAMES_PER_TAIL_CALL frames, then either tail-calls itself for more
/// or finalizes the stack trace.
pub unsafe fn dwarf_unwind_step_impl<C: EbpfContext>(ctx: C) {
    let Some(state) = UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };
    let state = &mut *state;

    // Unwind up to FRAMES_PER_TAIL_CALL frames per tail-call invocation.
    // Each frame does its own LPM trie lookup — no proc_info needed.
    let mut did_unwind = false;
    for _ in 0..FRAMES_PER_TAIL_CALL {
        if state.frame_count >= MAX_DWARF_STACK_DEPTH {
            break;
        }
        if state.frame_count >= state.pointers.len() {
            break;
        }
        if !dwarf_unwind_one_frame(state) {
            // Unwinding complete or failed — finalize
            dwarf_finalize_stack(state);
            return;
        }
        did_unwind = true;
    }

    if !did_unwind || state.frame_count >= MAX_DWARF_STACK_DEPTH {
        // Reached max depth or no progress — finalize
        dwarf_finalize_stack(state);
        return;
    }

    // More frames to unwind — tail-call back into ourselves.
    // If this fails (max 33 tail calls reached), we finalize below.
    let _ = PROG_ARRAY.tail_call(&ctx, 0);

    // Tail call failed (max tail calls reached) — finalize with what we have
    dwarf_finalize_stack(state);
}

/// DWARF-based stack unwinding entry point (legacy, no tail calls).
/// Used as fallback when tail-call dispatch is not available.
/// Uses per-CPU state and a flat loop limited to LEGACY_MAX_DWARF_STACK_DEPTH (21) frames.
#[inline(always)]
unsafe fn dwarf_copy_stack(regs: &pt_regs, pointers: &mut [u64], tgid: u32) -> (u64, u64, usize) {
    dwarf_copy_stack_regs(regs, pointers, tgid)
}

/// Try a single frame-pointer-based unwind step.
/// Returns (return_address, new_bp) if successful.
#[inline(always)]
unsafe fn try_fp_step(bp: u64) -> Option<(u64, u64)> {
    if bp == 0 || invalid_userspace_pointer(bp) {
        return None;
    }
    let new_bp = bpf_probe_read_user(bp as *const u64).ok()?;
    let ra = bpf_probe_read_user((bp + 8) as *const u64).ok()?;
    if ra == 0 || invalid_userspace_pointer(ra) {
        return None;
    }
    Some((ra, new_bp))
}

/// Look up an UnwindEntry from the array-of-maps by shard_id and index.
///
/// Uses the fused `get_value()` API which performs both outer and inner
/// `bpf_map_lookup_elem` calls without intermediate struct indirection.
/// This avoids verifier state explosion that occurs when the two lookups
/// are separated by typed wrapper code (MapDef::as_ptr() on the inner map).
#[inline(always)]
unsafe fn shard_lookup(shard_id: u16, idx: u32) -> Option<UnwindEntry> {
    let entry: &UnwindEntry = UNWIND_SHARDS.get_value(shard_id as u32, &idx)?;
    Some(*entry)
}

#[inline(always)]
unsafe fn binary_search_unwind_entry(
    shard_id: u16,
    table_count: u32,
    relative_pc: u32,
) -> Option<UnwindEntry> {
    if table_count == 0 {
        return None;
    }

    let mut lo: u32 = 0;
    let mut hi: u32 = table_count;

    for _ in 0..MAX_BIN_SEARCH_DEPTH {
        if lo >= hi {
            break;
        }
        let mid = lo + (hi - lo) / 2;

        let entry = match shard_lookup(shard_id, mid) {
            Some(e) => e,
            None => return None,
        };

        if entry.pc <= relative_pc {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo == 0 {
        return None;
    }

    shard_lookup(shard_id, lo - 1)
}

/// puts the userspace stack in the target pointer slice (from pt_regs directly)
#[inline(always)]
unsafe fn copy_stack_regs(regs: &pt_regs, pointers: &mut [u64]) -> (u64, u64, usize, u64) {
    // instruction pointer
    let ip = regs.rip;
    let sp = regs.rsp;

    // base pointer (frame pointer)
    let mut bp = regs.rbp;

    pointers[0] = ip;

    let mut len = pointers.len();
    for i in 1..pointers.len() {
        let Some(ret_addr) = get_frame(&mut bp) else {
            len = i;
            break;
        };

        pointers[i] = ret_addr;
    }

    (ip, bp, len, sp)
}

/// unwind frame pointer
#[inline(always)]
unsafe fn get_frame(fp: &mut u64) -> Option<u64> {
    let bp = *fp;
    if bp == 0 {
        return None;
    }

    const RETURN_OFFSET: u64 = 8; // x86_64 offset to get return addr from the base pointer
    let return_addr: u64 = bp + RETURN_OFFSET;

    // return address is the instruction pointer
    let ip = bpf_probe_read::<u64>(return_addr as *const u8 as _).ok()?;

    // frame pointer points to the base pointer!
    let bp: u64 = bpf_probe_read(bp as *const u8 as _).unwrap_or_default();

    *fp = bp;

    // santity check whether is the framepointer
    if invalid_userspace_pointer(ip) {
        return None;
    }

    Some(ip)
}

#[inline(always)]
fn invalid_userspace_pointer(ip: u64) -> bool {
    ip == 0 || ip >= __START_KERNEL_MAP
}

// ---------------------------------------------------------------------------
// Off-CPU profiling
// ---------------------------------------------------------------------------

/// Off-CPU profiling: trace context switches via kprobe on finish_task_switch.
///
/// This function is called from a kprobe attached to `finish_task_switch(prev)`.
/// It uses a per-CPU map to track which thread was previously running on each
/// CPU, avoiding the need to read task_struct fields at kernel-version-dependent
/// offsets.
///
/// The algorithm:
///   1. Look up which thread was previously running on this CPU (= "prev")
///   2. Record that prev went off-CPU at the current timestamp
///   3. Update the per-CPU map with the current (waking) thread's PID
///   4. Check if the current thread has a recorded off-CPU start time
///   5. Compute delta (blocked time in microseconds), apply filters
///   6. Capture stack trace and accumulate delta into COUNTS map
///
/// The stack trace belongs to the current (waking) thread. Application stack
/// traces don't change while off-CPU, so this captures the blocking context.
///
/// ## Alternative approach (documented for future work)
///
/// A `#[raw_tracepoint(tracepoint = "sched_switch")]` could be used instead,
/// which provides a more stable API (no kernel symbol name variations like
/// `finish_task_switch.isra.*`). The raw tracepoint args for sched_switch are:
///   - args[0] = bool preempt
///   - args[1] = struct task_struct *prev
///   - args[2] = struct task_struct *next
/// This would require different arg parsing but avoids kprobe symbol issues.
#[inline(always)]
pub unsafe fn collect_off_cpu_trace<C: EbpfContext>(ctx: C) {
    let now = bpf_ktime_get_ns();
    collect_off_cpu_trace_percpu(&ctx, now);
}

/// Per-CPU based off-CPU trace collection.
///
/// Uses a per-CPU map to track which thread PID was last running on each CPU.
/// When a context switch occurs (finish_task_switch entry):
///   1. Look up the PID that was previously running on this CPU (= prev)
///   2. Record off-CPU start time for prev
///   3. Update per-CPU map with current PID
///   4. Check if current has an off-CPU start time, compute delta, record stack
///
/// This avoids reading task_struct fields at unknown offsets.
#[inline(always)]
unsafe fn collect_off_cpu_trace_percpu<C: EbpfContext>(ctx: &C, now: u64) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let current_pid = pid_tgid as u32; // thread ID (kernel PID)
    let current_tgid = (pid_tgid >> 32) as u32; // process ID (TGID)

    let cpu = bpf_get_smp_processor_id();

    // --- Step 1: Record off-CPU start for the previously-running thread ---
    // Look up who was last running on this CPU
    if let Some(prev_pid_ptr) = LAST_PID_ON_CPU.get_ptr_mut(cpu) {
        let prev_pid = *prev_pid_ptr;

        // Record that prev went off-CPU now (if prev is a real thread)
        if prev_pid != 0 {
            let _ = OFF_CPU_START.insert(&prev_pid, &now, 0);
        }

        // Update: current is now running on this CPU
        *prev_pid_ptr = current_pid;
    }

    // --- Step 2: Compute off-CPU time for the current (waking) thread ---
    let Some(start_ts) = OFF_CPU_START.get(&current_pid).copied() else {
        return; // No recorded off-CPU start — first time seeing this thread
    };

    // Clean up the start time entry
    let _ = OFF_CPU_START.remove(&current_pid);

    // Sanity check: start should be before now
    if start_ts > now {
        return;
    }

    let delta_ns = now - start_ts;
    let delta_us = delta_ns / 1000;

    // Apply min/max block time filters
    let min_us = min_block_us();
    let max_us = max_block_us();
    if delta_us < min_us || delta_us > max_us {
        return;
    }

    // Skip idle threads if configured
    if current_pid == 0 && skip_idle() {
        return;
    }

    // Filter by target PID if specified
    let filter_pid = target_pid();
    if filter_pid != 0 && current_tgid != filter_pid {
        return;
    }

    // --- Step 3: Capture stack trace for the waking thread ---
    let user_stack_id = STACK_TRACES
        .get_stackid::<C>(ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid::<C>(ctx, 0)
        .map_or(-1, |stack_id| stack_id as i32);

    // Use per-CPU storage for frame pointers
    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };
    let pointer = &mut *pointer;

    // For kprobe context, ctx.as_ptr() is pt_regs for the CURRENT task.
    // We can use it for FP-based unwinding of the current task's user stack.
    // Note: For off-CPU, the user stack was frozen when the thread went to
    // sleep, and bpf_get_stackid captures it from the saved registers.
    // Custom FP/DWARF unwinding also works here since the kernel preserves
    // the task's register state.
    let regs = ctx.as_ptr() as *const pt_regs;

    // Attempt FP/DWARF unwinding if enabled, otherwise just use stackid
    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack_regs(&*regs, &mut pointer.pointers, current_tgid);
        (ip, bp, len, (*regs).rsp)
    } else {
        copy_stack_regs(&*regs, &mut pointer.pointers)
    };
    pointer.len = len;

    let cmd = ctx.command().unwrap_or_default();
    let stack_info = StackInfo {
        tgid: current_tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip,
        bp,
        sp,
    };

    let _ = STACK_ID_TO_TRACES.insert(&stack_info, pointer, 0);

    let notify_code = notify_type();
    let mut notify = notify_code == EVENT_TRACE_ALWAYS;

    // --- Step 4: Accumulate off-CPU time (microseconds) into COUNTS ---
    // Unlike on-CPU profiling which increments by 1 (sample count),
    // off-CPU profiling accumulates the blocked time in microseconds.
    if let Some(count) = COUNTS.get_ptr_mut(&stack_info) {
        *count += delta_us;
    } else {
        let _ = COUNTS.insert(&stack_info, &delta_us, 0);
        notify = true;
    }

    if notify {
        if let Some(mut entry) = RING_BUF_STACKS.reserve::<StackInfo>(0) {
            let _writable = entry.write(stack_info);
            entry.submit(0);
        }
    }
}

/// Handle sched_process_exit tracepoint for process exit monitoring.
/// Notifies userspace when the monitored PID exits.
#[inline(always)]
pub unsafe fn handle_process_exit<C: EbpfContext>(ctx: C) {
    use profile_bee_common::ProcessExitEvent;

    let tgid = ctx.tgid();
    let monitor_pid = monitor_exit_pid();

    // Only send notification if this is the PID we're monitoring
    if monitor_pid != 0 && tgid == monitor_pid {
        // Send exit notification to userspace
        if let Some(mut entry) = RING_BUF_PROCESS_EXIT.reserve::<ProcessExitEvent>(0) {
            let exit_event = ProcessExitEvent {
                pid: tgid,
                exit_code: 0, // Exit code is not easily accessible from sched_process_exit
            };
            let _writable = entry.write(exit_event);
            entry.submit(0);
        }
    }
}

// Make this simple now - checking for valid pointers can include
// checking with stack pointer address or getting valid ranges
// from from /proc/[pid]/maps
// void get_stack_bounds(u64 *stack_start, u64 *stack_end) {
//     struct task_struct *task;
//     task = (struct task_struct *)bpf_get_current_task();
//     // Read stack pointer and stack size from task_struct
//     bpf_probe_read(stack_start, sizeof(*stack_start), &task->stack);
//     *stack_end = *stack_start + THREAD_SIZE;  // THREAD_SIZE is typically 16KB on x86_64
// }
// bool valid_fp(u64 fp, u64 stack_start, u64 stack_end) {
//     // Check if frame pointer is within stack bounds and properly aligned
//     return (fp >= stack_start) &&
//            (fp < stack_end) &&
//            ((fp & 0x7) == 0);  // 8-byte aligned
// }
