#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{bpf_raw_tracepoint_args, pt_regs, BPF_F_USER_STACK},
    helpers::{
        bpf_get_current_task_btf, bpf_get_smp_processor_id, bpf_probe_read, bpf_probe_read_kernel,
        bpf_probe_read_user, bpf_task_pt_regs,
    },
    macros::map,
    maps::{Array, ArrayOfMaps, HashMap, PerCpuArray, ProgramArray, RingBuf, StackTrace},
    programs::RawTracePointContext,
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{
    DwarfUnwindState, FramePointers, ProcInfo, ProcInfoKey, StackInfo, UnwindEntry,
    CFA_REG_DEREF_RSP, CFA_REG_PLT, CFA_REG_RBP, CFA_REG_RSP, EVENT_TRACE_ALWAYS,
    FRAMES_PER_TAIL_CALL, LEGACY_MAX_DWARF_STACK_DEPTH, MAX_DWARF_STACK_DEPTH, MAX_PROC_MAPS,
    MAX_SHARD_ENTRIES, REG_RULE_OFFSET, REG_RULE_SAME_VALUE, SHARD_NONE,
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

// DWARF unwind maps — sharded per-binary Array tables (32 shards)

#[map(name = "shard_0")]
pub static SHARD_0: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_1")]
pub static SHARD_1: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_2")]
pub static SHARD_2: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_3")]
pub static SHARD_3: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_4")]
pub static SHARD_4: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_5")]
pub static SHARD_5: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_6")]
pub static SHARD_6: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_7")]
pub static SHARD_7: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_8")]
pub static SHARD_8: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_9")]
pub static SHARD_9: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_10")]
pub static SHARD_10: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_11")]
pub static SHARD_11: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_12")]
pub static SHARD_12: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_13")]
pub static SHARD_13: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_14")]
pub static SHARD_14: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_15")]
pub static SHARD_15: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_16")]
pub static SHARD_16: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_17")]
pub static SHARD_17: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_18")]
pub static SHARD_18: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_19")]
pub static SHARD_19: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_20")]
pub static SHARD_20: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_21")]
pub static SHARD_21: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_22")]
pub static SHARD_22: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_23")]
pub static SHARD_23: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_24")]
pub static SHARD_24: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_25")]
pub static SHARD_25: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_26")]
pub static SHARD_26: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_27")]
pub static SHARD_27: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_28")]
pub static SHARD_28: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_29")]
pub static SHARD_29: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_30")]
pub static SHARD_30: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);
#[map(name = "shard_31")]
pub static SHARD_31: Array<UnwindEntry> = Array::with_max_entries(MAX_SHARD_ENTRIES, 0);

/// Per-process unwind info: maps tgid to ProcInfo (exec mappings)
#[map(name = "proc_info")]
pub static PROC_INFO: HashMap<ProcInfoKey, ProcInfo> = HashMap::with_max_entries(1024, 0);

/// Per-CPU state for DWARF tail-call unwinding
#[map(name = "unwind_state")]
pub static UNWIND_STATE: PerCpuArray<DwarfUnwindState> = PerCpuArray::with_max_entries(1, 0);

/// Program array for tail-call chaining during DWARF unwinding
#[map(name = "prog_array")]
pub static PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

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
        .get_stackid(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid(&ctx, 0)
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
        // If we reach here, the tail call failed — continue with legacy path
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
        .get_stackid(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid(&ctx, 0)
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
        .get_stackid(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid(&ctx, 0)
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
        .get_stackid(&ctx, BPF_F_USER_STACK.into())
        .map_or(-1, |stack_id| stack_id as i32);
    let kernel_stack_id = STACK_TRACES
        .get_stackid(&ctx, 0)
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
#[inline(always)]
unsafe fn dwarf_unwind_one_frame(state: &mut DwarfUnwindState, proc_info: &ProcInfo) -> bool {
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

    // Find the mapping that contains current_ip
    let mut found_mapping = false;
    let mut shard_id: u8 = SHARD_NONE;
    let mut table_count: u32 = 0;
    let mut load_bias: u64 = 0;

    for m in 0..MAX_PROC_MAPS {
        if m >= state.mapping_count as usize {
            break;
        }
        let mapping = &proc_info.mappings[m];
        if current_ip >= mapping.begin && current_ip < mapping.end {
            shard_id = mapping.shard_id;
            table_count = mapping.table_count;
            load_bias = mapping.load_bias;
            found_mapping = true;
            break;
        }
    }

    if !found_mapping || table_count == 0 || shard_id == SHARD_NONE {
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

    // Look up the process's unwind information
    let proc_key = ProcInfoKey { tgid, _pad: 0 };
    let proc_info = match PROC_INFO.get(&proc_key) {
        Some(info) => info,
        None => {
            let (ip, bp, len, _sp) = copy_stack_regs(regs, pointers);
            return (ip, bp, len);
        }
    };

    let mut current_ip = ip;
    let mut len = 1usize;

    let mapping_count = proc_info.mapping_count as usize;

    let mut i = 1usize;
    for _ in 1..LEGACY_MAX_DWARF_STACK_DEPTH {
        if i >= pointers.len() {
            break;
        }
        if invalid_userspace_pointer(current_ip) {
            break;
        }

        // Find the mapping that contains current_ip
        let mut found_mapping = false;
        let mut shard_id: u8 = SHARD_NONE;
        let mut table_count: u32 = 0;
        let mut load_bias: u64 = 0;

        for m in 0..MAX_PROC_MAPS {
            if m >= mapping_count {
                break;
            }
            let mapping = &proc_info.mappings[m];
            if current_ip >= mapping.begin && current_ip < mapping.end {
                shard_id = mapping.shard_id;
                table_count = mapping.table_count;
                load_bias = mapping.load_bias;
                found_mapping = true;
                break;
            }
        }

        if !found_mapping || table_count == 0 || shard_id == SHARD_NONE {
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
    (*state).mapping_count = 0; // Step program reads from PROC_INFO directly

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

    let proc_key = ProcInfoKey {
        tgid: state.tgid,
        _pad: 0,
    };
    let Some(proc_info) = PROC_INFO.get(&proc_key) else {
        // No proc info found — finalize with whatever frames we have
        dwarf_finalize_stack(state);
        return;
    };

    // Set mapping_count from proc_info (not stored during init to save verifier budget)
    state.mapping_count = proc_info.mapping_count;

    // Unwind up to FRAMES_PER_TAIL_CALL frames per tail-call invocation
    let mut did_unwind = false;
    for _ in 0..FRAMES_PER_TAIL_CALL {
        if state.frame_count >= MAX_DWARF_STACK_DEPTH {
            break;
        }
        if state.frame_count >= state.pointers.len() {
            break;
        }
        if !dwarf_unwind_one_frame(state, proc_info) {
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

/// Dispatch to the correct shard Array by shard_id.
/// This is an 8-way static match — the verifier sees constant branches, no loop.
#[inline(always)]
unsafe fn shard_lookup(shard_id: u8, idx: u32) -> Option<UnwindEntry> {
    match shard_id {
        0 => SHARD_0.get(idx).copied(),
        1 => SHARD_1.get(idx).copied(),
        2 => SHARD_2.get(idx).copied(),
        3 => SHARD_3.get(idx).copied(),
        4 => SHARD_4.get(idx).copied(),
        5 => SHARD_5.get(idx).copied(),
        6 => SHARD_6.get(idx).copied(),
        7 => SHARD_7.get(idx).copied(),
        8 => SHARD_8.get(idx).copied(),
        9 => SHARD_9.get(idx).copied(),
        10 => SHARD_10.get(idx).copied(),
        11 => SHARD_11.get(idx).copied(),
        12 => SHARD_12.get(idx).copied(),
        13 => SHARD_13.get(idx).copied(),
        14 => SHARD_14.get(idx).copied(),
        15 => SHARD_15.get(idx).copied(),
        16 => SHARD_16.get(idx).copied(),
        17 => SHARD_17.get(idx).copied(),
        18 => SHARD_18.get(idx).copied(),
        19 => SHARD_19.get(idx).copied(),
        20 => SHARD_20.get(idx).copied(),
        21 => SHARD_21.get(idx).copied(),
        22 => SHARD_22.get(idx).copied(),
        23 => SHARD_23.get(idx).copied(),
        24 => SHARD_24.get(idx).copied(),
        25 => SHARD_25.get(idx).copied(),
        26 => SHARD_26.get(idx).copied(),
        27 => SHARD_27.get(idx).copied(),
        28 => SHARD_28.get(idx).copied(),
        29 => SHARD_29.get(idx).copied(),
        30 => SHARD_30.get(idx).copied(),
        31 => SHARD_31.get(idx).copied(),
        _ => None,
    }
}

/// Max binary search iterations (covers 2^18 = 262K entries = MAX_SHARD_ENTRIES)
const MAX_BIN_SEARCH_DEPTH: u32 = 18;

#[inline(always)]
unsafe fn binary_search_unwind_entry(
    shard_id: u8,
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
