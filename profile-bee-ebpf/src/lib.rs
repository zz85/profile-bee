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
    maps::{Array, HashMap, PerCpuArray, RingBuf, StackTrace},
    programs::RawTracePointContext,
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{
    FramePointers, ProcInfo, ProcInfoKey, StackInfo, UnwindEntry, CFA_REG_DEREF_RSP, CFA_REG_PLT,
    CFA_REG_RBP, CFA_REG_RSP, EVENT_TRACE_ALWAYS, MAX_DWARF_STACK_DEPTH, MAX_PROC_MAPS,
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

#[map(name = "stack_traces")]
pub static STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

// DWARF unwind maps — sharded per-binary Array tables

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

/// Per-process unwind info: maps tgid to ProcInfo (exec mappings)
#[map(name = "proc_info")]
pub static PROC_INFO: HashMap<ProcInfoKey, ProcInfo> = HashMap::with_max_entries(1024, 0);

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

/// Collect trace for raw tracepoint programs attached to sys_enter/sys_exit.
///
/// Raw tracepoint args for sys_enter: args[0] = struct pt_regs *, args[1] = syscall id
/// Raw tracepoint args for sys_exit:  args[0] = struct pt_regs *, args[1] = return value
///
/// Unlike `collect_trace`, this reads pt_regs from the tracepoint args rather than
/// from ctx.as_ptr(), since RawTracePointContext's as_ptr() returns bpf_raw_tracepoint_args.
#[inline(always)]
pub unsafe fn collect_trace_raw_syscall(ctx: RawTracePointContext) {
    // Read args from bpf_raw_tracepoint_args
    let args = ctx.as_ptr() as *const bpf_raw_tracepoint_args;
    let args_ptr = (*args).args.as_ptr();

    // args[0] = struct pt_regs *regs (pointer to interrupted userspace registers)
    let regs_ptr = args_ptr.read() as *const pt_regs;
    // args[1] = long syscall_id
    let syscall_nr = args_ptr.add(1).read() as i64;

    // Filter by target syscall number (-1 = match all)
    let target = target_syscall_nr();
    if target >= 0 && syscall_nr != target {
        return;
    }

    // Read pt_regs from kernel memory
    let Ok(regs) = bpf_probe_read_kernel(regs_ptr) else {
        return;
    };

    // From here, same logic as collect_trace but using regs directly
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

/// Collect trace for generic raw tracepoint programs (non-syscall).
///
/// For tracepoints like sched_switch, block_rq_issue, net_dev_xmit, etc.,
/// the raw tracepoint args do NOT contain pt_regs. We rely solely on
/// bpf_get_stackid() for stack traces (the kernel synthesizes pt_regs
/// internally via perf_fetch_caller_regs). Custom frame-pointer/DWARF
/// unwinding is not available — ip/bp/sp are set to 0.
#[inline(always)]
pub unsafe fn collect_trace_raw_tp_generic(ctx: RawTracePointContext) {
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

    // No pt_regs available — skip custom frame-pointer/DWARF unwinding.
    // Stack traces come entirely from bpf_get_stackid().
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
    for _ in 1..MAX_DWARF_STACK_DEPTH {
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
        _ => None,
    }
}

/// Max binary search iterations (covers 2^16 = 65K entries = MAX_SHARD_ENTRIES)
const MAX_BIN_SEARCH_DEPTH: u32 = 16;

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
