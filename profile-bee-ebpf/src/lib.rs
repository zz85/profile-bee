#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{bpf_raw_tracepoint_args, BPF_F_USER_STACK},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_get_smp_processor_id,
        bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_task_pt_regs,
    },
    macros::{btf_map, map},
    maps::lpm_trie::{Key as LpmKey, LpmTrie},
    maps::{Array, HashMap, PerCpuArray, ProgramArray, RingBuf, StackTrace},
    programs::RawTracePointContext,
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::HotspotProcInfo;
use profile_bee_common::{
    normalize_exec_context, DwarfUnwindState, ExecMapping, ExecMappingKey, FramePointers,
    StackInfo, UnwindEntry, V8ProcInfo, CFA_REG_DEREF_RSP, CFA_REG_PLT, CFA_REG_RBP, CFA_REG_RSP,
    EVENT_TRACE_ALWAYS, EXEC_CTX_UNKNOWN, EXEC_MAPPING_KEY_BITS, FRAMES_PER_TAIL_CALL,
    LEGACY_MAX_DWARF_STACK_DEPTH, MAX_BIN_SEARCH_DEPTH, MAX_DWARF_STACK_DEPTH,
    MAX_EXEC_MAPPING_ENTRIES, MAX_SHARD_ENTRIES, MAX_UNWIND_SHARDS, MAX_V8_FRAMES, REG_RULE_OFFSET,
    REG_RULE_SAME_VALUE, SHARD_NONE, V8_FP_CONTEXT_SIZE,
};
// RA-recovery sentinels are only referenced by the aarch64 DWARF unwinder.
#[cfg(bpf_target_arch = "aarch64")]
use profile_bee_common::{RA_OFFSET_IN_LR, RA_OFFSET_UNDEFINED};

// ---------------------------------------------------------------------------
// Arch-neutral register access
// ---------------------------------------------------------------------------
//
// aya's `bindings::pt_regs` is field-accessible on x86_64 but an opaque ZST on
// aarch64. On aarch64 the kernel `struct pt_regs` begins with `user_pt_regs`
// ({ regs[31], sp, pc, pstate }) — the same leading bytes exposed to BPF as
// `bpf_user_pt_regs_t` — so we reinterpret the register file as `user_pt_regs`
// there. All unwinding code holds `&RawRegs` and reads registers through the
// `reg_*` accessors, keeping the sampling paths arch-neutral.
//
// The `bpf_target_arch` cfg is emitted by this crate's build.rs (mirroring
// aya-ebpf's own logic) so it matches the arch aya selected for `pt_regs`.
#[cfg(bpf_target_arch = "x86_64")]
type RawRegs = aya_ebpf::bindings::pt_regs;
#[cfg(bpf_target_arch = "aarch64")]
type RawRegs = aya_ebpf::bindings::user_pt_regs;

#[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
compile_error!("profile-bee-ebpf supports only x86_64 and aarch64 BPF targets");

/// Instruction pointer (program counter) of the sampled frame.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn reg_ip(r: &RawRegs) -> u64 {
    r.rip
}
/// Stack pointer of the sampled frame.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn reg_sp(r: &RawRegs) -> u64 {
    r.rsp
}
/// Frame pointer (base pointer) of the sampled frame.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn reg_fp(r: &RawRegs) -> u64 {
    r.rbp
}
/// Syscall number preserved in the register file (x86_64: `orig_rax`).
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn reg_syscall_nr(r: &RawRegs) -> u64 {
    r.orig_rax
}
/// Link register (return address of a leaf frame). x86_64 has no LR — the
/// return address is always on the stack — so this is unused there.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn reg_lr(_r: &RawRegs) -> u64 {
    0
}

// aarch64: PC = pc, SP = sp, FP = x29 (`regs[29]`), syscall NR = x8 (`regs[8]`).
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn reg_ip(r: &RawRegs) -> u64 {
    r.pc
}
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn reg_sp(r: &RawRegs) -> u64 {
    r.sp
}
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn reg_fp(r: &RawRegs) -> u64 {
    r.regs[29]
}
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn reg_syscall_nr(r: &RawRegs) -> u64 {
    r.regs[8]
}
/// Link register = x30 (`regs[30]`) — holds a leaf frame's return address.
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn reg_lr(r: &RawRegs) -> u64 {
    r.regs[30]
}

// Force LLVM to retain the full type definition of UnwindEntry during LTO.
// Without this, bpf-linker emits only a BTF FWD (forward declaration) for
// cross-crate types used solely as pointer targets in btf_map structs,
// causing aya's BTF parser to fail with UnexpectedBtfType.
#[used]
static _UNWIND_ENTRY_BTF_ANCHOR: UnwindEntry = UnwindEntry {
    pc: 0,
    cfa_offset: 0,
    rbp_offset: 0,
    ra_offset: 0,
    cfa_type: 0,
    rbp_type: 0,
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

/* preempt_count-based execution context detection.
 *
 * All resolved by userspace (see profile-bee/src/kernel_layout.rs) and injected
 * via override_global. When PREEMPT_CTX_MODE == 0 the feature is disabled and
 * current_exec_context() returns EXEC_CTX_UNKNOWN without any reads. */

/// 0 = disabled, 1 = x86 per-CPU var, 2 = arm64 task_struct field.
#[no_mangle]
static PREEMPT_CTX_MODE: u8 = 0;

/// x86 mode: absolute kernel address of the `__per_cpu_offset[]` array.
#[no_mangle]
static PREEMPT_PERCPU_OFFSET_ARRAY: u64 = 0;

/// x86 mode: per-CPU section offset of `__preempt_count`.
#[no_mangle]
static PREEMPT_PERCPU_VAR_OFFSET: u64 = 0;

/// arm64 mode: byte offset of `preempt_count` from the task pointer.
#[no_mangle]
static PREEMPT_TASK_BYTE_OFFSET: u32 = 0;

/// Hardirq levels contributed by the profiler's own sampling interrupt.
/// The perf software-clock hrtimer usually fires inside the APIC timer hardirq,
/// so this defaults to 1 for the perf_event path (set by userspace).
#[no_mangle]
static PREEMPT_SELF_HARDIRQ: u8 = 0;

/// NMI levels contributed by the profiler's own sampling interrupt
/// (nonzero only if sampling via a hardware PMU event).
#[no_mangle]
static PREEMPT_SELF_NMI: u8 = 0;

/// Softirq "serving" bit contributed by the profiler's own sampling interrupt
/// (nonzero only when the sampling hrtimer runs from the timer softirq).
#[no_mangle]
static PREEMPT_SELF_SOFTIRQ: u8 = 0;

/// Target PID to profile (0 = profile all processes)
/// Stored in an Array map so userspace can update it after process spawn.
#[map(name = "target_pid_map")]
static TARGET_PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

/// PID to monitor for exit (0 = don't monitor any process exit)
/// Stored in an Array map so userspace can update it dynamically.
#[map(name = "monitor_exit_pid_map")]
static MONITOR_EXIT_PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

/// Whether process lifecycle tracking is enabled (0 = disabled, 1 = enabled).
/// When enabled, exit events fire for ALL process exits (not just DWARF-tracked
/// or monitored PIDs), and the exec tracepoint sends exec events.
#[map(name = "lifecycle_tracking_map")]
static LIFECYCLE_TRACKING_MAP: Array<u32> = Array::with_max_entries(1, 0);

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

/// Normalized execution context (`EXEC_CTX_*`) of the *sampled* code, derived
/// from the kernel `preempt_count`.
///
/// Returns `EXEC_CTX_UNKNOWN` when the layout is disabled (`PREEMPT_CTX_MODE == 0`)
/// or any kernel read fails, so userspace falls back to symbol heuristics.
///
/// Kept branch-light and loop-free: two `bpf_probe_read_kernel` calls at most,
/// a handful of `.rodata` reads, and straight-line ALU. When the feature is
/// disabled the `mode == 0` early return lets the verifier prune the body via
/// `.rodata` constant folding.
///
/// `#[inline(never)]` is load-bearing: `collect_trace` is `#[inline(always)]`
/// and instantiated into several programs, and the branches here (two fallible
/// `bpf_probe_read_kernel` calls plus the mode/plausibility checks) would
/// multiply the verifier's explored-state count through the FP-walker loop that
/// follows, pushing `profile_cpu` past the 1M-instruction limit. Emitting it as
/// a single bpf-to-bpf subprogram verifies the body once and leaves each caller
/// with only a call instruction.
#[inline(never)]
unsafe fn current_exec_context(cpu: u32) -> u32 {
    let mode = core::ptr::read_volatile(&PREEMPT_CTX_MODE);
    if mode == 0 {
        return EXEC_CTX_UNKNOWN;
    }

    let raw: u32 = if mode == 1 {
        // x86 per-CPU variable.
        let arr = core::ptr::read_volatile(&PREEMPT_PERCPU_OFFSET_ARRAY);
        let voff = core::ptr::read_volatile(&PREEMPT_PERCPU_VAR_OFFSET);
        let Ok(base) = bpf_probe_read_kernel((arr + (cpu as u64) * 8) as *const u64) else {
            return EXEC_CTX_UNKNOWN;
        };
        let Ok(v) = bpf_probe_read_kernel((base + voff) as *const u32) else {
            return EXEC_CTX_UNKNOWN;
        };
        // x86 stores PREEMPT_NEED_RESCHED (0x80000000, inverted) inside
        // __preempt_count; preempt_count() masks it off. normalize_exec_context
        // also masks the top byte defensively, but do it here too for clarity.
        v & !0x8000_0000u32
    } else {
        // arm64 task_struct field.
        let off = core::ptr::read_volatile(&PREEMPT_TASK_BYTE_OFFSET);
        let task = bpf_get_current_task_btf() as *const u8;
        if task.is_null() {
            return EXEC_CTX_UNKNOWN;
        }
        let Ok(v) = bpf_probe_read_kernel(task.add(off as usize) as *const u32) else {
            return EXEC_CTX_UNKNOWN;
        };
        // arm64 keeps need_resched in a separate u32 — no masking needed.
        v
    };

    // Plausibility guard: no valid preempt_count sets bits 24..32 (after the
    // x86 need-resched mask). A bad injected offset surfaces as UNKNOWN rather
    // than a confidently-wrong context.
    if raw & 0xff00_0000 != 0 {
        return EXEC_CTX_UNKNOWN;
    }

    let self_nmi = core::ptr::read_volatile(&PREEMPT_SELF_NMI) as u32;
    let self_hardirq = core::ptr::read_volatile(&PREEMPT_SELF_HARDIRQ) as u32;
    let self_softirq = core::ptr::read_volatile(&PREEMPT_SELF_SOFTIRQ) as u32;
    normalize_exec_context(raw, self_nmi, self_hardirq, self_softirq)
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

#[inline]
unsafe fn lifecycle_tracking_enabled() -> bool {
    match LIFECYCLE_TRACKING_MAP.get(0) {
        Some(&v) => v != 0,
        None => false,
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

#[map(name = "process_exec_events")]
static RING_BUF_PROCESS_EXEC: RingBuf = RingBuf::with_byte_size(4096, 0);

#[map(name = "stack_traces")]
pub static STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);
// DWARF unwind maps — single outer ArrayOfMaps containing per-binary inner Array maps.
// Each inner map holds UnwindEntry values, keyed by u32 index.
// The outer map is indexed by shard_id (0..MAX_UNWIND_SHARDS-1).
// Userspace creates inner maps of the exact size needed per binary, then inserts
// their FDs into this outer map. This eliminates the old 8-shard / 65K-entry caps.
//
// Uses BTF map definition so the inner map shape is encoded in BTF metadata.
// The aya loader resolves the inner map template from BTF at load time — no
// separate UNWIND_SHARD_TEMPLATE map needed.

#[btf_map(name = "unwind_shards")]
pub static UNWIND_SHARDS: aya_ebpf::btf_maps::ArrayOfMaps<
    aya_ebpf::btf_maps::Array<UnwindEntry, { MAX_SHARD_ENTRIES as usize }>,
    { MAX_UNWIND_SHARDS },
> = aya_ebpf::btf_maps::ArrayOfMaps::new();

/// LPM trie for exec mapping lookups: maps (tgid, virtual_address) → ExecMapping.
/// Replaces the old proc_info HashMap + linear scan with O(log n) longest prefix match.
/// Userspace decomposes each memory mapping's address range into aligned power-of-2
/// blocks and inserts each as a separate LPM trie entry.
#[map(name = "exec_mappings")]
pub static EXEC_MAPPINGS: LpmTrie<ExecMappingKey, ExecMapping> =
    LpmTrie::with_max_entries(MAX_EXEC_MAPPING_ENTRIES, 0);

/// Tracks which tgids have DWARF unwind data loaded.
/// Userspace inserts (tgid, 1) when loading DWARF mappings for a process.
/// The BPF process-exit handler checks this map to decide whether to send
/// a cleanup event — avoids firing for every process exit on the system.
#[map(name = "dwarf_tgids")]
pub static DWARF_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

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

// --- V8 / Node.js introspection ---

/// Per-process V8 introspection data, keyed by tgid.
/// Userspace populates this when a Node.js process is detected, with offsets
/// parsed from v8dbg_* ELF symbols. The FP walker reads this to extract
/// JSFunction pointers from V8's frame pointer context slots.
#[map(name = "v8_proc_info")]
pub static V8_PROC_INFO: HashMap<u32, profile_bee_common::V8ProcInfo> =
    HashMap::with_max_entries(256, 0);

/// Per-process HotSpot interpreter info, populated by userspace when a JVM is
/// registered. The FP walker uses it to extract interpreter-frame `Method*`.
#[map(name = "hotspot_proc_info")]
pub static HOTSPOT_PROC_INFO: HashMap<u32, HotspotProcInfo> = HashMap::with_max_entries(256, 0);

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

    let regs = ctx.as_ptr() as *const RawRegs;

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
        (ip, bp, len, reg_sp(&*regs))
    } else {
        // Try tail-call-based FP+V8 walking for deep stacks with V8 SFI extraction.
        // If the tail call succeeds, execution transfers to fp_v8_unwind_step and
        // this function never continues past this point (the step program handles
        // finalization, COUNTS insertion, and RING_BUF submission).
        // If it fails (program not registered, non-perf_event context), we fall
        // through to the inline FP walker below (without V8 extraction).
        fp_v8_try_tail_call(&ctx, &*regs, tgid, user_stack_id, kernel_stack_id, cpu);
        copy_stack_regs(&*regs, pointer, tgid)
    };
    pointer.len = len;

    // Read execution context here — the *latest* point before building the key.
    // current_exec_context contains fallible kernel reads; placing it earlier
    // would fork verifier state through the FP-walk loop above and blow the
    // instruction limit. The tail-call paths (which never return here) read it
    // in their finalizers instead — tail calls preserve interrupt context.
    let context = current_exec_context(cpu);

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
        context,
        _reserved: 0,
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
    let regs_ptr = args_ptr.read() as *const RawRegs;
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
    let regs_ptr = args_ptr.read() as *const RawRegs;

    let Ok(regs) = bpf_probe_read_kernel(regs_ptr) else {
        return;
    };

    // For sys_exit, recover the syscall number from the register file
    // (x86_64: orig_rax; aarch64: x8, best-effort).
    let syscall_nr = reg_syscall_nr(&regs) as i64;

    let target = target_syscall_nr();
    if target >= 0 && syscall_nr != target {
        return;
    }

    collect_trace_with_regs_and_ctx(ctx, &regs);
}

/// Shared body for raw syscall tracepoint collection.
/// Called after syscall NR filtering with the already-read pt_regs.
#[inline(always)]
unsafe fn collect_trace_with_regs_and_ctx(ctx: RawTracePointContext, regs: &RawRegs) {
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
        (ip, bp, len, reg_sp(regs))
    } else {
        copy_stack_regs(regs, pointer, tgid)
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
        // Raw-syscall tracepoint path: context read not wired here (kept scoped
        // to the perf_event collect_trace to bound verifier cost). Userspace
        // falls back to symbol heuristics.
        context: EXEC_CTX_UNKNOWN,
        _reserved: 0,
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
        // Tracepoint/raw_tp stackid-only path: context not wired; userspace
        // falls back to symbol heuristics.
        context: EXEC_CTX_UNKNOWN,
        _reserved: 0,
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
    let regs_ptr = bpf_task_pt_regs(task) as *const RawRegs;
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
            context: EXEC_CTX_UNKNOWN,
            _reserved: 0,
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
        (ip, bp, len, reg_sp(&regs))
    } else {
        copy_stack_regs(&regs, pointer, tgid)
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
        // Generic raw_tp with task pt_regs: context not wired here.
        context: EXEC_CTX_UNKNOWN,
        _reserved: 0,
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

/// First non-userspace address — used to reject kernel pointers when validating
/// unwound frame IPs and interpreter `Method*` reads. Architecture-specific:
///
/// - x86_64: the kernel text base `0xffffffff80000000`. (Canonical kernel-half
///   addresses start at `0xffff800000000000`, but the historical value here is
///   sufficient for the FP/DWARF walkers and is preserved unchanged.)
/// - aarch64: `2^48`, one past the top of the 48-bit user virtual address range
///   (`0x0000_ffff_ffff_ffff`). Kernel (TTBR1) addresses live at
///   `0xffff_0000_0000_0000`+ — crucially *below* the x86_64 constant, so that
///   value would wrongly accept aarch64 kernel pointers (observed as bogus
///   "user" frames when walking kernel register state, e.g. off-CPU).
#[cfg(bpf_target_arch = "x86_64")]
const __START_KERNEL_MAP: u64 = 0xffffffff80000000;
#[cfg(bpf_target_arch = "aarch64")]
const __START_KERNEL_MAP: u64 = 0x0001_0000_0000_0000;

/// Resolve a frame's return address from its unwind entry and computed CFA.
///
/// Returns `None` to stop unwinding. `is_leaf_step` is true when unwinding out
/// of the sampled (leaf) frame — the only frame whose return address may still
/// be in a register. `lr` is the sampled link register (aarch64).
///
/// x86_64: the return address is always at CFA-8 (or a fixed ucontext offset
/// for signal frames); `ra_offset` is ignored, preserving the original behavior
/// byte-for-byte.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
unsafe fn dwarf_return_addr(
    entry: &UnwindEntry,
    cfa: u64,
    sp: u64,
    _lr: u64,
    _is_leaf_step: bool,
) -> Option<u64> {
    // Signal frame: RA at *(RSP + 168); normal frame: RA at CFA-8.
    let ra_addr = if entry.cfa_type == CFA_REG_DEREF_RSP {
        sp + 168
    } else {
        cfa.wrapping_sub(8)
    };
    let ra = bpf_probe_read_user(ra_addr as *const u64).ok()?;
    if ra == 0 {
        None
    } else {
        Some(ra)
    }
}

/// aarch64: the return address lives in LR (x30). `ra_offset` is load-bearing —
/// it is either a CFA-relative offset where the RA was spilled, or the sentinel
/// [`RA_OFFSET_IN_LR`] (RA still in x30, recoverable only for the leaf step) or
/// [`RA_OFFSET_UNDEFINED`] (top of stack).
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
unsafe fn dwarf_return_addr(
    entry: &UnwindEntry,
    cfa: u64,
    _sp: u64,
    lr: u64,
    is_leaf_step: bool,
) -> Option<u64> {
    match entry.ra_offset {
        RA_OFFSET_UNDEFINED => None,
        RA_OFFSET_IN_LR => {
            // RA is still in x30: only the sampled leaf frame's LR is known.
            if is_leaf_step && lr != 0 {
                Some(lr)
            } else {
                None
            }
        }
        off => {
            let ra_addr = (cfa as i64).wrapping_add(off as i64) as u64;
            let ra = bpf_probe_read_user(ra_addr as *const u64).ok()?;
            if ra == 0 {
                None
            } else {
                Some(ra)
            }
        }
    }
}

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
        EXEC_MAPPING_KEY_BITS,
        ExecMappingKey {
            tgid: state.tgid.to_be(),
            _pad: 0,
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

    // Return address: x86_64 uses CFA-8 (or the signal-frame ucontext slot);
    // aarch64 uses the entry's ra_offset / LR. frame_idx == 1 is the step out
    // of the sampled leaf frame (the only frame whose RA may be in a register).
    let Some(return_addr) = dwarf_return_addr(&entry, cfa, sp, state.lr, frame_idx == 1) else {
        return false;
    };

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
    regs: &RawRegs,
    pointers: &mut [u64],
    tgid: u32,
) -> (u64, u64, usize) {
    let ip = reg_ip(regs);
    let mut sp = reg_sp(regs);
    let mut bp = reg_fp(regs);

    pointers[0] = ip;

    // Quick check: try LPM for initial IP. If no mapping found,
    // this process likely has no DWARF info — use full FP unwinding.
    let first_key = LpmKey::new(
        EXEC_MAPPING_KEY_BITS,
        ExecMappingKey {
            tgid: tgid.to_be(),
            _pad: 0,
            address: ip.to_be(),
        },
    );
    if EXEC_MAPPINGS.get(&first_key).is_none() {
        let (ip, bp, len, _sp) = copy_stack_regs_fp_only(regs, pointers);
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
            EXEC_MAPPING_KEY_BITS,
            ExecMappingKey {
                tgid: tgid.to_be(),
                _pad: 0,
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

        // Return address: x86_64 uses CFA-8 (or signal-frame ucontext slot);
        // aarch64 uses the entry's ra_offset / LR. i == 1 is the step out of the
        // sampled leaf frame (the only frame whose RA may still be in a register).
        let Some(return_addr) = dwarf_return_addr(&entry, cfa, sp, reg_lr(regs), i == 1) else {
            break;
        };

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
    regs: &RawRegs,
    tgid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
    cpu: u32,
) {
    let Some(state) = UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };

    let ip = reg_ip(regs);
    let sp = reg_sp(regs);
    let bp = reg_fp(regs);

    // Initialize unwind state with first frame
    (*state).pointers[0] = ip;
    (*state).frame_count = 1;
    (*state).current_ip = ip;
    (*state).sp = sp;
    (*state).bp = bp;
    // Sampled link register: lets the aarch64 step program recover the leaf
    // frame's return address when it is still in x30 (no-op on x86_64).
    (*state).lr = reg_lr(regs);
    (*state).tgid = tgid;
    (*state).mapping_count = 0; // Unused with LPM trie, kept for struct layout compat

    // Save finalization context so the step program can complete the work
    (*state).user_stack_id = user_stack_id;
    (*state).kernel_stack_id = kernel_stack_id;
    (*state).cmd = ctx.command().unwrap_or_default();
    (*state).cpu = cpu;
    (*state).initial_ip = ip;
    (*state).initial_bp = bp;
    (*state).initial_sp = sp;

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

    // Clear v8_sfi / hotspot_method to prevent stale data from a previous
    // FP sample leaking into this DWARF sample (STORAGE persists per-CPU).
    for i in 0..MAX_V8_FRAMES {
        pointer.v8_sfi[i] = 0;
        pointer.hotspot_method[i] = 0;
    }

    // Tail calls preserve interrupt context, so preempt_count read here reflects
    // the sampled code's context, just as it would in collect_trace.
    let context = current_exec_context(state.cpu);
    let stack_info = StackInfo {
        tgid: state.tgid,
        user_stack_id: state.user_stack_id,
        kernel_stack_id: state.kernel_stack_id,
        cmd: state.cmd,
        cpu: state.cpu,
        ip: state.initial_ip,
        bp: state.initial_bp,
        sp: state.initial_sp,
        context,
        _reserved: 0,
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
unsafe fn dwarf_copy_stack(regs: &RawRegs, pointers: &mut [u64], tgid: u32) -> (u64, u64, usize) {
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
///
/// The V8 SFI extraction is handled by the FP+V8 tail-call walker
/// (fp_v8_try_tail_call → fp_v8_unwind_step) which runs as a separate
/// tail-call program at PROG_ARRAY index 1. If the tail call succeeds,
/// collect_trace never reaches this function. If it fails (program not
/// registered, non-perf_event context), this inline fallback runs without
/// V8 extraction.
#[inline(always)]
unsafe fn copy_stack_regs(
    regs: &RawRegs,
    pointer: &mut FramePointers,
    tgid: u32,
) -> (u64, u64, usize, u64) {
    // Clear v8_sfi / hotspot_method to prevent stale values from a previous
    // tail-call sample leaking through (STORAGE is a PerCpuArray that persists).
    for i in 0..MAX_V8_FRAMES {
        pointer.v8_sfi[i] = 0;
        pointer.hotspot_method[i] = 0;
    }
    let ret = copy_stack_regs_fp_only(regs, &mut pointer.pointers);

    // HotSpot interpreter Method* for the LEAF frame only, on the inline FP path
    // (kprobe/uprobe, and kernels where the tail-call FP program won't load).
    // A per-frame re-walk here blows the BPF verifier complexity budget on this
    // already-large program, so we name only the on-CPU leaf (the most valuable
    // frame); deeper interpreter frames are named via the tail-call path. One
    // map lookup + one read — same cost class as the V8 leaf extraction.
    if let Some(hi) = HOTSPOT_PROC_INFO.get(&tgid) {
        if let Some(m) = try_read_hotspot_method(hi, reg_ip(regs), reg_fp(regs)) {
            pointer.hotspot_method[0] = m;
        }
    }
    ret
}

/// Initialize FP+V8 unwind state and attempt to tail-call into the FP+V8 step
/// program at PROG_ARRAY index 1.
///
/// If the tail call succeeds, execution transfers to fp_v8_unwind_step and this
/// function never returns. The step program walks the frame pointer chain 5
/// frames at a time, extracts V8 SFI for each frame, and finalizes by copying
/// results to STORAGE + submitting to RING_BUF_STACKS.
///
/// If the tail call fails (step program not loaded, wrong program type for
/// kprobe/uprobe), we return to the caller which falls through to the inline
/// FP walker (copy_stack_regs) without V8 extraction.
#[inline(always)]
unsafe fn fp_v8_try_tail_call<C: EbpfContext>(
    ctx: &C,
    regs: &RawRegs,
    tgid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
    cpu: u32,
) {
    let Some(state) = UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };

    let ip = reg_ip(regs);
    let sp = reg_sp(regs);
    let bp = reg_fp(regs);

    // Initialize with first frame (current IP)
    (*state).pointers[0] = ip;
    (*state).frame_count = 1;
    (*state).current_ip = ip;
    (*state).sp = sp;
    (*state).bp = bp;
    (*state).tgid = tgid;

    // Zero V8 SFI slot for frame 0 and attempt extraction
    (*state).v8_sfi[0] = 0;
    if let Some(vi) = V8_PROC_INFO.get(&tgid) {
        if let Some(sfi) = try_read_v8_sfi(vi, bp) {
            (*state).v8_sfi[0] = sfi;
        }
    }

    // HotSpot interpreter Method* for the leaf frame (IP=pc, base=fp).
    (*state).hotspot_method[0] = 0;
    if let Some(hi) = HOTSPOT_PROC_INFO.get(&tgid) {
        if let Some(m) = try_read_hotspot_method(hi, ip, bp) {
            (*state).hotspot_method[0] = m;
        }
    }

    // Save finalization context
    (*state).user_stack_id = user_stack_id;
    (*state).kernel_stack_id = kernel_stack_id;
    (*state).cmd = ctx.command().unwrap_or_default();
    (*state).cpu = cpu;
    (*state).initial_ip = ip;
    (*state).initial_bp = bp;
    (*state).initial_sp = sp;

    // Attempt tail call to FP+V8 step program at index 1.
    // If successful, we never return.
    let _ = PROG_ARRAY.tail_call(ctx, 1);
}

/// Finalize FP+V8 unwinding: copy frame pointers and V8 SFI data from per-CPU
/// state to STORAGE, build StackInfo, and submit to maps/ring buffer.
/// Called from fp_v8_unwind_step when walking is complete.
#[inline(always)]
unsafe fn fp_v8_finalize_stack(state: &DwarfUnwindState) {
    let Some(pointer) = STORAGE.get_ptr_mut(0) else {
        return;
    };
    let pointer = &mut *pointer;

    // Copy frame pointers from state to STORAGE
    let len = state.frame_count;
    for i in 0..MAX_DWARF_STACK_DEPTH {
        if i >= len || i >= pointer.pointers.len() {
            break;
        }
        pointer.pointers[i] = state.pointers[i];
    }
    pointer.len = len;

    // Copy V8 SFI data
    for i in 0..MAX_V8_FRAMES {
        if i >= len {
            break;
        }
        pointer.v8_sfi[i] = state.v8_sfi[i];
    }

    // Copy HotSpot interpreter Method* data
    for i in 0..MAX_V8_FRAMES {
        if i >= len {
            break;
        }
        pointer.hotspot_method[i] = state.hotspot_method[i];
    }

    // Tail calls preserve interrupt context (see dwarf_finalize_stack).
    let context = current_exec_context(state.cpu);
    let stack_info = StackInfo {
        tgid: state.tgid,
        user_stack_id: state.user_stack_id,
        kernel_stack_id: state.kernel_stack_id,
        cmd: state.cmd,
        cpu: state.cpu,
        ip: state.initial_ip,
        bp: state.initial_bp,
        sp: state.initial_sp,
        context,
        _reserved: 0,
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

/// FP+V8 unwind step program body. Called via tail-call from collect_trace
/// (through fp_v8_try_tail_call at PROG_ARRAY index 1).
///
/// Walks FRAMES_PER_TAIL_CALL (5) frames per invocation using frame pointer
/// chaining, and for each frame extracts V8 SFI if the process has V8ProcInfo.
/// Then either tail-calls itself for more frames or finalizes the stack trace.
///
/// This is the FP equivalent of dwarf_unwind_step_impl — same tail-call pattern,
/// different unwinding logic.
pub unsafe fn fp_v8_unwind_step_impl<C: EbpfContext>(ctx: C) {
    let Some(state) = UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };
    let state = &mut *state;

    let mut did_walk = false;
    for _ in 0..FRAMES_PER_TAIL_CALL {
        if state.frame_count >= MAX_DWARF_STACK_DEPTH {
            break;
        }
        if state.frame_count >= state.pointers.len() {
            break;
        }

        // FP step: read [bp] = next_bp, [bp+8] = return_addr
        let Some((ra, new_bp)) = try_fp_step(state.bp) else {
            fp_v8_finalize_stack(state);
            return;
        };

        let idx = state.frame_count;
        state.pointers[idx] = ra;

        // V8 SFI extraction for this frame (the V8 context at new_bp
        // belongs to the frame we just discovered at pointers[idx])
        if idx < MAX_V8_FRAMES {
            state.v8_sfi[idx] = 0;
            if let Some(vi) = V8_PROC_INFO.get(&state.tgid) {
                if let Some(sfi) = try_read_v8_sfi(vi, new_bp) {
                    state.v8_sfi[idx] = sfi;
                }
            }
            // HotSpot interpreter Method* for this frame (same convention as
            // V8: the frame just discovered at pointers[idx] has base new_bp).
            state.hotspot_method[idx] = 0;
            if let Some(hi) = HOTSPOT_PROC_INFO.get(&state.tgid) {
                if let Some(m) = try_read_hotspot_method(hi, ra, new_bp) {
                    state.hotspot_method[idx] = m;
                }
            }
        }

        state.frame_count = idx + 1;
        state.bp = new_bp;
        state.current_ip = ra;
        did_walk = true;
    }

    if !did_walk || state.frame_count >= MAX_DWARF_STACK_DEPTH {
        fp_v8_finalize_stack(state);
        return;
    }

    // More frames to walk — tail-call back into ourselves at index 1
    let _ = PROG_ARRAY.tail_call(&ctx, 1);

    // Tail call failed (max 33 tail calls reached) — finalize with what we have
    fp_v8_finalize_stack(state);
}

/// Pure FP-based stack walking without V8 extraction.
/// Used internally by `copy_stack_regs` and as a fallback from `dwarf_copy_stack_regs`.
unsafe fn copy_stack_regs_fp_only(regs: &RawRegs, pointers: &mut [u64]) -> (u64, u64, usize, u64) {
    // instruction pointer
    let ip = reg_ip(regs);
    let sp = reg_sp(regs);

    // base pointer (frame pointer)
    let mut bp = reg_fp(regs);

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

/// Try to extract the V8 SharedFunctionInfo tagged pointer from a frame's
/// FP context. Returns the tagged SFI pointer if the frame looks like a V8
/// JavaScript frame (JSFunction type check passes).
///
/// Reads: [fp - V8_FP_CONTEXT_SIZE + fp_function] → JSFunction tagged ptr
///        JSFunction.map → Map.instance_type (verify it's a JSFunction)
///        JSFunction.shared → SharedFunctionInfo tagged ptr
/// Extract a HotSpot interpreter frame's `Method*`.
///
/// `ra` is the frame's return address (its executing PC) and `frame_bp` its
/// base pointer. If `ra` is inside the template-interpreter code range, the
/// current `Method*` is at `frame_bp + method_offset`.
#[inline(always)]
unsafe fn try_read_hotspot_method(hi: &HotspotProcInfo, ra: u64, frame_bp: u64) -> Option<u64> {
    if ra < hi.interp_low || ra >= hi.interp_high {
        return None;
    }
    let addr = (frame_bp as i64).wrapping_add(hi.method_offset) as u64;
    let method = bpf_probe_read_user::<u64>(addr as *const u64).ok()?;
    if method == 0 || method >= __START_KERNEL_MAP {
        return None;
    }
    Some(method)
}

#[inline(always)]
unsafe fn try_read_v8_sfi(vi: &V8ProcInfo, bp: u64) -> Option<u64> {
    // The fp_function offset is a byte offset within the 64-byte FP context
    // buffer (already mapped from the signed FP-relative offset by userspace).
    // Ensure the entire 8-byte u64 read fits within the context area.
    let fp_func_offset = vi.fp_function as u64;
    if fp_func_offset + core::mem::size_of::<u64>() as u64 > V8_FP_CONTEXT_SIZE as u64 {
        return None; // read would extend past the FP context boundary
    }

    // Read the JSFunction tagged pointer from the FP context
    let fp_ctx_addr = bp.wrapping_sub(V8_FP_CONTEXT_SIZE as u64);
    let jsfunc_tagged: u64 =
        bpf_probe_read_user((fp_ctx_addr + fp_func_offset) as *const u64).ok()?;

    // Check heap object tag (low 2 bits == 01)
    if jsfunc_tagged & 0x3 != 0x1 {
        return None;
    }
    let jsfunc_addr = jsfunc_tagged & !0x3u64;

    // Verify it's a JSFunction by reading HeapObject.map → Map.instance_type
    let map_tagged: u64 =
        bpf_probe_read_user((jsfunc_addr + vi.off_heap_object_map as u64) as *const u64).ok()?;
    if map_tagged & 0x3 != 0x1 {
        return None;
    }
    let map_addr = map_tagged & !0x3u64;

    let instance_type: u16 =
        bpf_probe_read_user((map_addr + vi.off_map_instance_type as u64) as *const u16).ok()?;

    // Check if instance_type falls in the JSFunction range
    if instance_type < vi.type_jsfunction_first || instance_type > vi.type_jsfunction_last {
        return None;
    }

    // Read JSFunction.shared → SharedFunctionInfo tagged pointer
    let sfi_tagged: u64 =
        bpf_probe_read_user((jsfunc_addr + vi.off_jsfunction_shared as u64) as *const u64).ok()?;

    // Verify it's a heap object
    if sfi_tagged & 0x3 != 0x1 {
        return None;
    }

    Some(sfi_tagged)
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
    let regs = ctx.as_ptr() as *const RawRegs;

    // Attempt FP/DWARF unwinding if enabled, otherwise just use stackid
    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack_regs(&*regs, &mut pointer.pointers, current_tgid);
        (ip, bp, len, reg_sp(&*regs))
    } else {
        copy_stack_regs(&*regs, pointer, current_tgid)
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
        // Off-CPU path (finish_task_switch kprobe): the sampled context is the
        // waking thread, not an interrupt; context detection is not meaningful
        // here, so leave it unknown.
        context: EXEC_CTX_UNKNOWN,
        _reserved: 0,
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
/// Sends a ProcessExitEvent when:
/// - The monitored PID exits (--pid mode: stops profiling), OR
/// - A DWARF-tracked process exits (cleanup LPM trie entries), OR
/// - Lifecycle tracking is enabled (system-wide process awareness).
///
/// Only fires for process exits (tid == tgid), not individual thread exits.
/// sched_process_exit fires for every thread exit; without this filter,
/// thread-heavy workloads (Java, Go) would generate thousands of
/// duplicate events per second for the same tgid.
#[inline(always)]
pub unsafe fn handle_process_exit<C: EbpfContext>(ctx: C) {
    use profile_bee_common::ProcessExitEvent;

    let tid = ctx.pid();
    let tgid = ctx.tgid();

    // Skip thread exits — only fire for the main thread (process exit).
    if tid != tgid {
        return;
    }

    let monitor_pid = monitor_exit_pid();

    // Send notification if this is a monitored PID, DWARF-tracked process,
    // or lifecycle tracking is enabled (for system-wide process awareness).
    let is_monitored = monitor_pid != 0 && tgid == monitor_pid;
    let is_dwarf_tracked = unsafe { DWARF_TGIDS.get(&tgid).is_some() };
    let lifecycle = unsafe { lifecycle_tracking_enabled() };

    if is_monitored || is_dwarf_tracked || lifecycle {
        if let Some(mut entry) = RING_BUF_PROCESS_EXIT.reserve::<ProcessExitEvent>(0) {
            let exit_event = ProcessExitEvent {
                pid: tgid,
                exit_code: 0,
            };
            let _writable = entry.write(exit_event);
            entry.submit(0);
        }
    }
}

/// Handle sched_process_exec tracepoint for process exec monitoring.
/// Sends a ProcessExecEvent when a process calls execve(), enabling
/// proactive DWARF table loading and metadata cache invalidation.
///
/// Note: sched_process_exec only fires once per execve() (not per-thread),
/// so no tid == tgid filter is needed here.
#[inline(always)]
pub unsafe fn handle_process_exec<C: EbpfContext>(ctx: C) {
    use profile_bee_common::ProcessExecEvent;

    let tgid = ctx.tgid();

    if let Some(mut entry) = RING_BUF_PROCESS_EXEC.reserve::<ProcessExecEvent>(0) {
        let exec_event = ProcessExecEvent { pid: tgid, _pad: 0 };
        let _writable = entry.write(exec_event);
        entry.submit(0);
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
