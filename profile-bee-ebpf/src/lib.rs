#![no_std]

/// Shared reusable profiling ebpf components that can be included in
/// different ebpf applications.
///
use aya_ebpf::{
    bindings::{pt_regs, BPF_F_USER_STACK},
    helpers::{bpf_get_smp_processor_id, bpf_probe_read, bpf_probe_read_user},
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf, StackTrace},
    EbpfContext,
};

// use aya_log_ebpf::info;
use profile_bee_common::{
    FramePointers, StackInfo, EVENT_TRACE_ALWAYS, EVENT_TRACE_NEW,
    UnwindEntry, ProcInfo, ProcInfoKey,
    CFA_REG_RSP, CFA_REG_RBP,
    REG_RULE_OFFSET, REG_RULE_SAME_VALUE,
    MAX_DWARF_STACK_DEPTH, MAX_UNWIND_TABLE_SIZE, MAX_PROC_MAPS,
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

// DWARF unwind maps

/// Global unwind table: array of UnwindEntry indexed by position
#[map(name = "unwind_table")]
pub static UNWIND_TABLE: Array<UnwindEntry> = Array::with_max_entries(MAX_UNWIND_TABLE_SIZE, 0);

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

    let cmd = ctx.command().unwrap_or_default();
    let tgid = ctx.tgid(); // thread group id
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

    let (ip, bp, len, sp) = if dwarf_enabled() {
        let (ip, bp, len) = dwarf_copy_stack(&ctx, &mut pointer.pointers, tgid);
        let regs = ctx.as_ptr() as *const pt_regs;
        (ip, bp, len, (*regs).rsp)
    } else {
        copy_stack(&ctx, &mut pointer.pointers)
    };
    pointer.len = len;

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

const __START_KERNEL_MAP: u64 = 0xffffffff80000000;

/// DWARF-based stack unwinding using pre-loaded unwind tables
#[inline(always)]
unsafe fn dwarf_copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64], tgid: u32) -> (u64, u64, usize) {
    let regs = ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;

    let ip = regs.rip;
    let mut sp = regs.rsp;
    let mut bp = regs.rbp;

    pointers[0] = ip;

    // Look up the process's unwind information
    let proc_key = ProcInfoKey { tgid, _pad: 0 };
    let proc_info = match PROC_INFO.get(&proc_key) {
        Some(info) => info,
        None => {
            // No DWARF info loaded for this process, fall back to FP unwinding
            let (ip, bp, len, _sp) = copy_stack(ctx, pointers);
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
        let mut table_start: u32 = 0;
        let mut table_count: u32 = 0;
        let mut load_bias: u64 = 0;

        for m in 0..MAX_PROC_MAPS {
            if m >= mapping_count {
                break;
            }
            let mapping = &proc_info.mappings[m];
            if current_ip >= mapping.begin && current_ip < mapping.end {
                table_start = mapping.table_start;
                table_count = mapping.table_count;
                load_bias = mapping.load_bias;
                found_mapping = true;
                break;
            }
        }

        if !found_mapping || table_count == 0 {
            break;
        }

        // Convert virtual address to file-relative address for table lookup
        let relative_pc = current_ip - load_bias;

        // Binary search for the unwind entry covering this PC
        let entry = match binary_search_unwind_entry(table_start, table_count, relative_pc) {
            Some(e) => e,
            None => break,
        };

        // Compute CFA (Canonical Frame Address) based on rule type
        let cfa = match entry.cfa_type {
            CFA_REG_RSP => sp.wrapping_add(entry.cfa_offset as u64),
            CFA_REG_RBP => bp.wrapping_add(entry.cfa_offset as u64),
            _ => break,
        };

        if cfa == 0 {
            break;
        }

        // Get return address using the RA rule
        let return_addr = match entry.ra_type {
            REG_RULE_OFFSET => {
                let ra_addr = (cfa as i64 + entry.ra_offset as i64) as u64;
                match bpf_probe_read_user(ra_addr as *const u64) {
                    Ok(val) => val,
                    Err(_) => break,
                }
            }
            REG_RULE_SAME_VALUE => current_ip,
            _ => break,
        };

        if return_addr == 0 || return_addr == current_ip {
            break;
        }

        // Restore RBP if needed
        let new_bp = match entry.rbp_type {
            REG_RULE_OFFSET => {
                let bp_addr = (cfa as i64 + entry.rbp_offset as i64) as u64;
                match bpf_probe_read_user(bp_addr as *const u64) {
                    Ok(val) => val,
                    Err(_) => bp,
                }
            }
            REG_RULE_SAME_VALUE => bp,
            _ => bp,
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

/// Max binary search iterations (covers 2^16 = 65K entries per mapping)
const MAX_BIN_SEARCH_DEPTH: u32 = 16;

#[inline(always)]
unsafe fn binary_search_unwind_entry(table_start: u32, table_count: u32, relative_pc: u64) -> Option<UnwindEntry> {
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
        let idx = table_start + mid;

        let entry = match UNWIND_TABLE.get(idx) {
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

    let result_idx = table_start + lo - 1;
    UNWIND_TABLE.get(result_idx).copied()
}

/// puts the userspace stack in the target pointer slice
#[inline(always)]
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, usize, u64) {
    // refernce pt_regs
    let regs = ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;

    // instruction pointer
    let ip = regs.rip;
    let sp = regs.rsp;

    // base pointer (frame pointer)
    let mut bp = regs.rbp;

    pointers[0] = ip;

    return (ip, bp, 1, sp);

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
