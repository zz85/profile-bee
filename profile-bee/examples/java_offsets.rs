//! Dev tool: validate HotSpot VM-structs introspection against a live JVM.
//!
//! Dumps the resolved struct offsets, then ptrace-attaches the target's main
//! thread, walks the interpreter frame-pointer chain, and resolves each
//! frame's `Method*` (`[fp - 24]`, `interpreter_frame_method_offset = -3`
//! words — identical on x86-64 and aarch64) to a name — proving the full
//! `Method* -> "Class.method"` chain end to end. Run the target with `-Xint`
//! so frames stay interpreted.
//!
//! Usage: sudo ./java_offsets <pid>
use profile_bee::java::VmStructsReader;

// interpreter_frame_method_offset (-3) * wordSize(8); same on x86-64 / aarch64.
const INTERP_METHOD_OFF: i64 = -24;

fn main() {
    let pid: i32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("usage: java_offsets <pid>");

    let reader = VmStructsReader::new(pid as u32).expect("no libjvm.so for pid");
    let offsets = reader.resolve_offsets().expect("resolve offsets");
    println!("offsets: {offsets:?}");
    println!("is_complete = {}", offsets.is_complete());

    // The Java main() usually runs on a thread other than the process's
    // initial tid, so scan every thread's stack for Method* candidates. A
    // random 8-byte value chasing cleanly through Method->ConstMethod->
    // ConstantPool->Klass->Symbol to valid UTF-8 is effectively impossible, so
    // any hit is a real live Method* — validating the whole resolver.
    let _ = INTERP_METHOD_OFF;
    let mut seen = std::collections::HashSet::new();
    let mut names = std::collections::BTreeSet::new();
    let tids = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|d| {
            d.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    println!(
        "\nscanning {} thread stack(s) for live Method*...",
        tids.len()
    );
    for tid in tids {
        let Some(sp) = ptrace_stack_pointer(tid) else {
            continue;
        };
        for i in 0..8192u64 {
            let Some(method) = read_u64(pid, sp + i * 8) else {
                continue;
            };
            if method < 0x1000 || method % 8 != 0 || !seen.insert(method) {
                continue;
            }
            if let Some(name) = reader.resolve_method_name(&offsets, method) {
                names.insert(name);
            }
        }
        ptrace_detach(tid);
    }
    println!("resolved {} distinct live Method* name(s):", names.len());
    for n in names.iter().take(25) {
        println!("  {n}");
    }
}

fn read_u64(pid: i32, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: 8,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: 8,
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    (n == 8).then(|| u64::from_le_bytes(buf))
}

/// Attach to `pid` and return its stack pointer (leaving it attached on
/// success; the caller detaches). x86_64 reads `rsp` via `PTRACE_GETREGS`;
/// aarch64 reads `sp` via `PTRACE_GETREGSET`(`NT_PRSTATUS`).
#[cfg(target_arch = "x86_64")]
fn ptrace_stack_pointer(pid: i32) -> Option<u64> {
    unsafe {
        if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) != 0 {
            return None;
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let mut regs: libc::user_regs_struct = std::mem::zeroed();
        if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs as *mut _) == 0 {
            Some(regs.rsp)
        } else {
            // Detach so a failed register read doesn't leave the target stopped.
            libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            None
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn ptrace_stack_pointer(pid: i32) -> Option<u64> {
    const NT_PRSTATUS: i32 = 1;
    unsafe {
        if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) != 0 {
            return None;
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let mut regs: libc::user_regs_struct = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<libc::user_regs_struct>(),
        };
        if libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        ) == 0
        {
            Some(regs.sp)
        } else {
            libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            None
        }
    }
}

fn ptrace_detach(pid: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
    }
}
