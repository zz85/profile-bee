// Rust test fixture: deterministic call chain for DWARF unwinding validation.
// Expected stack: hot_loop → rust_func_c → rust_func_b → rust_func_a → main
//
// Build:
//   rustc -C opt-level=2 -C force-frame-pointers=no -g -o rust-no-fp rust_callstack.rs
//   rustc -C opt-level=2 -C force-frame-pointers=yes -g -o rust-fp rust_callstack.rs

use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_signal(_: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

mod libc {
    pub type c_int = i32;
    pub type c_uint = u32;
    pub const SIGTERM: c_int = 15;
    pub const SIGINT: c_int = 2;
    pub const SIGALRM: c_int = 14;
    extern "C" {
        pub fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
        pub fn alarm(seconds: c_uint) -> c_uint;
    }
}

#[inline(never)]
fn hot_loop() {
    while RUNNING.load(Ordering::Relaxed) {}
}

#[inline(never)]
fn rust_func_c() { hot_loop(); }

#[inline(never)]
fn rust_func_b() { rust_func_c(); }

#[inline(never)]
fn rust_func_a() { rust_func_b(); }

fn main() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_signal);
        libc::signal(libc::SIGINT, handle_signal);
        libc::signal(libc::SIGALRM, handle_signal);
        libc::alarm(10);
    }
    rust_func_a();
}
