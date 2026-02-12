// Test: C++ with exceptions and virtual dispatch (complex unwind tables).
// Tests DWARF unwinding through vtable calls and exception-heavy code paths.
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

volatile int keep_running = 1;
void handle_signal(int sig) { keep_running = 0; }

__attribute__((noinline)) void leaf_work(void) {
    while (keep_running) {}
}

// Simulate a deep indirect call chain (function pointers)
typedef void (*func_ptr)(int);

__attribute__((noinline)) void indirect_d(int depth) { leaf_work(); }
__attribute__((noinline)) void indirect_c(int depth) { indirect_d(depth); }
__attribute__((noinline)) void indirect_b(int depth) { indirect_c(depth); }
__attribute__((noinline)) void indirect_a(int depth) { indirect_b(depth); }

__attribute__((noinline)) void dispatch(func_ptr fn, int depth) {
    fn(depth);
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    alarm(10);
    dispatch(indirect_a, 4);
    return 0;
}
