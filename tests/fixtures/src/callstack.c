// Test fixture: deterministic call chain for stack unwinding validation.
// Expected stack (leaf to root): hot → function_c → function_b → function_a → main
//
// Compile variants:
//   gcc callstack.c -g -fno-omit-frame-pointer -o callstack-fp
//   gcc callstack.c -g -fomit-frame-pointer    -o callstack-no-fp

#include <signal.h>
#include <stdlib.h>

// Signal handler so we can stop cleanly from the test harness
volatile int keep_running = 1;
void handle_signal(int sig) { keep_running = 0; }

__attribute__((noinline)) void hot(void) {
    while (keep_running) {
        // busy spin — this is where the profiler will sample
    }
}

__attribute__((noinline)) void function_c(void) { hot(); }
__attribute__((noinline)) void function_b(void) { function_c(); }
__attribute__((noinline)) void function_a(void) { function_b(); }

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    function_a();
    return 0;
}
