// Test fixture: deep recursion to test stack depth limits.
// Expected: recurse appears N times in the stack.
//
// Compile variants:
//   gcc deep.c -g -fno-omit-frame-pointer -o deep-fp
//   gcc deep.c -g -fomit-frame-pointer    -o deep-no-fp

#include <signal.h>
#include <stdlib.h>

volatile int keep_running = 1;
void handle_signal(int sig) { keep_running = 0; }

__attribute__((noinline)) void leaf(void) {
    while (keep_running) {}
}

__attribute__((noinline)) void recurse(int depth) {
    if (depth <= 0) {
        leaf();
        return;
    }
    recurse(depth - 1);
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    recurse(20);
    return 0;
}
