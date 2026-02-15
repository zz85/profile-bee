// Test fixture: deterministic off-CPU blocking for off-CPU profiling validation.
// Expected off-CPU stacks should contain: nanosleep / clock_nanosleep
// and the call chain: do_sleep -> sleep_inner -> main
//
// Compile:
//   gcc offcpu_sleep.c -g -fno-omit-frame-pointer -o offcpu-sleep-fp

#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

volatile int keep_running = 1;
void handle_signal(int sig) { keep_running = 0; }

__attribute__((noinline)) void do_sleep(void) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; // 10ms
    nanosleep(&ts, NULL);
}

__attribute__((noinline)) void sleep_inner(void) {
    while (keep_running) {
        do_sleep();
    }
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    alarm(10);  // self-terminate after 10s
    sleep_inner();
    return 0;
}
