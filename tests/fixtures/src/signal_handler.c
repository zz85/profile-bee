// Test: stack unwinding through signal handlers (signal trampolines).
// Uses setitimer to self-deliver SIGPROF instead of forking.
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

volatile int keep_running = 1;
volatile long counter = 0;

void handle_term(int sig) { keep_running = 0; }

__attribute__((noinline)) void signal_work(void) {
    for (volatile int i = 0; i < 100000; i++) { counter++; }
}

__attribute__((noinline)) void handler(int sig) {
    signal_work();
}

__attribute__((noinline)) void compute(void) {
    while (keep_running) {
        for (volatile int i = 0; i < 1000; i++) { counter++; }
    }
}

int main(void) {
    signal(SIGTERM, handle_term);
    signal(SIGINT, handle_term);
    signal(SIGALRM, handle_term);
    signal(SIGPROF, handler);

    // Deliver SIGPROF every 1ms via setitimer
    struct itimerval timer = {
        .it_interval = { .tv_sec = 0, .tv_usec = 1000 },
        .it_value    = { .tv_sec = 0, .tv_usec = 1000 },
    };
    setitimer(ITIMER_PROF, &timer, NULL);

    alarm(10);
    compute();
    return 0;
}
