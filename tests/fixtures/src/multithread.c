// Test: multiple threads with different call stacks.
// Stresses DWARF unwinding across threads sharing the same address space.
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

volatile int keep_running = 1;
void handle_signal(int sig) { keep_running = 0; }

__attribute__((noinline)) void hot_a(void) {
    while (keep_running) {}
}
__attribute__((noinline)) void chain_a2(void) { hot_a(); }
__attribute__((noinline)) void chain_a1(void) { chain_a2(); }

__attribute__((noinline)) void hot_b(void) {
    while (keep_running) {}
}
__attribute__((noinline)) void chain_b3(void) { hot_b(); }
__attribute__((noinline)) void chain_b2(void) { chain_b3(); }
__attribute__((noinline)) void chain_b1(void) { chain_b2(); }

void *thread_a(void *arg) { chain_a1(); return NULL; }
void *thread_b(void *arg) { chain_b1(); return NULL; }

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    alarm(10);

    pthread_t ta, tb;
    pthread_create(&ta, NULL, thread_a, NULL);
    pthread_create(&tb, NULL, thread_b, NULL);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return 0;
}
