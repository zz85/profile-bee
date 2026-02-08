// Test fixture: cross-library call chain for DWARF unwinding validation.
// Expected stack: lib_hot → lib_inner → lib_entry → caller_b → caller_a → main
//
// Compile:
//   gcc -shared -fPIC -g -fomit-frame-pointer -o libhotlib.so libhotlib.c
//   gcc sharedlib.c -g -fomit-frame-pointer -L. -lhotlib -Wl,-rpath,'$ORIGIN' -o sharedlib-no-fp

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "libhotlib.h"

void handle_signal(int sig) { lib_keep_running = 0; }

__attribute__((noinline)) void caller_b(void) { lib_entry(); }
__attribute__((noinline)) void caller_a(void) { caller_b(); }

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    alarm(10);
    caller_a();
    return 0;
}
