// Shared library with a hot function for testing cross-library DWARF unwinding.
//
// Compile:
//   gcc -shared -fPIC -g -fomit-frame-pointer -o libhotlib.so libhotlib.c

#include "libhotlib.h"

volatile int lib_keep_running = 1;

__attribute__((noinline)) void lib_hot(void) {
    while (lib_keep_running) {}
}

__attribute__((noinline)) void lib_inner(void) { lib_hot(); }

__attribute__((noinline)) void lib_entry(void) { lib_inner(); }
