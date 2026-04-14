// Node.js test fixture for profile-bee E2E tests.
// Creates a CPU-intensive call stack with known function names.
//
// V8's tiered compilation starts functions in the interpreter and only
// JIT-compiles them after sufficient invocations. The warmup phase below
// ensures our functions are compiled (and appear in the perf-map file)
// before the main profiling window.

'use strict';

function hot() {
    // Busy loop to consume CPU time and be visible in profiles
    let sum = 0;
    for (let i = 0; i < 1e6; i++) {
        sum += Math.sqrt(i) * Math.sin(i);
    }
    return sum;
}

function processData() {
    return hot();
}

function handleRequest() {
    return processData();
}

function serverLoop() {
    return handleRequest();
}

// Warmup: call enough times to trigger JIT compilation in all V8 tiers.
// Sparkplug/baseline compiles after ~1 call, TurboFan after ~100-1000.
// This ensures perf-map entries exist before the profiling window.
for (let i = 0; i < 50; i++) {
    serverLoop();
}

// Run for a fixed duration to give the profiler time to capture samples
const duration = parseInt(process.env.DURATION_MS || '2000', 10);
const start = Date.now();
let result = 0;
while (Date.now() - start < duration) {
    result += serverLoop();
}

// Prevent dead code elimination
if (result === Infinity) {
    console.log(result);
}
