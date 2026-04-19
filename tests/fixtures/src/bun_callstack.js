// Bun test fixture for profile-bee E2E tests.
// Creates a CPU-intensive call stack with known function names.
//
// Bun uses JavaScriptCore (not V8). When BUN_JSC_useJITDump=1 is set,
// JSC writes /tmp/jit-<pid>.dump with address-to-symbol mappings for
// JIT-compiled functions. profile-bee auto-injects this env var when
// spawning Bun via `probee -- bun <script>`.
//
// The warmup phase ensures functions are JIT-compiled (and recorded in
// the JITDump file) before the main profiling window.

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

// Warmup: call enough times to trigger JIT compilation in JSC.
// JSC's DFG JIT compiles after ~100 invocations, FTL after ~1000.
for (let i = 0; i < 100; i++) {
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
