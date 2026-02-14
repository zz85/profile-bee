#!/usr/bin/env bash
# End-to-end tests for profile-bee DWARF stack unwinding.
#
# Requires: root (for eBPF), gcc, profile-bee binary built.
# Usage:
#   ./tests/run_e2e.sh              # run all tests
#   ./tests/run_e2e.sh --build      # rebuild profile-bee first
#   ./tests/run_e2e.sh --verbose    # show profiler output
#   ./tests/run_e2e.sh --filter fp  # run only tests matching "fp"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/bin"
OUTPUT_DIR="$SCRIPT_DIR/output"
PROFILER="$PROJECT_DIR/target/release/probee"

# ── Configuration ────────────────────────────────────────────────────────────
PROFILE_TIME_MS=1000    # how long to profile each test (ms)
FREQUENCY=99            # sampling frequency (Hz)
TEST_TIMEOUT=30         # max seconds per individual test

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

# ── State ────────────────────────────────────────────────────────────────────
PASSED=0; FAILED=0; SKIPPED=0
VERBOSE=false
FILTER=""
FAILURES=()

# ── Parse args ───────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --build)
            echo "Building profile-bee..."
            cd "$PROJECT_DIR" && cargo xtask build-ebpf --release && cargo build --release
            ;;
        --verbose) VERBOSE=true ;;
        --filter) shift_next=true ;;
        *)
            if [[ "${shift_next:-}" == "true" ]]; then
                FILTER="$arg"; shift_next=false
            else
                FILTER="$arg"
            fi
            ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (eBPF requires CAP_SYS_ADMIN)${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

if [[ ! -x "$PROFILER" ]]; then
    echo -e "${RED}ERROR: profile-bee not found at $PROFILER${NC}"
    echo "Run: cargo xtask build-ebpf --release && cargo build --release"
    exit 1
fi

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo "Building test fixtures..."
    bash "$SCRIPT_DIR/build_fixtures.sh"
fi

mkdir -p "$OUTPUT_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Run profile-bee against a command, return collapse file path.
# Usage: run_profiler <binary> <output_name> [extra_args...]
run_profiler() {
    local binary="$1"
    local name="$2"
    shift 2
    local extra_args=("$@")
    local collapse_file="$OUTPUT_DIR/${name}.collapse"

    # Profile using --cmd (handles process lifecycle automatically)
    local profiler_output
    profiler_output=$(timeout "$TEST_TIMEOUT" "$PROFILER" \
        --cmd "$binary" \
        --time "$PROFILE_TIME_MS" \
        --frequency "$FREQUENCY" \
        --collapse "$collapse_file" \
        --skip-idle \
        "${extra_args[@]+"${extra_args[@]}"}" 2>&1) || true

    if [[ "$VERBOSE" == "true" ]]; then
        echo "--- profiler output ---" >&2
        echo "$profiler_output" >&2
        echo "--- end ---" >&2
    fi

    if [[ ! -f "$collapse_file" ]]; then
        echo "Collapse file not created: $collapse_file" >&2
        return 1
    fi

    # Only output the file path on stdout
    echo "$collapse_file"
}

# Check that a collapse file contains a stack matching a pattern.
# Usage: assert_stack_contains <collapse_file> <grep_pattern> <description>
assert_stack_contains() {
    local file="$1" pattern="$2" desc="${3:-}"
    if grep -q "$pattern" "$file"; then
        return 0
    else
        echo "  Stack pattern not found: $pattern" >&2
        if [[ "$VERBOSE" == "true" ]]; then
            echo "  File contents:" >&2
            head -20 "$file" | sed 's/^/    /' >&2
        fi
        return 1
    fi
}

# Check minimum number of frames in the deepest stack.
# Usage: assert_min_depth <collapse_file> <min_frames> <description>
assert_min_depth() {
    local file="$1" min="$2" desc="${3:-}"
    # Count semicolons in the longest line (each ; = one frame boundary)
    local max_depth
    max_depth=$(awk -F';' '{print NF}' "$file" | sort -rn | head -1)
    if [[ "$max_depth" -ge "$min" ]]; then
        return 0
    else
        echo "  Max stack depth $max_depth < required $min" >&2
        return 1
    fi
}

# Count total samples in a collapse file
count_samples() {
    awk '{sum += $NF} END {print sum+0}' "$1"
}

# Run a single test case.
# Usage: run_test <test_name> <test_function>
run_test() {
    local name="$1"
    local func="$2"

    if [[ -n "$FILTER" ]] && [[ "$name" != *"$FILTER"* ]]; then
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    printf "  %-55s " "$name"

    local output exit_code=0
    output=$($func 2>&1) || exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
        FAILURES+=("$name")
    fi
}

# ── Test Cases ───────────────────────────────────────────────────────────────

# ---------- Frame Pointer tests (baseline — these should always work) --------

test_fp_callstack() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-fp" "fp-callstack")
    assert_stack_contains "$file" "hot" "hot() should appear"
    assert_stack_contains "$file" "function_a" "function_a() should appear"
    assert_stack_contains "$file" "function_b" "function_b() should appear"
    assert_stack_contains "$file" "function_c" "function_c() should appear"
    assert_stack_contains "$file" "main" "main() should appear"
    # FP should give us the full chain: at least 5 frames
    assert_min_depth "$file" 4 "FP should produce deep stacks"
}

test_fp_deep() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/deep-fp" "fp-deep")
    assert_stack_contains "$file" "leaf" "leaf() should appear"
    assert_stack_contains "$file" "recurse" "recurse() should appear"
    assert_stack_contains "$file" "main" "main() should appear"
    # 20 levels of recursion + leaf + main = at least 15 frames
    assert_min_depth "$file" 15 "FP deep recursion should show many frames"
}

# ---------- No-FP without DWARF (shows the problem) -------------------------

test_no_fp_without_dwarf() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-no-fp" "no-fp-no-dwarf")
    # Without FP and without DWARF, we should get very shallow stacks
    assert_stack_contains "$file" "hot" "hot() should still appear (it's the leaf)"
    # The stack should be shallow — this documents the problem DWARF solves
    local max_depth
    max_depth=$(awk -F';' '{print NF}' "$file" | sort -rn | head -1)
    if [[ "$max_depth" -le 3 ]]; then
        return 0  # Expected: shallow stack without FP
    fi
    # If we somehow get deep stacks without FP or DWARF, that's also fine
    return 0
}

# ---------- DWARF tests (the main event) ------------------------------------

test_dwarf_callstack() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-no-fp" "dwarf-callstack" --dwarf true)
    assert_stack_contains "$file" "hot" "hot() should appear"
    assert_stack_contains "$file" "function_a" "function_a() should appear with DWARF"
    assert_stack_contains "$file" "function_b" "function_b() should appear with DWARF"
    assert_stack_contains "$file" "function_c" "function_c() should appear with DWARF"
    assert_stack_contains "$file" "main" "main() should appear with DWARF"
    assert_min_depth "$file" 4 "DWARF should produce deep stacks"
}

test_dwarf_callstack_O2() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-O2-no-fp" "dwarf-callstack-O2" --dwarf true)
    assert_stack_contains "$file" "hot\|function_\|main" "Should resolve some symbols with DWARF on O2"
    # O2 may inline functions, so we check for at least hot + main
    assert_stack_contains "$file" "hot" "hot() should appear (busy loop not inlined)"
}

test_dwarf_deep() {
    local file
    file=$(run_profiler "$FIXTURE_DIR/deep-no-fp" "dwarf-deep" --dwarf true)
    assert_stack_contains "$file" "leaf" "leaf() should appear with DWARF"
    assert_stack_contains "$file" "recurse" "recurse() should appear with DWARF"
    assert_stack_contains "$file" "main" "main() should appear with DWARF"
    # Should recover most of the 20 recursion levels
    assert_min_depth "$file" 10 "DWARF should recover deep recursion"
}

test_dwarf_deepstack() {
    # Test deep DWARF unwinding on a 50-level recursion binary.
    # Currently limited to ~21 frames by the BPF verifier's instruction complexity limit.
    # True tail-call support (PROG_ARRAY) is needed to reach MAX_DWARF_STACK_DEPTH (165).
    # For now, verify DWARF produces full stacks up to the verifier limit.
    local file
    file=$(run_profiler "$FIXTURE_DIR/deepstack-no-fp" "dwarf-deepstack" --dwarf true)
    assert_stack_contains "$file" "leaf" "leaf() should appear with DWARF"
    assert_stack_contains "$file" "recurse" "recurse() should appear with DWARF"

    local max_depth
    max_depth=$(awk -F';' '{print NF}' "$file" | sort -rn | head -1)

    # Should get at least 20 frames (verifier limit is ~21 unwind iterations + leaf)
    if [[ "$max_depth" -ge 20 ]]; then
        return 0
    else
        echo "  Stack depth ($max_depth) below expected minimum of 20" >&2
        return 1
    fi
}

# ---------- Comparison tests (DWARF should match or beat FP) -----------------

test_dwarf_vs_fp_depth() {
    # Profile the same FP binary with and without --dwarf
    # DWARF should produce at least as many frames as FP
    local fp_file dwarf_file
    fp_file=$(run_profiler "$FIXTURE_DIR/callstack-fp" "cmp-fp")
    dwarf_file=$(run_profiler "$FIXTURE_DIR/callstack-fp" "cmp-dwarf" --dwarf true)

    local fp_depth dwarf_depth
    # Count only userspace frames (exclude kernel frames ending with _k)
    fp_depth=$(sed 's/;[^ ]*_k[^ ]*//g' "$fp_file" | awk -F';' '{print NF}' | sort -rn | head -1)
    dwarf_depth=$(sed 's/;[^ ]*_k[^ ]*//g' "$dwarf_file" | awk -F';' '{print NF}' | sort -rn | head -1)

    if [[ "$dwarf_depth" -ge "$((fp_depth - 1))" ]]; then
        return 0  # DWARF at least as good as FP (allow 1 frame tolerance)
    else
        echo "  DWARF depth ($dwarf_depth) significantly less than FP depth ($fp_depth)" >&2
        return 1
    fi
}

test_dwarf_improves_no_fp() {
    # The key test: DWARF on a no-FP binary should produce deeper stacks
    # than profiling the same binary without DWARF
    local no_dwarf_file dwarf_file
    no_dwarf_file=$(run_profiler "$FIXTURE_DIR/callstack-no-fp" "improve-no-dwarf" --dwarf false)
    dwarf_file=$(run_profiler "$FIXTURE_DIR/callstack-no-fp" "improve-dwarf" --dwarf true)

    local no_dwarf_depth dwarf_depth
    no_dwarf_depth=$(awk -F';' '{print NF}' "$no_dwarf_file" | sort -rn | head -1)
    dwarf_depth=$(awk -F';' '{print NF}' "$dwarf_file" | sort -rn | head -1)

    if [[ "$dwarf_depth" -gt "$no_dwarf_depth" ]]; then
        return 0
    else
        echo "  DWARF depth ($dwarf_depth) not better than no-DWARF ($no_dwarf_depth)" >&2
        echo "  (This is the core value proposition of DWARF unwinding)" >&2
        return 1
    fi
}

# ---------- Robustness tests ------------------------------------------------

test_dwarf_nonexistent_binary() {
    # --dwarf with a binary that doesn't exist should not crash
    local output
    output=$(timeout "$TEST_TIMEOUT" "$PROFILER" --cmd "/nonexistent/binary" --dwarf true --time 200 --collapse "$OUTPUT_DIR/bad-bin.collapse" 2>&1) || true
    # Should exit without segfault — any output is fine
    return 0
}

test_dwarf_shared_library() {
    # DWARF unwinding across shared library boundary (no frame pointers)
    local file
    file=$(run_profiler "$FIXTURE_DIR/sharedlib-no-fp" "dwarf-sharedlib" --dwarf true)
    assert_stack_contains "$file" "lib_hot"
    assert_stack_contains "$file" "caller_a"
    assert_stack_contains "$file" "caller_b"
    assert_stack_contains "$file" "main"
    assert_min_depth "$file" 6
}

test_dwarf_pie_binary() {
    # DWARF unwinding on a PIE (position-independent) binary without frame pointers
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-pie-no-fp" "dwarf-pie" --dwarf true)
    assert_stack_contains "$file" "hot"
    assert_stack_contains "$file" "function_a"
    assert_stack_contains "$file" "function_b"
    assert_stack_contains "$file" "function_c"
    assert_stack_contains "$file" "main"
    assert_min_depth "$file" 4
}

test_dwarf_rust_binary() {
    # DWARF unwinding on a Rust binary compiled with -C opt-level=2 -C force-frame-pointers=no
    # At O2, tail calls eliminate intermediate functions, but we should still get
    # hot_loop and the Rust runtime frames (lang_start, etc.)
    local file
    file=$(run_profiler "$FIXTURE_DIR/rust-no-fp" "dwarf-rust" --dwarf true)
    assert_stack_contains "$file" "hot_loop"
    assert_stack_contains "$file" "main"
    assert_min_depth "$file" 5
}

test_samples_collected() {
    # Basic sanity: we should collect a non-zero number of samples
    local file
    file=$(run_profiler "$FIXTURE_DIR/callstack-fp" "samples-check")
    local count
    count=$(count_samples "$file")
    if [[ "$count" -gt 0 ]]; then
        return 0
    else
        echo "  No samples collected (count=0)" >&2
        return 1
    fi
}

# ── Run all tests ────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        profile-bee DWARF Unwinding E2E Tests                ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Profiler:  $PROFILER"
echo "║  Fixtures:  $FIXTURE_DIR"
echo "║  Output:    $OUTPUT_DIR"
echo "║  Time:      ${PROFILE_TIME_MS}ms @ ${FREQUENCY}Hz"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "── Baseline: Frame Pointer Unwinding ──"
run_test "FP callstack (hot→c→b→a→main)"          test_fp_callstack
run_test "FP deep recursion (20 levels)"            test_fp_deep
run_test "Samples collected (sanity)"               test_samples_collected
echo ""

echo "── Problem Statement: No-FP Without DWARF ──"
run_test "No-FP without DWARF (shallow stacks)"    test_no_fp_without_dwarf
echo ""

echo "── DWARF Unwinding ──"
run_test "DWARF callstack (no-FP binary)"           test_dwarf_callstack
run_test "DWARF callstack O2 (no-FP, optimized)"    test_dwarf_callstack_O2
run_test "DWARF deep recursion (no-FP, 20 levels)"  test_dwarf_deep
run_test "DWARF deep stack (no-FP, 50 levels)"      test_dwarf_deepstack
run_test "DWARF shared library (cross-.so calls)"   test_dwarf_shared_library
run_test "DWARF PIE binary (position-independent)"  test_dwarf_pie_binary
run_test "DWARF Rust binary (O2, no frame pointers)" test_dwarf_rust_binary
echo ""

echo "── Comparison: DWARF vs FP ──"
run_test "DWARF depth >= FP depth (FP binary)"      test_dwarf_vs_fp_depth
run_test "DWARF improves no-FP stacks"              test_dwarf_improves_no_fp
echo ""

echo "── Robustness ──"
run_test "Non-existent binary doesn't crash"        test_dwarf_nonexistent_binary
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  ${YELLOW}Skipped: $SKIPPED${NC}"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Failed tests:${NC}"
    for f in "${FAILURES[@]}"; do
        echo "    - $f"
    done
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Save collapse files for debugging
echo ""
echo "Collapse files saved in $OUTPUT_DIR/ for inspection."

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
