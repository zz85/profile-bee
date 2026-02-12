#!/usr/bin/env bash
# DWARF Correctness Regression Test
#
# Compares profile-bee DWARF unwinding against perf to catch regressions.
# Tests: symbol correctness, stack depth, cross-library unwinding, signal frames.
#
# Usage: sudo ./tests/dwarf_correctness_test.sh [--verbose] [--filter PATTERN]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/bin"
OUTPUT_DIR="$SCRIPT_DIR/output/dwarf-correctness"
PROFILER="${PROFILER:-$PROJECT_DIR/target/release/profile-bee}"

PROFILE_TIME_MS=1500
FREQUENCY=99
TEST_TIMEOUT=15

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
PASSED=0; FAILED=0; SKIPPED=0
VERBOSE=false; FILTER=""
FAILURES=()

for arg in "$@"; do
    case "$arg" in
        --verbose) VERBOSE=true ;;
        *) FILTER="$arg" ;;
    esac
done

if [[ $EUID -ne 0 ]]; then echo -e "${RED}Must run as root${NC}"; exit 1; fi
[[ -x "$PROFILER" ]] || { echo -e "${RED}profile-bee not found at $PROFILER${NC}"; exit 1; }
[[ -d "$FIXTURE_DIR" ]] || { echo "Building fixtures..."; bash "$SCRIPT_DIR/build_fixtures.sh"; }
mkdir -p "$OUTPUT_DIR"

pb_profile() {
    local binary="$1" name="$2"; shift 2
    local out="$OUTPUT_DIR/${name}.collapse"
    timeout "$TEST_TIMEOUT" "$PROFILER" --cmd "$binary" --time "$PROFILE_TIME_MS" \
        --frequency "$FREQUENCY" --collapse "$out" --skip-idle --dwarf true "$@" >/dev/null 2>&1 || true
    [[ -f "$out" ]] && [[ -s "$out" ]] && echo "$out" || echo ""
}

perf_profile() {
    local binary="$1" name="$2"
    local out="$OUTPUT_DIR/${name}.perf.collapse"
    timeout "$TEST_TIMEOUT" perf record -F "$FREQUENCY" -g --call-graph dwarf \
        -o /tmp/_perf_$$.data -- timeout $(( PROFILE_TIME_MS / 1000 + 1 )) "$binary" >/dev/null 2>&1 || true
    if [[ -f /tmp/_perf_$$.data ]]; then
        perf script -i /tmp/_perf_$$.data 2>/dev/null | awk '
            /^[^ ]/ { if (stack != "") print stack " 1"; stack="" }
            /^\t/ { gsub(/^[ \t]+/,""); split($0,p," "); s=p[1]; gsub(/\+0x[0-9a-f]+$/,"",s);
                     if(s!=""&&s!="[unknown]") { stack = (stack=="" ? s : s";"stack) } }
            END { if (stack != "") print stack " 1" }
        ' > "$out" 2>/dev/null
        rm -f /tmp/_perf_$$.data
    fi
    [[ -f "$out" ]] && [[ -s "$out" ]] && echo "$out" || echo ""
}

max_depth() { [[ -f "$1" ]] && awk -F';' '{print NF}' "$1" | sort -rn | head -1 || echo 0; }
has_sym() { [[ -f "$1" ]] && grep -qE "$2" "$1"; }

run_test() {
    local name="$1" func="$2"
    [[ -n "$FILTER" ]] && [[ "$name" != *"$FILTER"* ]] && { SKIPPED=$((SKIPPED+1)); return; }
    printf "  %-55s " "$name"
    local out ec=0; out=$($func 2>&1) || ec=$?
    if [[ $ec -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED+1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "$out" | sed 's/^/    /' | head -5
        FAILED=$((FAILED+1)); FAILURES+=("$name")
    fi
}

# ── Tests ────────────────────────────────────────────────────────────────────

test_basic_symbols() {
    local f; f=$(pb_profile "$FIXTURE_DIR/callstack-no-fp" "t-basic")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    for s in hot function_a function_b function_c main; do
        has_sym "$f" "$s" || { echo "Missing: $s"; return 1; }
    done
}

test_deep_recursion() {
    local f; f=$(pb_profile "$FIXTURE_DIR/deep-no-fp" "t-deep")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    has_sym "$f" "leaf" || { echo "Missing: leaf"; return 1; }
    has_sym "$f" "recurse" || { echo "Missing: recurse"; return 1; }
    local d; d=$(max_depth "$f")
    [[ "$d" -ge 18 ]] || { echo "Depth $d < 18 (20-level recursion should produce >=18 frames)"; return 1; }
}

test_shared_lib() {
    local f; f=$(pb_profile "$FIXTURE_DIR/sharedlib-no-fp" "t-sharedlib")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    for s in lib_hot caller_a main; do
        has_sym "$f" "$s" || { echo "Missing: $s"; return 1; }
    done
}

test_pie() {
    local f; f=$(pb_profile "$FIXTURE_DIR/callstack-pie-no-fp" "t-pie")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    for s in hot function_a main; do has_sym "$f" "$s" || { echo "Missing: $s"; return 1; }; done
}

test_multithread() {
    local f; f=$(pb_profile "$FIXTURE_DIR/multithread-no-fp" "t-mt")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    has_sym "$f" "hot_a|hot_b" || { echo "Missing thread functions"; return 1; }
}

test_rust() {
    local f; f=$(pb_profile "$FIXTURE_DIR/rust-no-fp" "t-rust")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    has_sym "$f" "hot_loop" || { echo "Missing: hot_loop"; return 1; }
    has_sym "$f" "main" || { echo "Missing: main"; return 1; }
}

test_indirect() {
    local f; f=$(pb_profile "$FIXTURE_DIR/indirect-no-fp" "t-indirect")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    has_sym "$f" "leaf_work" || { echo "Missing: leaf_work"; return 1; }
    has_sym "$f" "dispatch" || { echo "Missing: dispatch"; return 1; }
    has_sym "$f" "main" || { echo "Missing: main"; return 1; }
}

test_signal() {
    local f; f=$(pb_profile "$FIXTURE_DIR/signal-no-fp" "t-signal")
    [[ -z "$f" ]] && { echo "No output"; return 1; }
    has_sym "$f" "compute|handler" || { echo "Missing: compute or handler"; return 1; }
    has_sym "$f" "main" || { echo "Missing: main"; return 1; }
}

test_depth_vs_perf() {
    local pb perf_f; pb=$(pb_profile "$FIXTURE_DIR/callstack-no-fp" "t-cmp-depth")
    perf_f=$(perf_profile "$FIXTURE_DIR/callstack-no-fp" "t-cmp-depth")
    [[ -z "$pb" ]] && { echo "profile-bee: no output"; return 1; }
    [[ -z "$perf_f" ]] && { echo "perf: no output (skipping comparison)"; return 0; }
    local pd pp; pd=$(max_depth "$pb"); pp=$(max_depth "$perf_f")
    [[ "$pd" -ge $(( pp - 2 )) ]] || { echo "pb depth=$pd << perf depth=$pp"; return 1; }
}

test_dwarf_improves_nofp() {
    local nofp dwarf
    # Profile without DWARF
    local nofp_out="$OUTPUT_DIR/t-improve-nofp.collapse"
    timeout "$TEST_TIMEOUT" "$PROFILER" --cmd "$FIXTURE_DIR/callstack-no-fp" --time "$PROFILE_TIME_MS" \
        --frequency "$FREQUENCY" --collapse "$nofp_out" --skip-idle --dwarf false >/dev/null 2>&1 || true
    dwarf=$(pb_profile "$FIXTURE_DIR/callstack-no-fp" "t-improve-dwarf")
    [[ -z "$dwarf" ]] && { echo "DWARF: no output"; return 1; }
    [[ ! -f "$nofp_out" ]] && { echo "no-DWARF: no output"; return 1; }
    local nd dd; nd=$(max_depth "$nofp_out"); dd=$(max_depth "$dwarf")
    [[ "$dd" -gt "$nd" ]] || { echo "DWARF depth=$dd not > no-DWARF depth=$nd"; return 1; }
}

# ── Run ──────────────────────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       DWARF Correctness Regression Tests                  ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Profiler: $PROFILER"
echo "║  Time: ${PROFILE_TIME_MS}ms @ ${FREQUENCY}Hz"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "── Symbol Correctness ──"
run_test "Basic callstack symbols"              test_basic_symbols
run_test "Deep recursion (>=18 frames)"         test_deep_recursion
run_test "Shared library cross-.so"             test_shared_lib
run_test "PIE binary"                           test_pie
run_test "Multi-threaded"                       test_multithread
run_test "Rust binary (O2, no-FP)"              test_rust
run_test "Indirect calls (function pointers)"   test_indirect
run_test "Signal handler"                       test_signal
echo ""

echo "── Comparison vs perf ──"
run_test "Depth within 2 frames of perf"        test_depth_vs_perf
run_test "DWARF improves no-FP stacks"          test_dwarf_improves_nofp
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}Passed: $PASSED${NC}  ${RED}Failed: $FAILED${NC}  Skipped: $SKIPPED"
[[ ${#FAILURES[@]} -gt 0 ]] && { echo -e "\n  ${RED}Failures:${NC}"; for f in "${FAILURES[@]}"; do echo "    - $f"; done; }
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Output: $OUTPUT_DIR/"
[[ $FAILED -gt 0 ]] && exit 1 || exit 0
