#!/usr/bin/env bash
# Build test binaries in all frame-pointer/optimization variants.
# Usage: ./tests/build_fixtures.sh [--clean]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/bin"
SRC_DIR="$SCRIPT_DIR/fixtures/src"

if [[ "${1:-}" == "--clean" ]]; then
    rm -rf "$FIXTURE_DIR"
    echo "Cleaned $FIXTURE_DIR"
    exit 0
fi

mkdir -p "$FIXTURE_DIR"

# ── C test programs ──────────────────────────────────────────────────────────

echo "Building C test fixtures..."

# callstack: main → function_a → function_b → function_c → hot
# Expected stack (bottom-up): hot;function_c;function_b;function_a;main
gcc "$SRC_DIR/callstack.c" -g -fno-omit-frame-pointer    -o "$FIXTURE_DIR/callstack-fp"
gcc "$SRC_DIR/callstack.c" -g -fomit-frame-pointer        -o "$FIXTURE_DIR/callstack-no-fp"
gcc "$SRC_DIR/callstack.c" -O2 -g -fno-omit-frame-pointer -o "$FIXTURE_DIR/callstack-O2-fp"
gcc "$SRC_DIR/callstack.c" -O2 -g -fomit-frame-pointer    -o "$FIXTURE_DIR/callstack-O2-no-fp"

# deep: main → recurse(20) — tests stack depth
gcc "$SRC_DIR/deep.c" -g -fno-omit-frame-pointer -o "$FIXTURE_DIR/deep-fp"
gcc "$SRC_DIR/deep.c" -g -fomit-frame-pointer    -o "$FIXTURE_DIR/deep-no-fp"

# PIE: position-independent executable
gcc "$SRC_DIR/callstack.c" -g -fomit-frame-pointer -pie -fPIE -o "$FIXTURE_DIR/callstack-pie-no-fp"

# shared library: cross-library call chain
gcc -shared -fPIC -g -fomit-frame-pointer "$SRC_DIR/libhotlib.c" -o "$FIXTURE_DIR/libhotlib.so"
gcc "$SRC_DIR/sharedlib.c" -g -fomit-frame-pointer -L"$FIXTURE_DIR" -lhotlib -Wl,-rpath,'$ORIGIN' -o "$FIXTURE_DIR/sharedlib-no-fp"

# ── Rust test programs ────────────────────────────────────────────────────────

echo "Building Rust test fixtures..."

# rust_callstack: main → rust_func_a → rust_func_b → rust_func_c → hot_loop
rustc -C opt-level=2 -C force-frame-pointers=no -g "$SRC_DIR/rust_callstack.rs" -o "$FIXTURE_DIR/rust-no-fp"
rustc -C opt-level=2 -C force-frame-pointers=yes -g "$SRC_DIR/rust_callstack.rs" -o "$FIXTURE_DIR/rust-fp"

echo "Verifying .eh_frame sections exist..."
for bin in "$FIXTURE_DIR"/*; do
    if ! readelf -S "$bin" 2>/dev/null | grep -q '.eh_frame'; then
        echo "WARNING: $bin missing .eh_frame section"
    fi
done

echo "Built $(ls "$FIXTURE_DIR" | wc -l) test fixtures in $FIXTURE_DIR"
ls -la "$FIXTURE_DIR"
