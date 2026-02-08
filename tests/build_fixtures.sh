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

echo "Verifying .eh_frame sections exist..."
for bin in "$FIXTURE_DIR"/*; do
    if ! readelf -S "$bin" 2>/dev/null | grep -q '.eh_frame'; then
        echo "WARNING: $bin missing .eh_frame section"
    fi
done

echo "Built $(ls "$FIXTURE_DIR" | wc -l) test fixtures in $FIXTURE_DIR"
ls -la "$FIXTURE_DIR"
