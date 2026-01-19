#!/bin/bash
# Profile-Guided Optimization build script for Moloch
#
# This script performs a complete PGO build cycle:
# 1. Build with instrumentation
# 2. Run benchmarks to collect profiles
# 3. Merge profile data
# 4. Rebuild with optimized profiles
#
# Usage:
#   ./scripts/pgo-build.sh [--quick]   # Quick mode uses fewer benchmark iterations
#   ./scripts/pgo-build.sh [--full]    # Full mode for maximum optimization

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PGO_DATA_DIR="/tmp/moloch-pgo-data"
MERGED_PROFILE="$PGO_DATA_DIR/merged.profdata"

# Parse arguments
QUICK_MODE=false
for arg in "$@"; do
    case $arg in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --full)
            QUICK_MODE=false
            shift
            ;;
    esac
done

echo "=== Moloch PGO Build ==="
echo "Project directory: $PROJECT_DIR"
echo "Profile data directory: $PGO_DATA_DIR"
echo "Quick mode: $QUICK_MODE"
echo ""

# Clean up previous profile data
rm -rf "$PGO_DATA_DIR"
mkdir -p "$PGO_DATA_DIR"

cd "$PROJECT_DIR"

# Step 1: Build with instrumentation
echo "=== Step 1: Building with PGO instrumentation ==="
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR" cargo build --profile pgo-generate -p moloch-bench

# Step 2: Run benchmarks to collect profiles
echo ""
echo "=== Step 2: Running benchmarks to collect profiles ==="

if [ "$QUICK_MODE" = true ]; then
    # Quick mode: fewer samples
    BENCH_ARGS="--sample-size 10 --warm-up-time 1"
else
    # Full mode: more comprehensive profiling
    BENCH_ARGS="--sample-size 50"
fi

# Run core benchmarks (most important for optimization)
echo "Running core benchmarks..."
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR" cargo bench --profile pgo-generate --bench core_benchmarks -- $BENCH_ARGS || true

# Run MMR benchmarks
echo "Running MMR benchmarks..."
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR" cargo bench --profile pgo-generate --bench mmr_benchmarks -- $BENCH_ARGS || true

# Run mempool benchmarks
echo "Running mempool benchmarks..."
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR" cargo bench --profile pgo-generate --bench mempool_benchmarks -- $BENCH_ARGS || true

# Step 3: Merge profile data
echo ""
echo "=== Step 3: Merging profile data ==="

# Find llvm-profdata (try multiple locations)
LLVM_PROFDATA=""
for cmd in llvm-profdata llvm-profdata-17 llvm-profdata-16 llvm-profdata-15 llvm-profdata-14; do
    if command -v "$cmd" &> /dev/null; then
        LLVM_PROFDATA="$cmd"
        break
    fi
done

if [ -z "$LLVM_PROFDATA" ]; then
    # Try to find in common installation paths
    for path in /usr/lib/llvm-*/bin/llvm-profdata; do
        if [ -x "$path" ]; then
            LLVM_PROFDATA="$path"
            break
        fi
    done
fi

if [ -z "$LLVM_PROFDATA" ]; then
    echo "Error: llvm-profdata not found. Install LLVM tools."
    echo "  Ubuntu/Debian: sudo apt install llvm"
    echo "  Fedora: sudo dnf install llvm"
    echo "  macOS: brew install llvm"
    exit 1
fi

echo "Using: $LLVM_PROFDATA"

# Count profile files
PROFILE_COUNT=$(find "$PGO_DATA_DIR" -name "*.profraw" | wc -l)
echo "Found $PROFILE_COUNT profile files"

if [ "$PROFILE_COUNT" -eq 0 ]; then
    echo "Error: No profile data collected. Benchmarks may have failed."
    exit 1
fi

# Merge profiles
$LLVM_PROFDATA merge -o "$MERGED_PROFILE" "$PGO_DATA_DIR"/*.profraw
echo "Merged profile: $MERGED_PROFILE"
ls -lh "$MERGED_PROFILE"

# Step 4: Rebuild with PGO
echo ""
echo "=== Step 4: Rebuilding with PGO optimization ==="
RUSTFLAGS="-Cprofile-use=$MERGED_PROFILE -Cllvm-args=-pgo-warn-missing-function" cargo build --profile pgo-use

echo ""
echo "=== PGO Build Complete ==="
echo ""
echo "Optimized binaries are in: target/pgo-use/"
echo ""
echo "To run optimized benchmarks:"
echo "  cargo bench --profile pgo-use"
echo ""
echo "Profile data saved in: $PGO_DATA_DIR"
echo "You can delete this after verifying the build."
