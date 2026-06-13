#!/usr/bin/env bash
# Build and run the zero-allocation steady-state gate (benchmark/ci_alloc_gate.c).
# Exits non-zero if the engine's hot path allocates in steady state. Used by CI
# and runnable locally from the repo root: benchmark/run_alloc_gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT="$ROOT/ext/data_redactor"
BIN="$(mktemp -d)/ci_alloc_gate"

cc -O2 -D_GNU_SOURCE -I"$EXT" \
   -DMATCHER_SRC="\"$EXT/matcher.c\"" \
   "$ROOT/benchmark/ci_alloc_gate.c" "$EXT/patterns.c" -ldl -o "$BIN"

"$BIN"
