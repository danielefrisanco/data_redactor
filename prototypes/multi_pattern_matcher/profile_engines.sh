#!/usr/bin/env bash
#
# profile_engines.sh — Callgrind instruction attribution for the three engines
# the paper §5.1 compares: the glibc regexec incumbent, plain Onigmo, and the
# shipped v19 lazy-DFA engine. Standalone: builds its own driver binaries from
# profile_driver.c and does not touch the gem, the existing benchmark Makefile,
# or any existing prototype source (it only compiles against them, read-only).
#
# Callgrind counts instructions executed per function *exactly* (no sampling), so
# the numbers are deterministic and reproducible across runs and machines — which
# is what we want for a paper, and what perf cannot give here (hardware counters
# are blocked by kernel.perf_event_paranoid on the author's machine). We report
# instruction reads (Ir), not cycles.
#
# Outputs, written to paper/data/:
#   profile_<engine>.txt    full callgrind_annotate dump (per-function Ir)
#   profile_summary.csv     engine,category,ir,pct  (parsed by gen_profile_table.py)
#
# Usage: ./profile_engines.sh [ITERS]   (ITERS scans per run; default 1 — exact)

set -euo pipefail

ITERS="${1:-1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$(cd "$HERE/../../paper/data" && pwd)"
CC="${CC:-cc}"
CFLAGS="-O2 -std=c99 -Wall"
ONIG_CFLAGS="$(pkg-config --cflags oniguruma 2>/dev/null || echo "-I/usr/include")"

cd "$HERE"

echo "==> Generating pattern table (read-only from gem source)"
ruby gen_patterns.rb > patterns_generated.h

echo "==> Building profiling drivers"
$CC $CFLAGS -DENGINE_GLIBC -o profile_glibc  profile_driver.c
$CC $CFLAGS -DENGINE_V19   -o profile_v19    profile_driver.c
$CC $CFLAGS $ONIG_CFLAGS -DENGINE_ONIG -o profile_onigmo profile_driver.c -lonig

run_one() {
    local engine="$1" bin="$2"
    local cg="callgrind.out.${engine}"
    echo "==> Profiling ${engine} (callgrind, ${ITERS} scan(s))"
    rm -f "$cg"
    valgrind --tool=callgrind --callgrind-out-file="$cg" \
             --dump-instr=no --collect-jumps=no \
             "./$bin" "$ITERS" 2> "callgrind.log.${engine}"
    # Full per-function Ir dump (threshold 100 = include everything that rounds
    # to a contribution; we re-bucket in the summary below).
    callgrind_annotate --threshold=100 --auto=no "$cg" > "${OUT_DIR}/profile_${engine}.txt"
}

run_one glibc  profile_glibc
run_one v19    profile_v19
run_one onigmo profile_onigmo

echo "==> Building category summary -> ${OUT_DIR}/profile_summary.csv"
python3 "$HERE/profile_categorize.py" "$OUT_DIR" glibc v19 onigmo

echo "==> Done. Per-function dumps in ${OUT_DIR}/profile_<engine>.txt"
echo "    Summary: ${OUT_DIR}/profile_summary.csv"
