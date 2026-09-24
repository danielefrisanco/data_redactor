#!/bin/sh
# Build and run the mm_resolve correctness gate (benchmark/ci_resolve_check.c).
# Checks the overlap resolver against a brute-force oracle over fixed cases and
# seeded random event lists, under -fsanitize=address,undefined. Used by CI and
# runnable locally from the repo root: benchmark/run_resolve_check.sh
#
# POSIX sh (not bash): kept consistent with run_asan_fuzz.sh.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/ext/data_redactor"
BIN="$(mktemp -d)/ci_resolve_check"

CC="${CC:-cc}"

"$CC" -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
   -D_GNU_SOURCE -I"$EXT" \
   -DMATCHER_SRC="\"$EXT/matcher.c\"" \
   "$ROOT/benchmark/ci_resolve_check.c" "$EXT/patterns.c" -o "$BIN"

ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1" \
UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1" \
"$BIN"
