#!/bin/sh
# Build and run the ASan/UBSan memory-safety gate (benchmark/ci_asan_fuzz.c).
# Drives the standalone matcher engine over an adversarial corpus + a seeded
# fuzz loop under -fsanitize=address,undefined; exits non-zero on any OOB read,
# use-after-free, or UB. Used by CI and runnable locally from the repo root:
# benchmark/run_asan_fuzz.sh
#
# POSIX sh (not bash): kept consistent with run_alloc_gate.sh.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/ext/data_redactor"
BIN="$(mktemp -d)/ci_asan_fuzz"

CC="${CC:-cc}"

# -fno-sanitize-recover=all: turn every UBSan finding into an abort (hard gate),
# not a logged-and-continue warning. -O1 -g keeps stack traces readable.
"$CC" -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
   -D_GNU_SOURCE -I"$EXT" \
   -DMATCHER_SRC="\"$EXT/matcher.c\"" \
   "$ROOT/benchmark/ci_asan_fuzz.c" "$EXT/patterns.c" -o "$BIN"

# halt_on_error=1: abort on the first ASan finding so the failing input is the
# last thing the engine touched (bisectable). abort_on_error=1: non-zero exit.
ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1" \
UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1" \
"$BIN"
