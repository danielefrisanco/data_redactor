# Standalone build for the multi-matcher prototype. NOT wired into the
# gem's extconf.rb — this is a one-off experiment.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -fPIC
LDFLAGS ?=

# Option A: standalone libonig-dev (apt install libonig-dev).
# Uses system Oniguruma — no Ruby VM required.
ONIG_CFLAGS  = $(shell pkg-config --cflags oniguruma 2>/dev/null || echo "-I/usr/include")
ONIG_LDFLAGS = -lonig

PCRE2_CFLAGS  = -DPCRE2_CODE_UNIT_WIDTH=8 $(shell pkg-config --cflags libpcre2-8 2>/dev/null)
PCRE2_LDFLAGS = -lpcre2-8

.PHONY: all clean smoke smoke2 smoke3 smoke4 smoke5 smoke6 smoke7 smoke9 smoke10 smoke11 smoke12 smoke14 smoke15 smoke16 smoke17 generate

all: matcher matcher.so matcher2 matcher2.so matcher3 matcher3.so matcher4 matcher4.so matcher5 matcher5.so matcher7 matcher7.so matcher9 matcher9.so matcher10 matcher10.so

# Option B generated header (always regenerate from gem source).
generate: gen_patterns.rb
	ruby gen_patterns.rb > patterns_generated.h

patterns_generated.h: gen_patterns.rb
	ruby gen_patterns.rb > patterns_generated.h

# Prototype v1 — 10 patterns, glibc regexec.
matcher: matcher.c matcher.h
	$(CC) $(CFLAGS) -DMM_MAIN -o $@ matcher.c $(LDFLAGS)

matcher.so: matcher.c matcher.h
	$(CC) $(CFLAGS) -shared -o $@ matcher.c $(LDFLAGS)

# Prototype v2 — 88 patterns, glibc regexec.
matcher2: matcher2.c matcher2.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM88_MAIN -o $@ matcher2.c $(LDFLAGS)

matcher2.so: matcher2.c matcher2.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher2.c $(LDFLAGS)

smoke: matcher
	./matcher

smoke2: matcher2
	./matcher2

# Prototype v3 — 88 patterns, Onigmo (Option A).
matcher3: matcher3.c matcher3.h patterns_generated.h
	$(CC) $(CFLAGS) $(ONIG_CFLAGS) -DMM3_MAIN -o $@ matcher3.c $(LDFLAGS) $(ONIG_LDFLAGS)

matcher3.so: matcher3.c matcher3.h patterns_generated.h
	$(CC) $(CFLAGS) $(ONIG_CFLAGS) -shared -o $@ matcher3.c $(LDFLAGS) $(ONIG_LDFLAGS)

smoke3: matcher3
	./matcher3

# Prototype v4 — 88 patterns, Thompson NFA → DFA, zero dependencies (Option D).
matcher4: matcher4.c matcher4.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM4_MAIN -o $@ matcher4.c $(LDFLAGS)

matcher4.so: matcher4.c matcher4.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher4.c $(LDFLAGS)

smoke4: matcher4
	./matcher4

# Prototype v5 — 88 patterns, AC + Onigmo + Boyer-Moore infix pre-filter.
matcher5: matcher5.c matcher5.h patterns_generated.h
	$(CC) $(CFLAGS) $(ONIG_CFLAGS) -DMM5_MAIN -o $@ matcher5.c $(LDFLAGS) $(ONIG_LDFLAGS)

matcher5.so: matcher5.c matcher5.h patterns_generated.h
	$(CC) $(CFLAGS) $(ONIG_CFLAGS) -shared -o $@ matcher5.c $(LDFLAGS) $(ONIG_LDFLAGS)

smoke5: matcher5
	./matcher5

# Prototype v6 — 88 patterns, AC + BM infix filter + glibc regexec (no Onigmo).
matcher6: matcher6.c matcher6.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM6_MAIN -o $@ matcher6.c $(LDFLAGS)

matcher6.so: matcher6.c matcher6.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher6.c $(LDFLAGS)

smoke6: matcher6
	./matcher6

# Prototype v7 — 88 patterns, AC + BM + PCRE2 (interpreter and JIT).
matcher7: matcher7.c matcher7.h patterns_generated.h
	$(CC) $(CFLAGS) $(PCRE2_CFLAGS) -DMM7_MAIN -o $@ matcher7.c $(LDFLAGS) $(PCRE2_LDFLAGS)

matcher7.so: matcher7.c matcher7.h patterns_generated.h
	$(CC) $(CFLAGS) $(PCRE2_CFLAGS) -shared -o $@ matcher7.c $(LDFLAGS) $(PCRE2_LDFLAGS)

smoke7: matcher7
	./matcher7

# Prototype v7_plain — 88 patterns, plain PCRE2 sequential (no AC, no BM).
matcher7_plain: matcher7_plain.c matcher7_plain.h patterns_generated.h
	$(CC) $(CFLAGS) $(PCRE2_CFLAGS) -DMM7P_MAIN -o $@ matcher7_plain.c $(LDFLAGS) $(PCRE2_LDFLAGS)

matcher7_plain.so: matcher7_plain.c matcher7_plain.h patterns_generated.h
	$(CC) $(CFLAGS) $(PCRE2_CFLAGS) -shared -o $@ matcher7_plain.c $(LDFLAGS) $(PCRE2_LDFLAGS)

smoke7_plain: matcher7_plain
	./matcher7_plain

# Prototype plain Onigmo — 88 patterns, plain Onigmo sequential (no AC, no BM).
matcher7_plain_onig.so: matcher7_plain_onig.c matcher7_plain_onig.h patterns_generated.h
	$(CC) $(CFLAGS) $(ONIG_CFLAGS) -shared -o $@ matcher7_plain_onig.c $(LDFLAGS) $(ONIG_LDFLAGS)

# Prototype v9 — 88 separate per-pattern Thompson NFA + lazy DFA caches. Zero deps.
matcher9: matcher9.c matcher9.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM9_MAIN -o $@ matcher9.c $(LDFLAGS)

matcher9.so: matcher9.c matcher9.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher9.c $(LDFLAGS)

smoke9: matcher9
	./matcher9

# Prototype v10 — 88 per-pattern backtracking NFA, fixed O(1) stack. Zero deps.
matcher10: matcher10.c matcher10.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM10_MAIN -o $@ matcher10.c $(LDFLAGS)

matcher10.so: matcher10.c matcher10.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher10.c $(LDFLAGS)

smoke10: matcher10
	./matcher10

# Prototype v11 — 88 per-pattern Thompson bytecode VM. Zero deps.
matcher11: matcher11.c matcher11.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM11_MAIN -o $@ matcher11.c $(LDFLAGS)

matcher11.so: matcher11.c matcher11.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher11.c $(LDFLAGS)

smoke11: matcher11
	./matcher11

# Prototype v12 — v11 bytecode VM + literal pre-filter for all 88 patterns. Zero deps.
matcher12: matcher12.c matcher12.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM12_MAIN -o $@ matcher12.c $(LDFLAGS)

matcher12.so: matcher12.c matcher12.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher12.c $(LDFLAGS)

smoke12: matcher12
	./matcher12

# Prototype v14 — v12.1 literal filter + per-pattern first-byte filter. Zero deps.
matcher14: matcher14.c matcher14.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM14_MAIN -o $@ matcher14.c $(LDFLAGS)

matcher14.so: matcher14.c matcher14.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher14.c $(LDFLAGS)

smoke14: matcher14
	./matcher14

# Prototype v15 — v14 + Thompson VM constant-factor speedups. Zero deps.
matcher15: matcher15.c matcher15.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM15_MAIN -o $@ matcher15.c $(LDFLAGS)

matcher15.so: matcher15.c matcher15.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher15.c $(LDFLAGS)

smoke15: matcher15
	./matcher15

# Prototype v16 — v15.1 + cross-pattern union first-byte bitmap. Zero deps.
matcher16: matcher16.c matcher16.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM16_MAIN -o $@ matcher16.c $(LDFLAGS)

matcher16.so: matcher16.c matcher16.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher16.c $(LDFLAGS)

smoke16: matcher16
	./matcher16

# Prototype v17 — v15.1 + precomputed initial thread list. Zero deps.
matcher17: matcher17.c matcher17.h patterns_generated.h
	$(CC) $(CFLAGS) -DMM17_MAIN -o $@ matcher17.c $(LDFLAGS)

matcher17.so: matcher17.c matcher17.h patterns_generated.h
	$(CC) $(CFLAGS) -shared -o $@ matcher17.c $(LDFLAGS)

smoke17: matcher17
	./matcher17

# Standalone micro-benchmarks (no .so — direct C executables).
bench_malloc: bench_malloc.c ../../ext/data_redactor/patterns.c ../../ext/data_redactor/placeholder.c
	$(CC) $(CFLAGS) -I../../ext/data_redactor \
	    bench_malloc.c \
	    ../../ext/data_redactor/patterns.c \
	    ../../ext/data_redactor/placeholder.c \
	    -o bench_malloc

bench_bm_inner: bench_bm_inner.c ../../ext/data_redactor/patterns.c ../../ext/data_redactor/placeholder.c
	$(CC) $(CFLAGS) -I../../ext/data_redactor \
	    bench_bm_inner.c \
	    ../../ext/data_redactor/patterns.c \
	    ../../ext/data_redactor/placeholder.c \
	    -o bench_bm_inner

clean:
	rm -f matcher matcher.so matcher2 matcher2.so matcher3 matcher3.so \
	      matcher4 matcher4.so matcher5 matcher5.so matcher6 matcher6.so \
	      matcher7 matcher7.so matcher9 matcher9.so matcher10 matcher10.so \
	      matcher11 matcher11.so matcher12 matcher12.so \
	      matcher14 matcher14.so matcher15 matcher15.so \
	      matcher16 matcher16.so \
	      matcher17 matcher17.so \
	      bench_malloc bench_bm_inner \
	      patterns_generated.h
