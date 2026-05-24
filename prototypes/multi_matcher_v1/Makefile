# Standalone build for the multi-matcher prototype. NOT wired into the
# gem's extconf.rb — this is a one-off experiment.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -fPIC
LDFLAGS ?=

# Option A: standalone libonig-dev (apt install libonig-dev).
# Uses system Oniguruma — no Ruby VM required.
ONIG_CFLAGS  = $(shell pkg-config --cflags oniguruma 2>/dev/null || echo "-I/usr/include")
ONIG_LDFLAGS = -lonig

.PHONY: all clean smoke smoke2 smoke3 smoke4 smoke5 generate

all: matcher matcher.so matcher2 matcher2.so matcher3 matcher3.so matcher4 matcher4.so matcher5 matcher5.so

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

clean:
	rm -f matcher matcher.so matcher2 matcher2.so matcher3 matcher3.so \
	      matcher4 matcher4.so matcher5 matcher5.so patterns_generated.h
