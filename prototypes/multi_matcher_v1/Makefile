# Standalone build for the multi-matcher prototype. NOT wired into the
# gem's extconf.rb — this is a one-off experiment.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -fPIC
LDFLAGS ?=

.PHONY: all clean smoke

all: matcher matcher.so

# Standalone smoke-test binary (Slice 1).
matcher: matcher.c matcher.h
	$(CC) $(CFLAGS) -DMM_MAIN -o $@ matcher.c $(LDFLAGS)

# Shared library for Ruby FFI (Slice 3).
matcher.so: matcher.c matcher.h
	$(CC) $(CFLAGS) -shared -o $@ matcher.c $(LDFLAGS)

smoke: matcher
	./matcher

clean:
	rm -f matcher matcher.so
