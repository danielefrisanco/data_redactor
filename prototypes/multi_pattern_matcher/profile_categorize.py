#!/usr/bin/env python3
"""
profile_categorize.py — bucket callgrind_annotate per-function Ir into mechanism
categories, for the paper §5.1 instruction-attribution table.

Reads paper/data/profile_<engine>.txt (output of `callgrind_annotate`), one file
per engine, and writes paper/data/profile_summary.csv with columns:

    engine,category,ir,pct

Categories (mutually exclusive, matched in order against the file:function field):

    automaton  per-position regex/NFA/DFA evaluation (the engine's core work)
    setup      per-call state/position setup: glibc re_string_reconstruct, the
               strlen it runs over the remaining input each call (the O(N)
               per-call cost the paper attributes to the incumbent)
    prefilter  literal pre-filter: Boyer-Moore / memmem / strstr
    alloc      malloc / free / realloc / calloc and internals
    output     memcpy / memmove (match copy-out)
    libonig    Onigmo internals with no debug symbols (cannot be split into
               prefilter vs automaton — disclosed as such in the paper)
    other      setup we can't attribute, libc glue, the driver's own main

Usage: profile_categorize.py OUT_DIR engine [engine ...]
"""
import os
import re
import sys

# Each (category, regex) is tried in order; first match wins. Patterns match the
# "file:function" field that callgrind_annotate prints (we strip the [lib] tail).
RULES = [
    # glibc regexec automaton core + Onigmo named NFA helpers + v19 DFA stepper
    ("automaton", re.compile(
        r"re_search_internal|merge_state_with_log|re_string_context_at|"
        r"match_ctx_clean|sift_states|update_cur_sifted|re_acquire_state|"
        r"re_node_set|check_halt_state|check_node_accept|re_compile|"  # glibc
        r"scan_one|addthread|vm_|step|dfa_compute_trans|dfa_intern|"   # v19
        r"onig_search|onig_init_for_match_at|match_at|onige?_step",    # onigmo (named)
        re.I)),
    # glibc per-call setup: rebuild the search string + strlen over the tail
    ("setup", re.compile(
        r"re_string_reconstruct|re_string_realloc|re_string_construct|"
        r"__strlen|:strlen|onigenc_|onig_region_|onig_initialize_match",
        re.I)),
    ("prefilter", re.compile(r"\bbm_|boyer|memmem|:strstr|sunday|fast_search", re.I)),
    ("alloc", re.compile(r"_int_malloc|_int_free|_int_realloc|malloc_consolidate|"
                         r"unlink_chunk|:malloc\b|:free\b|:realloc\b|:calloc\b|"
                         r"tcache|arena|sysmalloc|:brk\b", re.I)),
    ("output", re.compile(r"__memcpy|__memmove|__mempcpy|:memcpy|:memmove", re.I)),
]

# Stripped libonig static functions show up as ???:0x.... [.../libonig.so...].
LIBONIG = re.compile(r"libonig", re.I)
# memset inside onig is region-clear (NFA bookkeeping), bucket with automaton via libonig.

ROW = re.compile(r"^\s*([\d,]+)\s+\(\s*[0-9.]+%\)\s+(.*)$")


def categorize(field):
    # field is e.g. "./posix/./posix/regexec.c:re_search_internal [/usr/lib/...]"
    if LIBONIG.search(field):
        return "libonig"
    for name, rx in RULES:
        if rx.search(field):
            return name
    return "other"


def parse(path):
    cats = {"automaton": 0, "setup": 0, "prefilter": 0, "alloc": 0,
            "output": 0, "libonig": 0, "other": 0}
    grand = 0
    seen_total = False
    with open(path) as f:
        for line in f:
            m = ROW.match(line)
            if not m:
                continue
            ir = int(m.group(1).replace(",", ""))
            field = m.group(2).strip()
            if "PROGRAM TOTALS" in field:
                seen_total = True
                continue
            if ir <= 0:
                continue
            cats[categorize(field)] += ir
            grand += ir
    if not seen_total:
        sys.stderr.write(f"warning: no PROGRAM TOTALS line in {path}\n")
    return cats, max(grand, 1)


def main():
    out_dir = sys.argv[1]
    engines = sys.argv[2:]
    order = ["automaton", "setup", "prefilter", "output", "alloc", "libonig", "other"]

    rows = []
    table = {}
    for eng in engines:
        cats, grand = parse(os.path.join(out_dir, f"profile_{eng}.txt"))
        table[eng] = {c: 100.0 * cats[c] / grand for c in order}
        for c in order:
            rows.append((eng, c, cats[c], 100.0 * cats[c] / grand))

    with open(os.path.join(out_dir, "profile_summary.csv"), "w") as f:
        f.write("engine,category,ir,pct\n")
        for eng, c, ir, pct in rows:
            f.write(f"{eng},{c},{ir},{pct:.2f}\n")

    hdr = f"{'engine':8}" + "".join(f"{c:>11}" for c in order)
    print(hdr)
    for eng in engines:
        d = table[eng]
        print(f"{eng:8}" + "".join(f"{d[c]:10.1f}%" for c in order))


if __name__ == "__main__":
    main()
