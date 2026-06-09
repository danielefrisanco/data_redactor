#ifndef DATA_REDACTOR_MATCHER_H
#define DATA_REDACTOR_MATCHER_H

#include <stddef.h>

/*
 * The v19 multi-pattern engine: per-pattern lazy DFA (NFA -> bytecode ->
 * interned DFA) with two selective merges (pure-digit run pass, IBAN union
 * pass) and the v19.1 EOL-at-buffer-end fix. Zero dependencies beyond libc.
 * See docs/research_log.md (v15..v19) for the derivation, and
 * prototypes/multi_matcher_v1/ for the standalone prototype this is ported from.
 *
 * Built-in pattern engines are sourced from the gem's pattern arrays
 * (pattern_strings[]/boundary_wrapped[]/pattern_required_literal[]), NOT a
 * compile-time table. Custom patterns (DataRedactor.add_pattern) are appended
 * at ids [NUM_PATTERNS .. NUM_PATTERNS+custom_count) and always take the
 * per-pattern path (never folded into the selective merges) — documented as a
 * divergence in TODO.md §1d.
 *
 * Thread-safety: the engine uses file-scope mutable scan scratch. Phase 1 does
 * NOT release the GVL during a scan, so concurrent redact/scan calls are
 * serialized by MRI's GVL. See TODO.md §1d "Phase 1 — not done yet" for the
 * per-call re-entrancy work this defers.
 */

typedef struct {
    int    pattern_id;  /* index into the built-in + custom pattern space */
    size_t start;       /* byte offset of the CORE span in the ORIGINAL input */
    size_t length;      /* byte length of the CORE span */
} mm_match_t;

/* Build the built-in engines from the gem's pattern arrays. Idempotent;
 * called once from Init_data_redactor. */
void mm_init(void);

/* Append one engine for a custom pattern whose CORE regex is `regex`.
 * `boundary` mirrors custom_patterns[].boundary (wrap with the boundary group).
 * Must be called in registration order so the custom id == NUM_PATTERNS + slot.
 * Returns 0 on success, non-zero if the engine's own parser rejects the regex
 * (treated as a bug-to-fix, not a silent fallback — see Section E). */
int  mm_add(const char *regex, int boundary);

/* Free the engine at custom slot `idx` (0-based among customs) and compact the
 * custom engine array so the remaining customs keep registration order. */
void mm_remove(int idx);

/* Free every custom engine (DataRedactor.clear_custom_patterns!). */
void mm_clear_custom(void);

/*
 * Scan `input` once and write up to `max` match events to `out`, returning the
 * count. `enable_bits[i]` (i in [0, n_total)) gates pattern i; a NULL or short
 * array disables out-of-range patterns. Events carry ORIGINAL-frame offsets.
 *
 * Events are NOT pre-resolved for cross-pattern overlap — the caller applies
 * the index-order greedy claim (mm_resolve) to reproduce the gem's sequential
 * per-pattern rewrite semantics.
 */
size_t mm_scan(const char *input, size_t len,
               const int *enable_bits, size_t n_bits,
               mm_match_t *out, size_t max);

/*
 * Resolve raw scan events into the non-overlapping set the gem's sequential
 * per-pattern rewrite would produce: in (pattern_id, start) order, keep an
 * event iff its CORE span does not overlap an already-kept span. Sorts `ev`
 * in place and returns the kept count (compacted to the front of `ev`), in
 * ascending start order. n_total is the pattern-id upper bound for ordering.
 */
size_t mm_resolve(mm_match_t *ev, size_t n);

/* Pattern name for an id (built-in or custom), or NULL if out of range. */
const char *mm_pattern_name(int id);

/* Total number of engines currently built (NUM_PATTERNS + custom count). */
int mm_pattern_count(void);

#endif /* DATA_REDACTOR_MATCHER_H */
