/* matcher19.c — v19: v18.1 + merged pure-digit-group scan.
 *
 * Builds directly on v18.1 (per-pattern lazy DFA with anchor lowering). The change:
 * the pure-digit patterns — those whose regex is exactly `[0-9]{lo,hi}` and are
 * boundary-wrapped (south_african_id, japanese_my_number, the four `[0-9]{11}`
 * variants, the two `[0-9]{9}` variants, dutch_bsn `[0-9]{8,9}`) — are no longer
 * scanned individually. Instead a single linear pass over the input finds every
 * maximal digit run bounded by non-alphanumeric bytes, and for each run of length L
 * emits every member pattern whose length window [lo,hi] contains L.
 *
 * Why this is correct and equivalent to v18.1:
 *   Because each member is boundary-wrapped `(^|[^0-9A-Za-z])([0-9]{lo,hi})([^...]|$)`,
 *   a member of fixed length n matches ONLY a digit run of exactly length n (a
 *   shorter prefix of a longer run is followed by a digit, not a boundary, so the
 *   trailing `[^0-9A-Za-z]` fails). So per maximal run of length L, the members that
 *   fire are exactly those with lo<=L<=hi. The emitted span/start replicate v18.1's
 *   boundary-wrapped span: start at the leading boundary byte (run_start-1) when one
 *   exists, else the run start at pos 0; length = run + the boundary bytes present
 *   on each side. This is verified byte-for-byte against v15.1 in verify19.rb.
 *
 *   The members are mergeable because their start states are identical (all `[0-9]`);
 *   the per-run emission then fans out by length. This collapses the member patterns'
 *   per-pattern outer scans (each: first-byte filter + DFA drive) into one O(n)
 *   digit-run pass — the v19 speedup.
 *
 * Non-members with a digit first-byte (romanian_cnp `[1-8]...`, hungarian_tax_id
 * `8...`, french_nir, dashed/dotted ID formats, IBANs) keep v18.1's per-pattern DFA
 * path unchanged. Only the strictly-pure members are removed from that loop.
 *
 * Build:  make matcher19.so   (shared lib)
 *         make matcher19       (self-test binary)
 */

#define _GNU_SOURCE
#include "matcher19b.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>

/* ========================================================================
 * 0. Utilities
 * ======================================================================== */

static void *xmalloc(size_t n) {
    void *p = malloc(n); if (!p) { perror("malloc"); exit(1); } return p;
}
static void *xcalloc(size_t n, size_t s) {
    void *p = calloc(n, s); if (!p) { perror("calloc"); exit(1); } return p;
}

/* ========================================================================
 * 1. Character class bitmap (256 bits = 4 × uint64_t)
 * ======================================================================== */

typedef struct { uint64_t w[4]; } cclass_t;

static void cc_set(cclass_t *c, unsigned ch) { c->w[ch>>6] |= (uint64_t)1<<(ch&63); }
static void cc_unset(cclass_t *c, unsigned ch) { c->w[ch>>6] &= ~((uint64_t)1<<(ch&63)); }
static int  cc_test(const cclass_t *c, unsigned ch) { return (c->w[ch>>6]>>(ch&63))&1; }
static void cc_negate(cclass_t *c) {
    c->w[0]=~c->w[0]; c->w[1]=~c->w[1]; c->w[2]=~c->w[2]; c->w[3]=~c->w[3];
}
static void cc_add_range(cclass_t *c, unsigned lo, unsigned hi) {
    for (unsigned i=lo; i<=hi; i++) cc_set(c,i);
}
static void cc_add_posix(cclass_t *c, const char *cls, size_t len) {
    if      (len==5 && !memcmp(cls,"alpha",5)) { cc_add_range(c,'a','z'); cc_add_range(c,'A','Z'); }
    else if (len==5 && !memcmp(cls,"digit",5)) { cc_add_range(c,'0','9'); }
    else if (len==5 && !memcmp(cls,"alnum",5)) { cc_add_range(c,'a','z'); cc_add_range(c,'A','Z'); cc_add_range(c,'0','9'); }
    else if (len==5 && !memcmp(cls,"upper",5)) { cc_add_range(c,'A','Z'); }
    else if (len==5 && !memcmp(cls,"lower",5)) { cc_add_range(c,'a','z'); }
    else if (len==5 && !memcmp(cls,"space",5)) { cc_set(c,' '); cc_set(c,'\t'); cc_set(c,'\n'); cc_set(c,'\r'); cc_set(c,'\f'); cc_set(c,'\v'); }
    else if (len==6 && !memcmp(cls,"xdigit",6)) { cc_add_range(c,'0','9'); cc_add_range(c,'a','f'); cc_add_range(c,'A','F'); }
    else if (len==5 && !memcmp(cls,"print",5)) { cc_add_range(c,0x20,0x7e); }
    else if (len==5 && !memcmp(cls,"graph",5)) { cc_add_range(c,0x21,0x7e); }
    else if (len==5 && !memcmp(cls,"punct",5)) {
        for (unsigned i=0x21;i<=0x7e;i++) if (!isalnum(i)) cc_set(c,i);
    } else { fprintf(stderr,"matcher15: unknown POSIX class [:%.*s:]\n",(int)len,cls); exit(1); }
}

/* ========================================================================
 * 2. Regex parser → AST  (identical to matcher9 — proven)
 * ======================================================================== */

typedef enum {
    AST_LITERAL, AST_CCLASS, AST_DOT, AST_CONCAT, AST_ALT, AST_REPEAT,
    AST_ANCHOR_BOL, AST_ANCHOR_EOL,
} ast_type_t;

typedef struct ast_node ast_node_t;
struct ast_node {
    ast_type_t    type;
    unsigned char ch;
    cclass_t      cc;
    ast_node_t   *left, *right;
    int           lo, hi;
};

static ast_node_t *ast_alloc(ast_type_t t) {
    ast_node_t *n = xcalloc(1, sizeof(*n)); n->type=t; return n;
}
static void ast_free(ast_node_t *n) {
    if (!n) return;
    ast_free(n->left); ast_free(n->right); free(n);
}

typedef struct { const char *p, *end; } pctx_t;
static ast_node_t *parse_alt(pctx_t *ctx);

static ast_node_t *parse_cclass(pctx_t *ctx) {
    ast_node_t *n = ast_alloc(AST_CCLASS);
    int negate=0;
    if (ctx->p < ctx->end && *ctx->p=='^') { negate=1; ctx->p++; }
    int first=1;
    while (ctx->p < ctx->end && (*ctx->p!=']' || first)) {
        first=0;
        unsigned char c=(unsigned char)*ctx->p++;
        if (c=='[' && ctx->p < ctx->end && *ctx->p==':') {
            ctx->p++;
            const char *cs=ctx->p;
            while (ctx->p < ctx->end && !(*ctx->p==':' && *(ctx->p+1)==']')) ctx->p++;
            cc_add_posix(&n->cc, cs, (size_t)(ctx->p-cs));
            ctx->p+=2;
        } else if (ctx->p+1 < ctx->end && *ctx->p=='-' && *(ctx->p+1)!=']') {
            ctx->p++;
            cc_add_range(&n->cc, c, (unsigned char)*ctx->p++);
        } else if (c=='\\' && ctx->p < ctx->end) {
            cc_set(&n->cc, (unsigned char)*ctx->p++);
        } else {
            cc_set(&n->cc, c);
        }
    }
    if (ctx->p < ctx->end && *ctx->p==']') ctx->p++;
    if (negate) cc_negate(&n->cc);
    return n;
}

static void parse_quantifier(pctx_t *ctx, ast_node_t **io) {
    if (ctx->p >= ctx->end) return;
    char c=*ctx->p;
    int lo=1, hi=1;
    if      (c=='*') { lo=0; hi=-1; ctx->p++; }
    else if (c=='+') { lo=1; hi=-1; ctx->p++; }
    else if (c=='?') { lo=0; hi=1;  ctx->p++; }
    else if (c=='{') {
        ctx->p++; lo=0;
        while (ctx->p<ctx->end && isdigit((unsigned char)*ctx->p)) lo=lo*10+(*ctx->p++-'0');
        if (ctx->p<ctx->end && *ctx->p==',') {
            ctx->p++; hi=0;
            if (ctx->p<ctx->end && *ctx->p=='}') { hi=-1; }
            else while (ctx->p<ctx->end && isdigit((unsigned char)*ctx->p)) hi=hi*10+(*ctx->p++-'0');
        } else { hi=lo; }
        if (ctx->p<ctx->end && *ctx->p=='}') ctx->p++;
    } else return;
    if (ctx->p<ctx->end && *ctx->p=='?') ctx->p++;
    ast_node_t *rep=ast_alloc(AST_REPEAT);
    rep->left=*io; rep->lo=lo; rep->hi=hi; *io=rep;
}

static ast_node_t *parse_atom(pctx_t *ctx) {
    if (ctx->p >= ctx->end) return NULL;
    unsigned char c=(unsigned char)*ctx->p;
    if (c=='(') {
        ctx->p++;
        if (ctx->p+1<ctx->end && *ctx->p=='?' && *(ctx->p+1)==':') ctx->p+=2;
        ast_node_t *inner=parse_alt(ctx);
        if (ctx->p<ctx->end && *ctx->p==')') ctx->p++;
        return inner;
    }
    if (c=='[') { ctx->p++; return parse_cclass(ctx); }
    if (c=='.') { ctx->p++; return ast_alloc(AST_DOT); }
    if (c=='^') { ctx->p++; return ast_alloc(AST_ANCHOR_BOL); }
    if (c=='$') { ctx->p++; return ast_alloc(AST_ANCHOR_EOL); }
    if (c=='\\' && ctx->p+1<ctx->end) {
        ctx->p++;
        ast_node_t *n=ast_alloc(AST_LITERAL); n->ch=(unsigned char)*ctx->p++; return n;
    }
    if (c==')' || c=='|') return NULL;
    ctx->p++;
    ast_node_t *n=ast_alloc(AST_LITERAL); n->ch=c; return n;
}

static ast_node_t *parse_concat(pctx_t *ctx) {
    ast_node_t *head=NULL;
    while (ctx->p<ctx->end && *ctx->p!=')' && *ctx->p!='|') {
        ast_node_t *atom=parse_atom(ctx);
        if (!atom) break;
        parse_quantifier(ctx, &atom);
        if (!head) { head=atom; }
        else { ast_node_t *cat=ast_alloc(AST_CONCAT); cat->left=head; cat->right=atom; head=cat; }
    }
    return head;
}

static ast_node_t *parse_alt(pctx_t *ctx) {
    ast_node_t *left=parse_concat(ctx);
    while (ctx->p<ctx->end && *ctx->p=='|') {
        ctx->p++;
        ast_node_t *right=parse_concat(ctx);
        ast_node_t *alt=ast_alloc(AST_ALT);
        alt->left=left; alt->right=right; left=alt;
    }
    return left;
}

static ast_node_t *parse_regex(const char *src) {
    pctx_t ctx={src, src+strlen(src)}; return parse_alt(&ctx);
}

/* ========================================================================
 * 3. Bytecode program
 *
 * A program is a flat array of instructions. Control-flow ops (SPLIT, JMP)
 * carry instruction indices ("pc"). The compiler emits instructions in two
 * passes is not needed: we emit forward and back-patch jump targets in place
 * because we know fragment boundaries as we build.
 * ======================================================================== */

typedef enum {
    OP_CHAR,    /* match byte == arg.ch, then advance input */
    OP_CLASS,   /* match byte in arg.cc, then advance input */
    OP_ANY,     /* match any byte != '\n', then advance input */
    OP_SPLIT,   /* fork: try x (preferred) then y; no input consumed */
    OP_JMP,     /* goto x; no input consumed */
    OP_BOL,     /* assert at beginning of line (pos==0 or prev=='\n') */
    OP_EOL,     /* assert at end of line (pos==len or cur=='\n') */
    OP_MATCH,   /* accept */
} opcode_t;

typedef struct {
    opcode_t      op;
    unsigned char ch;   /* OP_CHAR */
    cclass_t      cc;   /* OP_CLASS */
    int           x, y; /* OP_SPLIT / OP_JMP targets (instruction indices) */
} inst_t;

typedef struct {
    inst_t  *code;
    int      n;     /* number of instructions used */
    int      cap;   /* allocated capacity */
} prog_t;

static int prog_emit(prog_t *pr, opcode_t op) {
    if (pr->n >= pr->cap) {
        pr->cap = pr->cap ? pr->cap * 2 : 64;
        pr->code = realloc(pr->code, pr->cap * sizeof(inst_t));
        if (!pr->code) { perror("realloc"); exit(1); }
    }
    int at = pr->n++;
    memset(&pr->code[at], 0, sizeof(inst_t));
    pr->code[at].op = op;
    return at;
}

/* ========================================================================
 * 4. AST → bytecode
 *
 * Each emit_* function appends instructions for `node` such that, on entry,
 * control is at the first emitted instruction, and on a successful match the
 * program "falls through" to whatever instruction is emitted next. Quantifier
 * loops use SPLIT to express choice (greedy = preferred branch first).
 * ======================================================================== */

static void emit_node(prog_t *pr, ast_node_t *node);

static void emit_repeat(prog_t *pr, ast_node_t *node) {
    ast_node_t *child = node->left;
    int lo = node->lo, hi = node->hi;

    /* mandatory copies: child repeated `lo` times */
    for (int i = 0; i < lo; i++) emit_node(pr, child);

    if (hi == -1) {
        /* {lo,∞}: greedy star.  L: split body, out ;  body ; jmp L ;  out: */
        int l = prog_emit(pr, OP_SPLIT);
        emit_node(pr, child);
        int j = prog_emit(pr, OP_JMP);
        pr->code[j].x = l;
        pr->code[l].x = l + 1;   /* prefer entering the body */
        pr->code[l].y = pr->n;   /* else exit (next instruction) */
    } else {
        /* {lo,hi}: (hi-lo) optional copies, each guarded by a split-to-end. */
        int n_opt = hi - lo;
        int *splits = n_opt ? xmalloc(n_opt * sizeof(int)) : NULL;
        for (int i = 0; i < n_opt; i++) {
            splits[i] = prog_emit(pr, OP_SPLIT);
            pr->code[splits[i]].x = splits[i] + 1; /* prefer taking the copy */
            emit_node(pr, child);
        }
        /* all optional splits skip to the instruction after the whole group */
        for (int i = 0; i < n_opt; i++) pr->code[splits[i]].y = pr->n;
        free(splits);
    }
}

static void emit_node(prog_t *pr, ast_node_t *node) {
    if (!node) return;  /* empty fragment matches the empty string */
    switch (node->type) {
    case AST_LITERAL: {
        int i = prog_emit(pr, OP_CHAR); pr->code[i].ch = node->ch; break;
    }
    case AST_CCLASS: {
        int i = prog_emit(pr, OP_CLASS); pr->code[i].cc = node->cc; break;
    }
    case AST_DOT:        prog_emit(pr, OP_ANY); break;
    case AST_ANCHOR_BOL: prog_emit(pr, OP_BOL); break;
    case AST_ANCHOR_EOL: prog_emit(pr, OP_EOL); break;
    case AST_CONCAT:
        emit_node(pr, node->left);
        emit_node(pr, node->right);
        break;
    case AST_ALT: {
        /* split L, R ; L: <left> ; jmp out ; R: <right> ; out: */
        int s = prog_emit(pr, OP_SPLIT);
        pr->code[s].x = pr->n;
        emit_node(pr, node->left);
        int j = prog_emit(pr, OP_JMP);
        pr->code[s].y = pr->n;
        emit_node(pr, node->right);
        pr->code[j].x = pr->n;
        break;
    }
    case AST_REPEAT: emit_repeat(pr, node); break;
    }
}

/* ========================================================================
 * 5. Minimum match length from AST (cheap reject + dead-end guard)
 * ======================================================================== */

static size_t ast_min_len(const ast_node_t *n) {
    if (!n) return 0;
    switch (n->type) {
    case AST_LITERAL: case AST_CCLASS: case AST_DOT: return 1;
    case AST_ANCHOR_BOL: case AST_ANCHOR_EOL:         return 0;
    case AST_CONCAT: return ast_min_len(n->left) + ast_min_len(n->right);
    case AST_ALT: { size_t l=ast_min_len(n->left), r=ast_min_len(n->right); return l<r?l:r; }
    case AST_REPEAT: return n->lo==0 ? 0 : (size_t)n->lo * ast_min_len(n->left);
    }
    return 0;
}

/* Maximum bytes a match can span. SIZE_MAX = unbounded (a *  or + or {n,}). */
#define LEN_UNBOUNDED SIZE_MAX
static size_t add_sat(size_t a, size_t b) {
    if (a == LEN_UNBOUNDED || b == LEN_UNBOUNDED) return LEN_UNBOUNDED;
    size_t s = a + b; return s < a ? LEN_UNBOUNDED : s;
}
static size_t mul_sat(size_t a, size_t b) {
    if (a == 0 || b == 0) return 0;
    if (a == LEN_UNBOUNDED || b == LEN_UNBOUNDED) return LEN_UNBOUNDED;
    size_t s = a * b; return s / a != b ? LEN_UNBOUNDED : s;
}
static size_t ast_max_len(const ast_node_t *n) {
    if (!n) return 0;
    switch (n->type) {
    case AST_LITERAL: case AST_CCLASS: case AST_DOT: return 1;
    case AST_ANCHOR_BOL: case AST_ANCHOR_EOL:         return 0;
    case AST_CONCAT: return add_sat(ast_max_len(n->left), ast_max_len(n->right));
    case AST_ALT: { size_t l=ast_max_len(n->left), r=ast_max_len(n->right); return l>r?l:r; }
    case AST_REPEAT:
        if (n->hi == -1) return LEN_UNBOUNDED;
        return mul_sat((size_t)n->hi, ast_max_len(n->left));
    }
    return 0;
}

/* ========================================================================
 * 6. Per-pattern engine
 * ======================================================================== */

typedef struct {
    prog_t      prog;
    size_t      min_len;
    /* required literal hint: skip to its next occurrence before scanning */
    const char *req_literal;
    size_t      req_lit_len;
    int         req_lit_at_start;  /* 1 = literal must begin the match span */
    /* v12 literal skip: a match must contain req_literal, so a match start lies
     * in [hit - max_back .. hit] for each literal occurrence `hit`.
     * can_skip = 0 means max_back is unbounded → fall back to v11 full scan. */
    int         can_skip;
    size_t      max_back;
    /* v14 first-byte filter: set of bytes that can be the first consumed byte of
     * a match, OVER ALL start positions (BOL/EOL treated as passable, so the set
     * is a safe superset and never rejects a real match). has_first_filter == 0
     * means the set is all 256 bytes (no filtering possible). */
    cclass_t    first;
    int         has_first_filter;
    /* v18: use a lazy DFA for this pattern iff it has no BOL/EOL anchor (those
     * make the closure position-dependent, which a DFA state can't encode). */
    int         use_dfa;
    /* v18.1: boundary-wrapped patterns need a pre-check before DFA seeding */
    int         boundary_wrapped;
} pat_engine_t;

static pat_engine_t g_engines[MM88_NUM_PATTERNS];
static int          g_initialized = 0;

/* ========================================================================
 * v19 merged pure-digit group
 *
 * A pattern is a "pure-digit member" iff it is boundary_wrapped and its raw regex
 * (before wrapping) is exactly `[0-9]{lo,hi}` — only digits, only a length window.
 * Such members are removed from the per-pattern scan loop and handled together by
 * one linear digit-run pass. g_digit_member[p] flags membership; g_digit_lo/hi[p]
 * record the length window so the run pass can fan out emissions by run length.
 * ======================================================================== */
static int g_digit_member[MM88_NUM_PATTERNS];
static int g_digit_lo[MM88_NUM_PATTERNS];
static int g_digit_hi[MM88_NUM_PATTERNS];
static int g_have_digit_group = 0;

/* v19 IBAN union pass. Each IBAN pattern has a fixed 2-letter country-code
 * prefix (pd->prefix, non-infix, length 2) and is NOT boundary-wrapped, so each
 * one would otherwise run its own memmem("XX") sweep over the whole buffer —
 * 18 sweeps that mostly find nothing. We replace them with ONE pass: a 256-entry
 * first-byte table picks candidate starts, and a [256][256] pair table maps the
 * 2-byte prefix to the single owning pattern id (country codes are unique, so the
 * mapping is 1:1). At each candidate we run that pattern's own DFA verify, with a
 * per-pattern non-overlapping cursor exactly as scan_one would. */
static int g_iban_member[MM88_NUM_PATTERNS];
static int g_iban_first[256];                 /* 1 = byte can start a country code */
static int g_iban_pair[256][256];             /* [c0][c1] = pattern id, or -1 */
static int g_have_iban_group = 0;

/* v19 https:// union pass. Four patterns (aws_s3_presigned_url,
 * microsoft_teams_webhook, slack_webhook_url, sentry_dsn) literally begin with
 * "https://" but carry only an *infix* bm_literal, and several have an unbounded
 * max_len so their literal-skip is disabled — each one therefore walks to every
 * 'h' in the buffer (common in text). One memmem("https://") sweep (rare in noise)
 * replaces those four first-byte walks; at each hit we drive all member DFAs. */
#define HTTPS_PREFIX     "https://"
#define HTTPS_PREFIX_LEN 8
static int g_https_member[MM88_NUM_PATTERNS];
static int g_have_https_group = 0;

/* Parse a raw regex of the form "[0-9]{n}" or "[0-9]{lo,hi}". Returns 1 and sets
 * *lo,*hi on success; returns 0 if the regex is anything else. Deliberately strict:
 * only the exact pure-digit shape qualifies, so [1-8].., 8.., dashed formats, etc.
 * are rejected and keep their own per-pattern DFA path. */
static int parse_pure_digit(const char *re, int *lo, int *hi) {
    if (strncmp(re, "[0-9]{", 6) != 0) return 0;
    const char *p = re + 6;
    int a = 0, has_a = 0;
    while (*p >= '0' && *p <= '9') { a = a*10 + (*p - '0'); p++; has_a = 1; }
    if (!has_a) return 0;
    int b;
    if (*p == ',') {
        p++;
        int c = 0, has_c = 0;
        while (*p >= '0' && *p <= '9') { c = c*10 + (*p - '0'); p++; has_c = 1; }
        if (!has_c) return 0;          /* `{n,}` unbounded — not a fixed digit member */
        b = c;
    } else {
        b = a;
    }
    if (*p != '}' || *(p+1) != '\0') return 0;   /* trailing junk → not pure */
    *lo = a; *hi = b;
    return 1;
}

/* An IBAN member is a non-boundary-wrapped pattern whose regex begins with two
 * uppercase ASCII letters then `[0-9]{2}` (the country code + check digits). The
 * two letters are the unique prefix we dispatch on. Returns 1 and sets c0,c1 on
 * success. */
static int parse_iban_prefix(const char *re, int boundary_wrapped,
                             unsigned char *c0, unsigned char *c1) {
    if (boundary_wrapped) return 0;
    if (!(re[0] >= 'A' && re[0] <= 'Z')) return 0;
    if (!(re[1] >= 'A' && re[1] <= 'Z')) return 0;
    if (strncmp(re + 2, "[0-9]{2}", 8) != 0) return 0;
    *c0 = (unsigned char)re[0];
    *c1 = (unsigned char)re[1];
    return 1;
}

#define WRAP_PFX "(^|[^0-9A-Za-z])("
#define WRAP_SFX ")([^0-9A-Za-z]|$)"

/* Per-pattern scan scratch, sized at first use to prog.n. Reused across calls;
 * the scan hot path allocates nothing. `matched` records whether the epsilon
 * closure reached OP_MATCH, so the per-byte accept check is O(1) instead of
 * rescanning the whole thread list (MATCH pcs are never stored in `list`). */
typedef struct {
    int      *list;   /* pc list of byte-consuming ops only */
    int       n;
    int       matched;
} tlist_t;

static int      *g_seen[MM88_NUM_PATTERNS];   /* seen[pc] = generation */
static int       g_seen_cap[MM88_NUM_PATTERNS];
static tlist_t   g_clist[MM88_NUM_PATTERNS], g_nlist[MM88_NUM_PATTERNS];
static int      *g_estack[MM88_NUM_PATTERNS]; /* iterative addthread DFS stack */
/* Generation counter PERSISTS across scan calls so seen[] stamps stay globally
 * monotonic — a fresh call never reuses a stamp left by a previous call. v11/v12
 * reset this to 0 per call, which is latently unsafe when seen[] holds a stale
 * value the new run climbs back through; v14's first-byte filter (fewer seeds →
 * lower final gen) made it surface, so we fix it here. */
static int       g_gen[MM88_NUM_PATTERNS];

/* ========================================================================
 * v18 lazy DFA cache (per pattern)
 *
 * A DFA state is a canonical (sorted, deduped) set of byte-consuming NFA pcs plus
 * a `matched` flag. States are interned: the pc-set is stored in a flat pool and a
 * hash maps the set to a small state id. trans[state*256 + byte] holds the next
 * state id, filled lazily (TRANS_UNFILLED until first computed; DFA_DEAD = no live
 * threads). The start state (id 0) is the closure of pc 0 for a non-boundary
 * position. All buffers are realloc-once and reused across calls; the scan hot
 * path allocates nothing once a pattern's reachable DFA is warm.
 * ======================================================================== */

#define DFA_DEAD       (-1)
#define TRANS_UNFILLED (-2)

typedef struct {
    /* interned states */
    int     *set_pool;     /* concatenated sorted pc-sets */
    size_t   set_pool_n, set_pool_cap;
    int     *set_off;      /* per-state: offset into set_pool */
    int     *set_len;      /* per-state: number of pcs */
    int     *matched;      /* per-state: closure reached MATCH */
    int     *trans;        /* per-state: 256 next-state ids (state*256 + byte) */
    int      n_states, states_cap;
    /* hash: pc-set -> state id (open addressing) */
    int     *hash;         /* state id or -1 */
    int      hash_cap;     /* power of two */
} dfa_t;

static dfa_t g_dfa[MM88_NUM_PATTERNS];

/* Compute the first-consumed-byte set of a compiled program, over all start
 * positions. Epsilon-closes from pc 0 over SPLIT/JMP and BOL/EOL (anchors are
 * treated as passable so the set is a safe superset — it may admit a byte that
 * a real match would reject, but never rejects a byte a real match accepts).
 * Collects the accepted bytes of every reachable CHAR/CLASS/ANY. If MATCH is
 * reachable with no byte consumed (a possible empty match), filtering is unsafe
 * and we report the full set. Init-time only; uses a fixed local stack. */
static void compute_first_set(const prog_t *pr, cclass_t *out, int *full) {
    memset(out, 0, sizeof(*out));
    *full = 0;
    uint8_t seen[2048];                 /* prog.n is well under this (max ~191) */
    int stack[2048], top = 0;
    memset(seen, 0, pr->n < 2048 ? (size_t)pr->n : 2048);
    if (pr->n > 2048) { *full = 1; return; }  /* defensive: never expected */
    stack[top++] = 0;
    while (top > 0) {
        int pc = stack[--top];
        if (pc < 0 || pc >= pr->n || seen[pc]) continue;
        seen[pc] = 1;
        const inst_t *in = &pr->code[pc];
        switch (in->op) {
        case OP_JMP:   stack[top++] = in->x; break;
        case OP_SPLIT: stack[top++] = in->x; stack[top++] = in->y; break;
        case OP_BOL: case OP_EOL: stack[top++] = pc + 1; break;  /* passable */
        case OP_CHAR:  cc_set(out, in->ch); break;
        case OP_CLASS: out->w[0]|=in->cc.w[0]; out->w[1]|=in->cc.w[1];
                       out->w[2]|=in->cc.w[2]; out->w[3]|=in->cc.w[3]; break;
        case OP_ANY:   cc_add_range(out, 0, 255); cc_unset(out, '\n'); break;
        case OP_MATCH: *full = 1; break;  /* empty match possible → cannot filter */
        }
        if (*full) return;
    }
}

/* Returns 1 if the program contains any line-anchor (BOL/EOL). Kept for
 * reference; not used in v18.1 since all patterns are DFA-able. */
static int prog_has_anchor(const prog_t *pr) __attribute__((unused));
static int prog_has_anchor(const prog_t *pr) {
    for (int i = 0; i < pr->n; i++)
        if (pr->code[i].op == OP_BOL || pr->code[i].op == OP_EOL) return 1;
    return 0;
}

void mm19b_init(void) {
    if (g_initialized) return;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        pat_engine_t *eng = &g_engines[p];
        memset(eng, 0, sizeof(*eng));

        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped) {
            size_t len = strlen(WRAP_PFX)+strlen(src)+strlen(WRAP_SFX)+1;
            to_free = xmalloc(len);
            snprintf(to_free, len, "%s%s%s", WRAP_PFX, src, WRAP_SFX);
            src = to_free;
        }

        ast_node_t *ast = parse_regex(src);
        eng->min_len = ast_min_len(ast);
        size_t max_len = ast_max_len(ast);
        emit_node(&eng->prog, ast);
        prog_emit(&eng->prog, OP_MATCH);
        ast_free(ast);
        free(to_free);

        const mm88_pattern_def_t *pd = &MM88_PATTERNS[p];
        if (pd->prefix && !pd->prefix_is_infix) {
            eng->req_literal      = pd->prefix;
            eng->req_lit_len      = strlen(pd->prefix);
            eng->req_lit_at_start = 1;
        } else if (pd->bm_literal) {
            eng->req_literal      = pd->bm_literal;
            eng->req_lit_len      = strlen(pd->bm_literal);
            eng->req_lit_at_start = 0;
        }

        /* v12 literal-skip window. A start-anchored literal already begins the
         * match (max_back = 0). For an infix literal, a match start can precede
         * the literal by at most (max_len - lit_len) bytes; if max_len is
         * unbounded we cannot bound the back-up, so we disable the skip and fall
         * back to v11's full scan for this pattern. */
        if (eng->req_literal) {
            if (eng->req_lit_at_start) {
                eng->can_skip = 1; eng->max_back = 0;
            } else if (max_len != LEN_UNBOUNDED && max_len >= eng->req_lit_len) {
                eng->can_skip = 1; eng->max_back = max_len - eng->req_lit_len;
            } else {
                eng->can_skip = 0;  /* unbounded prefix — full scan */
            }
        }

        /* v14 first-byte filter. */
        int full;
        compute_first_set(&eng->prog, &eng->first, &full);
        eng->has_first_filter = !full;

        /* v18: a pattern is DFA-cacheable iff its closure is position-independent,
         * i.e. it has no BOL/EOL anchor. Also require !full: if an empty match is
         * possible the DFA start state would be MATCH with no consuming threads —
         * the fallback handles that cleanly, so keep such patterns on the NFA path. */
        /* v18.1: all patterns use the DFA. For boundary-wrapped patterns, scan_one
         * will pre-check the boundary condition (pos==0 or non-alnum before pos)
         * before seeding the DFA, so addthread_dfa's always-passable BOL is safe:
         * when we enter the DFA the boundary condition always holds. */
        eng->use_dfa = !full;
        eng->boundary_wrapped = MM88_PATTERNS[p].boundary_wrapped;

        /* v19: flag pure-digit members. Detected from the RAW (unwrapped) regex —
         * the wrapper adds the boundary, which is exactly what the merged run pass
         * reproduces. */
        int lo, hi;
        if (MM88_PATTERNS[p].boundary_wrapped &&
            parse_pure_digit(MM88_PATTERNS[p].regex, &lo, &hi)) {
            g_digit_member[p] = 1;
            g_digit_lo[p] = lo;
            g_digit_hi[p] = hi;
            g_have_digit_group = 1;
        }

        /* v19: flag IBAN members and record their 2-byte prefix dispatch. */
        unsigned char c0, c1;
        if (parse_iban_prefix(MM88_PATTERNS[p].regex,
                              MM88_PATTERNS[p].boundary_wrapped, &c0, &c1)) {
            if (!g_have_iban_group)
                for (int a = 0; a < 256; a++)
                    for (int b = 0; b < 256; b++) g_iban_pair[a][b] = -1;
            g_iban_member[p] = 1;
            g_iban_first[c0] = 1;
            g_iban_pair[c0][c1] = p;
            g_have_iban_group = 1;
        }

        /* v19: flag https:// members (regex begins with the literal prefix and is
         * not boundary-wrapped). These move to the shared-prefix union pass. */
        if (!MM88_PATTERNS[p].boundary_wrapped &&
            strncmp(MM88_PATTERNS[p].regex, HTTPS_PREFIX, HTTPS_PREFIX_LEN) == 0) {
            g_https_member[p] = 1;
            g_have_https_group = 1;
        }
    }
    g_initialized = 1;
}

void mm19b_free(void) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        free(g_engines[p].prog.code);
        g_engines[p].prog.code = NULL;
        /* free the reusable scan scratch so re-init starts clean (seen[] and the
         * persistent gen counter must stay consistent — reset both together). */
        free(g_seen[p]);       g_seen[p] = NULL;
        free(g_clist[p].list); g_clist[p].list = NULL;
        free(g_nlist[p].list); g_nlist[p].list = NULL;
        free(g_estack[p]);     g_estack[p] = NULL;
        g_seen_cap[p] = 0;
        g_gen[p] = 0;

        /* free the lazy DFA cache */
        dfa_t *d = &g_dfa[p];
        free(d->set_pool); free(d->set_off); free(d->set_len);
        free(d->matched);  free(d->trans);   free(d->hash);
        memset(d, 0, sizeof(*d));
    }
    g_initialized = 0;
}

/* ========================================================================
 * 7. Thompson VM — two-list simulation
 *
 * State is just a pc (instruction index). A "thread" is one pc on the
 * current/next list. We add a thread by following all epsilon ops
 * (SPLIT/JMP/BOL/EOL) until we reach a byte-consuming op (CHAR/CLASS/ANY)
 * or MATCH, deduplicating by pc with a generation-stamped seen[] array.
 *
 * Leftmost-longest is enforced by remembering the longest accept end-pos
 * seen for the current start, then resuming the scan from there
 * (non-overlapping), exactly like String#gsub.
 * ======================================================================== */


/* addthread: epsilon-close `pc0` into list `tl`, dedup via seen[]/gen, appending
 * byte-consuming/MATCH pcs in thread-priority order. Iterative (explicit DFS stack
 * `stk`, capacity prog.n) — same pre-order the old recursion produced, so leftmost
 * preference is identical. pos is the current input position (for BOL/EOL).
 *
 * Pre-order preservation: a recursive SPLIT did addthread(x) fully, then
 * addthread(y). With a LIFO stack we push y first then x, so x pops and its whole
 * subtree is explored before y. seen[] is stamped at visit (pop) time, exactly as
 * the recursion stamped at entry. */
static void addthread(prog_t *pr, tlist_t *tl, int *seen, int gen,
                      int *stk, int pc0,
                      const char *input, size_t len, size_t pos) {
    int top = 0;
    stk[top++] = pc0;
    while (top > 0) {
        int pc = stk[--top];
        if (seen[pc] == gen) continue;
        seen[pc] = gen;
        inst_t *in = &pr->code[pc];
        switch (in->op) {
        case OP_JMP:
            stk[top++] = in->x;
            break;
        case OP_SPLIT:
            stk[top++] = in->y;   /* push y first ... */
            stk[top++] = in->x;   /* ... so x is popped (explored) first */
            break;
        case OP_BOL:
            if (pos == 0 || input[pos-1] == '\n') stk[top++] = pc + 1;
            break;
        case OP_EOL:
            if (pos == len || input[pos] == '\n') stk[top++] = pc + 1;
            break;
        case OP_MATCH:
            /* accept reached in the closure — record O(1), don't store a thread.
             * Threads are added in priority order, so the first MATCH seen is the
             * highest-priority accept; ignore later ones. */
            tl->matched = 1;
            break;
        default:
            /* byte-consuming op (CHAR/CLASS/ANY) — a real thread */
            tl->list[tl->n++] = pc;
            break;
        }
    }
}

/* addthread_dfa: computes position-independent closure for DFA states.
 * Calls the real addthread with pos=1 (not start-of-line, not end-of-input),
 * so OP_BOL only fires if input[0] == '\n' (never for pos=1 on a dummy empty
 * string), meaning the BOL branch of boundary-wrapped patterns does NOT fire
 * — only the [^0-9A-Za-z] branch is included in the DFA start state.
 * At pos==0 (true start-of-line), scan_one falls back to NFA for the seed. */
static void addthread_dfa(prog_t *pr, tlist_t *tl, int *seen, int gen, int *stk, int pc0) {
    addthread(pr, tl, seen, gen, stk, pc0, "", 0, 1);
}

/* ========================================================================
 * v18 lazy DFA construction
 * ======================================================================== */

static int int_cmp(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* FNV-1a over the sorted pc-set (+matched), masked to the hash capacity. */
static unsigned dfa_hash(const int *set, int n, int matched, int cap_mask) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        uint32_t k = (uint32_t)set[i];
        for (int b = 0; b < 4; b++) { h ^= (k & 0xff); h *= 1099511628211ULL; k >>= 8; }
    }
    h ^= (uint64_t)(matched & 1); h *= 1099511628211ULL;
    return (unsigned)(h & (uint64_t)cap_mask);
}

static int dfa_set_eq(const dfa_t *d, int sid, const int *set, int n, int matched) {
    if (d->set_len[sid] != n) return 0;
    if ((d->matched[sid] & 1) != (matched & 1)) return 0;
    const int *s = &d->set_pool[d->set_off[sid]];
    for (int i = 0; i < n; i++) if (s[i] != set[i]) return 0;
    return 1;
}

static void dfa_hash_insert(dfa_t *d, int sid);

static void dfa_grow_states(dfa_t *d) {
    if (d->n_states < d->states_cap) return;
    int newcap = d->states_cap ? d->states_cap * 2 : 64;
    d->set_off = realloc(d->set_off, (size_t)newcap * sizeof(int));
    d->set_len = realloc(d->set_len, (size_t)newcap * sizeof(int));
    d->matched = realloc(d->matched, (size_t)newcap * sizeof(int));
    d->trans   = realloc(d->trans,   (size_t)newcap * 256 * sizeof(int));
    if (!d->set_off || !d->set_len || !d->matched || !d->trans) {
        perror("realloc"); exit(1);
    }
    d->states_cap = newcap;
}

static void dfa_rehash(dfa_t *d) {
    int newcap = d->hash_cap ? d->hash_cap * 2 : 256;
    free(d->hash);
    d->hash = xmalloc((size_t)newcap * sizeof(int));
    for (int i = 0; i < newcap; i++) d->hash[i] = -1;
    d->hash_cap = newcap;
    for (int sid = 0; sid < d->n_states; sid++) dfa_hash_insert(d, sid);
}

static void dfa_hash_insert(dfa_t *d, int sid) {
    int mask = d->hash_cap - 1;
    unsigned h = dfa_hash(&d->set_pool[d->set_off[sid]], d->set_len[sid],
                          d->matched[sid], mask);
    while (d->hash[h] != -1) h = (h + 1) & (unsigned)mask;
    d->hash[h] = sid;
}

/* Intern a canonical (sorted) pc-set + matched flag, returning its state id.
 * Creates a new state (with an all-UNFILLED trans row) on first sight. */
static int dfa_intern(dfa_t *d, const int *set, int n, int matched) {
    if (d->n_states * 4 >= d->hash_cap * 3) dfa_rehash(d);  /* keep load < 0.75 */
    int mask = d->hash_cap - 1;
    unsigned h = dfa_hash(set, n, matched, mask);
    while (d->hash[h] != -1) {
        int sid = d->hash[h];
        if (dfa_set_eq(d, sid, set, n, matched)) return sid;
        h = (h + 1) & (unsigned)mask;
    }
    /* not found — create */
    dfa_grow_states(d);
    int sid = d->n_states++;
    /* append the pc-set to the pool */
    if (d->set_pool_n + (size_t)n > d->set_pool_cap) {
        size_t newcap = d->set_pool_cap ? d->set_pool_cap * 2 : 1024;
        while (newcap < d->set_pool_n + (size_t)n) newcap *= 2;
        d->set_pool = realloc(d->set_pool, newcap * sizeof(int));
        if (!d->set_pool) { perror("realloc"); exit(1); }
        d->set_pool_cap = newcap;
    }
    d->set_off[sid] = (int)d->set_pool_n;
    d->set_len[sid] = n;
    d->matched[sid] = matched & 1;
    memcpy(&d->set_pool[d->set_pool_n], set, (size_t)n * sizeof(int));
    d->set_pool_n += (size_t)n;
    for (int b = 0; b < 256; b++) d->trans[sid * 256 + b] = TRANS_UNFILLED;
    d->hash[h] = sid;
    return sid;
}

/* Step DFA state `sid` over byte `c`: for each pc in the state's set whose op
 * matches `c`, epsilon-close pc+1 into a fresh list; canonicalize and intern the
 * result. Returns the next state id (DFA_DEAD if empty and not matched).
 *
 * Uses the per-pattern scratch (g_seen/g_estack) and a local sort. This runs at
 * most once per (state, byte) pair over the program's lifetime; thereafter the
 * result is cached in d->trans. */
static int dfa_compute_trans(int p, int sid, unsigned char c) {
    pat_engine_t *eng = &g_engines[p];
    prog_t       *pr  = &eng->prog;
    dfa_t        *d   = &g_dfa[p];
    int          *seen = g_seen[p];
    int          *estk = g_estack[p];
    tlist_t      *nl   = &g_nlist[p];

    /* bump a private generation for this closure (reuse g_gen so seen[] stamps
     * stay monotonic with the fallback path's use of the same array). */
    int gen = ++g_gen[p];
    nl->n = 0; nl->matched = 0;

    const int *set = &d->set_pool[d->set_off[sid]];
    int        sn  = d->set_len[sid];
    for (int i = 0; i < sn; i++) {
        inst_t *in = &pr->code[set[i]];
        int matches = 0;
        switch (in->op) {
        case OP_CHAR:  matches = (in->ch == c); break;
        case OP_CLASS: matches = cc_test(&in->cc, c); break;
        case OP_ANY:   matches = (c != '\n'); break;
        default: break;
        }
        if (matches)
            addthread_dfa(pr, nl, seen, gen, estk, set[i] + 1);
    }

    if (nl->n == 0 && !nl->matched) {
        d->trans[sid * 256 + c] = DFA_DEAD;
        return DFA_DEAD;
    }
    /* canonicalize: sort + dedup the pc list */
    qsort(nl->list, (size_t)nl->n, sizeof(int), int_cmp);
    int m = 0;
    for (int i = 0; i < nl->n; i++)
        if (i == 0 || nl->list[i] != nl->list[i-1]) nl->list[m++] = nl->list[i];
    /* dfa_intern may realloc d->trans (when it creates a new state), so capture
     * `next` first, then write through the current base. */
    int next = dfa_intern(d, nl->list, m, nl->matched);
    d->trans[sid * 256 + c] = next;
    return next;
}

/* Build the DFA start state (id 0): closure of pc 0 at a non-boundary position. */
/* Ensure per-pattern NFA scratch is sized for prog.n. scan_one inlines this; the
 * merged group passes (IBAN) call it because they build/step the DFA without ever
 * entering scan_one for these patterns. */
static void ensure_scratch(int p) {
    prog_t *pr = &g_engines[p].prog;
    if (g_seen_cap[p] >= pr->n) return;
    g_seen[p]       = realloc(g_seen[p],       pr->n * sizeof(int));
    g_clist[p].list = realloc(g_clist[p].list, pr->n * sizeof(int));
    g_nlist[p].list = realloc(g_nlist[p].list, pr->n * sizeof(int));
    g_estack[p]     = realloc(g_estack[p],     (2 * pr->n + 1) * sizeof(int));
    if (!g_seen[p] || !g_clist[p].list || !g_nlist[p].list || !g_estack[p]) {
        perror("realloc"); exit(1);
    }
    memset(g_seen[p], 0, pr->n * sizeof(int));
    g_seen_cap[p] = pr->n;
}

static void dfa_build_start(int p) {
    pat_engine_t *eng = &g_engines[p];
    prog_t       *pr  = &eng->prog;
    dfa_t        *d   = &g_dfa[p];
    int          *seen = g_seen[p];
    int          *estk = g_estack[p];
    tlist_t      *cl   = &g_clist[p];

    int gen = ++g_gen[p];
    cl->n = 0; cl->matched = 0;
    addthread_dfa(pr, cl, seen, gen, estk, 0);
    qsort(cl->list, (size_t)cl->n, sizeof(int), int_cmp);
    int m = 0;
    for (int i = 0; i < cl->n; i++)
        if (i == 0 || cl->list[i] != cl->list[i-1]) cl->list[m++] = cl->list[i];
    int sid = dfa_intern(d, cl->list, m, cl->matched);
    /* start must be id 0 (first interned) */
    (void)sid;
}

static size_t scan_one(int p, const char *input, size_t len,
                       mm19b_match_t *out, size_t max, size_t count) {
    pat_engine_t *eng = &g_engines[p];
    prog_t       *pr  = &eng->prog;

    /* ensure scratch is large enough for this pattern's program. The DFS stack can
     * transiently hold duplicate pcs (deduped at pop), bounded by total epsilon
     * edges ≤ 2·prog.n, so size it 2·n+1. */
    if (g_seen_cap[p] < pr->n) {
        g_seen[p]        = realloc(g_seen[p],        pr->n * sizeof(int));
        g_clist[p].list  = realloc(g_clist[p].list,  pr->n * sizeof(int));
        g_nlist[p].list  = realloc(g_nlist[p].list,  pr->n * sizeof(int));
        g_estack[p]      = realloc(g_estack[p],      (2 * pr->n + 1) * sizeof(int));
        if (!g_seen[p] || !g_clist[p].list || !g_nlist[p].list || !g_estack[p]) {
            perror("realloc"); exit(1);
        }
        memset(g_seen[p], 0, pr->n * sizeof(int));
        g_seen_cap[p] = pr->n;
    }
    int     *seen = g_seen[p];
    int     *estk = g_estack[p];
    tlist_t *cl   = &g_clist[p], *nl = &g_nlist[p];

    /* Both inner loops bump g_gen[p] (the persistent, monotonic generation stamp).
     * If it lacks headroom for this call, clear seen[] and restart at 0 once. The
     * DFA path bumps gen only when filling a new transition (bounded, rare after
     * warm-up); the fallback path bumps ~2 per byte. */
    if (g_gen[p] > INT_MAX - (int)(2 * (len + 2))) {
        memset(seen, 0, pr->n * sizeof(int));
        g_gen[p] = 0;
    }

    dfa_t *d = &g_dfa[p];
    if (eng->use_dfa && d->n_states == 0) dfa_build_start(p);  /* lazy, once */

    size_t pos = 0;
    while (pos <= len) {
        /* Literal skip: a match must contain req_literal, so the earliest a
         * match can start at-or-after `pos` is (next literal hit - max_back).
         * Jump there, skipping noise. Patterns with an unbounded prefix have
         * can_skip == 0 and fall through to the plain per-byte scan. */
        if (eng->can_skip) {
            if (len - pos < eng->req_lit_len) break;
            const char *hit = memmem(input + pos, len - pos,
                                     eng->req_literal, eng->req_lit_len);
            if (!hit) break;
            size_t hpos = (size_t)(hit - input);
            size_t start = hpos > eng->max_back ? hpos - eng->max_back : 0;
            if (start > pos) pos = start;
        }

        /* First-byte filter: a match consumes its first byte at `pos`, so if
         * input[pos] is not in the start set, no match can begin here. Skip
         * forward over the run of rejected bytes entirely in C. (Safe superset:
         * never skips a byte a real match could start on.) */
        if (eng->has_first_filter && pos < len) {
            while (pos < len && !cc_test(&eng->first, (unsigned char)input[pos]))
                pos++;
            if (pos >= len) break;
        }

        size_t match_end = (size_t)-1;  /* longest accept end for this start */
        size_t sp = pos;

        /* Determine whether to use the DFA or NFA inner loop for this position.
         * v18.1: use DFA for all patterns EXCEPT boundary-wrapped at pos==0,
         * where ^ must fire correctly (NFA handles it). */
        int use_dfa_here = eng->use_dfa &&
                           !(eng->boundary_wrapped && pos == 0);

        if (use_dfa_here) {
            /* DFA inner loop: one table lookup per byte. */
            int st = 0;
            while (st != DFA_DEAD) {
                if (d->matched[st] && sp - pos >= eng->min_len) match_end = sp;
                if (sp == len) break;
                int next = d->trans[st * 256 + (unsigned char)input[sp]];
                if (next == TRANS_UNFILLED)
                    next = dfa_compute_trans(p, st, (unsigned char)input[sp]);
                st = next;
                sp++;
            }
        } else {
            /* NFA inner loop: used for (a) non-DFA patterns, (b) boundary-wrapped
             * patterns at pos==0 where ^ must fire. */
            int gen = ++g_gen[p];
            cl->n = 0; cl->matched = 0;
            addthread(pr, cl, seen, gen, estk, 0, input, len, pos);
            while (cl->n > 0 || cl->matched) {
                if (cl->matched && sp - pos >= eng->min_len) match_end = sp;
                if (cl->n == 0 || sp == len) break;
                unsigned char c = (unsigned char)input[sp];
                gen = ++g_gen[p];
                nl->n = 0; nl->matched = 0;
                for (int i = 0; i < cl->n; i++) {
                    inst_t *in = &pr->code[cl->list[i]];
                    int matches = 0;
                    switch (in->op) {
                    case OP_CHAR:  matches = (in->ch == c); break;
                    case OP_CLASS: matches = cc_test(&in->cc, c); break;
                    case OP_ANY:   matches = (c != '\n'); break;
                    default: break;
                    }
                    if (matches)
                        addthread(pr, nl, seen, gen, estk, cl->list[i] + 1,
                                  input, len, sp + 1);
                }
                tlist_t tmp = *cl; *cl = *nl; *nl = tmp;
                sp++;
            }
        }

        if (match_end != (size_t)-1) {
            size_t span = match_end - pos;
            if (count < max) out[count++] = (mm19b_match_t){p, pos, span};
            pos = (span == 0) ? pos + 1 : match_end;  /* non-overlapping */
        } else {
            pos++;
        }
    }
    return count;
}

/* v19 merged digit-group scan. One linear pass finds each maximal run of ASCII
 * digits; for every pure-digit member whose [lo,hi] window contains the run length
 * L, it emits the match that member's own per-pattern gsub would produce. This
 * replicates v15's boundary-wrapped semantics — INCLUDING the per-pattern
 * non-overlapping `String#gsub` stream — exactly.
 *
 * Wrapper recap: each member is `(^|[^0-9A-Za-z])([0-9]{lo,hi})([^0-9A-Za-z]|$)`.
 * For a run [rs,re) of length L and a member p with its own `last_end[p]` (end of
 * p's previous match, gsub-style non-overlapping cursor):
 *
 *   Left boundary — one of:
 *     (a) consume a real byte: rs>0 AND input[rs-1] non-alnum AND rs-1 >= last_end[p]
 *         → start = rs-1  (the `[^0-9A-Za-z]` branch);
 *     (b) zero-width BOL: rs==0 OR input[rs-1]=='\n'  → start = rs  (the `^` branch);
 *     else no left boundary is available (e.g. the separator byte was already
 *     consumed by p's previous match and isn't '\n') → p does not match here.
 *   Right boundary — one of:
 *     (a) consume a real byte: re<len AND input[re] non-alnum → end = re+1;
 *     (b) zero-width EOL: re==len → end = re  (the `$` branch);
 *     else input[re] is a letter (run is maximal so never a digit) → no match.
 *
 * Each member keeps its own last_end[] cursor, so adjacent runs sharing a single
 * separator byte are resolved per-pattern exactly as gsub would (the byte is
 * consumed by the earlier match; the later run falls back to BOL only after '\n').
 * Members are visited in ascending id; the harness sorts, so order is cosmetic. */
static int g_digit_last_end[MM88_NUM_PATTERNS];

static size_t scan_digit_group(const char *input, size_t len,
                               mm19b_match_t *out, size_t max, size_t count) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (g_digit_member[p]) g_digit_last_end[p] = 0;

    size_t i = 0;
    while (i < len) {
        unsigned char c = (unsigned char)input[i];
        if (c < '0' || c > '9') { i++; continue; }
        size_t rs = i;
        while (i < len && input[i] >= '0' && input[i] <= '9') i++;
        size_t re = i;                       /* one past last digit */
        size_t L  = re - rs;

        /* Right boundary is shared across all members (independent of last_end):
         * a maximal run's right neighbor is never a digit, so it's either a
         * consumable non-alnum byte, EOL, or a letter (→ no match for anyone). */
        size_t end;
        if (re == len)                                   end = re;       /* $ */
        else if (!isalnum((unsigned char)input[re]))     end = re + 1;   /* consume */
        else                                             continue;       /* letter → reject run */

        for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++) {
            if (!g_digit_member[p]) continue;
            if ((int)L < g_digit_lo[p] || (int)L > g_digit_hi[p]) continue;

            size_t start;
            if (rs > 0 && !isalnum((unsigned char)input[rs-1]) &&
                rs - 1 >= (size_t)g_digit_last_end[p]) {
                start = rs - 1;                          /* consume left boundary */
            } else if (rs == 0 || input[rs-1] == '\n') {
                start = rs;                              /* zero-width ^ */
            } else {
                continue;                                /* no left boundary for p */
            }

            out[count++] = (mm19b_match_t){p, start, end - start};
            g_digit_last_end[p] = (int)end;
        }
        if (count >= max) break;
    }
    return count;
}

/* v19 IBAN union pass. One linear sweep replaces the 18 per-pattern memmem
 * prefix sweeps. At each position whose byte can start a country code, look up
 * the 2-byte prefix; if it owns a pattern, run that pattern's DFA from this
 * position (exactly scan_one's DFA inner loop) and emit the leftmost-longest
 * match. Each member keeps its own non-overlapping cursor (last_end), so a hit
 * advances only that pattern's resume point — identical to scan_one's per-pattern
 * `pos = match_end` semantics. IBAN patterns are never boundary-wrapped and are
 * always use_dfa, so no ^/$ special-casing is needed. */
static size_t g_iban_last_end[MM88_NUM_PATTERNS];

static size_t scan_iban_group(const char *input, size_t len,
                              mm19b_match_t *out, size_t max, size_t count) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (g_iban_member[p]) {
            g_iban_last_end[p] = 0;
            pat_engine_t *eng = &g_engines[p];
            dfa_t *d = &g_dfa[p];
            if (eng->use_dfa && d->n_states == 0) { ensure_scratch(p); dfa_build_start(p); }
        }

    size_t i = 0;
    while (i + 1 < len && count < max) {
        unsigned char c0 = (unsigned char)input[i];
        if (!g_iban_first[c0]) { i++; continue; }
        int p = g_iban_pair[c0][(unsigned char)input[i + 1]];
        if (p < 0) { i++; continue; }
        if (i < g_iban_last_end[p]) { i++; continue; }  /* non-overlapping resume */

        pat_engine_t *eng = &g_engines[p];
        dfa_t *d = &g_dfa[p];
        size_t match_end = (size_t)-1, sp = i;
        int st = 0;
        while (st != DFA_DEAD) {
            if (d->matched[st] && sp - i >= eng->min_len) match_end = sp;
            if (sp == len) break;
            int next = d->trans[st * 256 + (unsigned char)input[sp]];
            if (next == TRANS_UNFILLED)
                next = dfa_compute_trans(p, st, (unsigned char)input[sp]);
            st = next;
            sp++;
        }

        if (match_end != (size_t)-1) {
            size_t span = match_end - i;
            out[count++] = (mm19b_match_t){p, i, span};
            g_iban_last_end[p] = match_end;
            i = (span == 0) ? i + 1 : match_end;
        } else {
            i++;
        }
    }
    return count;
}

/* v19 https:// union pass. One memmem("https://") sweep replaces the four
 * per-pattern first-byte walks (each of which skipped to every 'h'). At each hit
 * we run every member's DFA from that position; members share the prefix, so —
 * unlike the 1:1 IBAN dispatch — we loop over all members per hit. Each keeps its
 * own non-overlapping cursor (last_end), reproducing scan_one's per-pattern
 * `pos = match_end` resume exactly. Members are never boundary-wrapped and always
 * use_dfa. */
static size_t g_https_last_end[MM88_NUM_PATTERNS];

static size_t scan_https_group(const char *input, size_t len,
                               mm19b_match_t *out, size_t max, size_t count) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (g_https_member[p]) {
            g_https_last_end[p] = 0;
            pat_engine_t *eng = &g_engines[p];
            dfa_t *d = &g_dfa[p];
            if (eng->use_dfa && d->n_states == 0) { ensure_scratch(p); dfa_build_start(p); }
        }

    const char *base = input, *p = input;
    size_t rem = len;
    while (count < max) {
        const char *hit = memmem(p, rem, HTTPS_PREFIX, HTTPS_PREFIX_LEN);
        if (!hit) break;
        size_t i = (size_t)(hit - base);

        for (int m = 0; m < MM88_NUM_PATTERNS && count < max; m++) {
            if (!g_https_member[m]) continue;
            if (i < g_https_last_end[m]) continue;  /* non-overlapping resume for m */

            pat_engine_t *eng = &g_engines[m];
            dfa_t *d = &g_dfa[m];
            size_t match_end = (size_t)-1, sp = i;
            int st = 0;
            while (st != DFA_DEAD) {
                if (d->matched[st] && sp - i >= eng->min_len) match_end = sp;
                if (sp == len) break;
                int next = d->trans[st * 256 + (unsigned char)input[sp]];
                if (next == TRANS_UNFILLED)
                    next = dfa_compute_trans(m, st, (unsigned char)input[sp]);
                st = next;
                sp++;
            }
            if (match_end != (size_t)-1) {
                size_t span = match_end - i;
                out[count++] = (mm19b_match_t){m, i, span};
                g_https_last_end[m] = match_end;
            }
        }
        p = hit + 1;                       /* next https:// occurrence */
        rem = len - (size_t)(p - base);
    }
    return count;
}

size_t mm19b_scan(const char *input, size_t len, mm19b_match_t *out, size_t max) {
    size_t count = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++) {
        if (g_digit_member[p]) continue;   /* handled by the merged digit pass */
        if (g_iban_member[p])  continue;   /* handled by the IBAN union pass */
        if (g_https_member[p]) continue;   /* handled by the https:// union pass */
        count = scan_one(p, input, len, out, max, count);
    }
    if (g_have_iban_group && count < max)
        count = scan_iban_group(input, len, out, max, count);
    if (g_have_https_group && count < max)
        count = scan_https_group(input, len, out, max, count);
    if (g_have_digit_group && count < max)
        count = scan_digit_group(input, len, out, max, count);
    return count;
}

/* Bench helper: scan only patterns in [lo,hi]. Used by bench_iban_cost.c to
 * isolate the per-group cost. Not part of the public engine API. */
size_t mm19b_scan_range(int lo, int hi, const char *input, size_t len,
                       mm19b_match_t *out, size_t max) {
    size_t count = 0;
    for (int p = lo; p <= hi && p < MM88_NUM_PATTERNS && count < max; p++) {
        if (g_digit_member[p]) continue;
        count = scan_one(p, input, len, out, max, count);
    }
    return count;
}

const char *mm19b_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 8. Self-test
 * ======================================================================== */

#ifdef MM19B_MAIN
int main(void) {
    mm19b_init();

    int members = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) if (g_digit_member[p]) members++;
    printf("digit-group members merged: %d patterns (one linear pass)\n", members);
    for (int p = 0; p < MM88_NUM_PATTERNS; p++)
        if (g_digit_member[p])
            printf("   [%2d] %-28s [0-9]{%d,%d}\n", p, MM88_PATTERNS[p].name,
                   g_digit_lo[p], g_digit_hi[p]);
    printf("\n");

    struct { const char *input; const char *expect; } tests[] = {
        { "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt" },
        { "contact us at user@example.com please", "email" },
        { "ssn: 123-45-6789 end", "us_ssn" },
        { "server 192.168.1.1 responding", "ipv4" },
        { "key=AKIAIOSFODNN7EXAMPLE end", "aws_access_key_id" },
        { "AIzaSyDxample12345678901234567890123456 here", "google_api_key" },
        { "cc: 4111111111111111 end", "credit_card" },
        { "iban: DE89370400440532013000 end", "iban_de" },
        { "plain text nothing here and no secrets at all", "(none)" },
        { "sk_live_abcdefghijklmnopqrstuvwx end", "stripe_secret_key" },
        { "ghp_ABCDEFGHIJabcdefghij0123456789ABCDEF end", "github_classic_pat" },
        { "id 12345678901 here", "polish_pesel" },
        { "bsn 12345678 end", "dutch_bsn" },
    };
    int n=(int)(sizeof(tests)/sizeof(tests[0]));
    int pass=0;
    mm19b_match_t out[256];

    for (int t=0; t<n; t++) {
        size_t len=strlen(tests[t].input);
        size_t nm=mm19b_scan(tests[t].input, len, out, 256);
        int found=0, no_expect=strcmp(tests[t].expect,"(none)")==0;
        for (size_t m=0; m<nm; m++) {
            const char *pn=mm19b_pattern_name(out[m].pattern_id);
            if (!no_expect && pn && strcmp(pn,tests[t].expect)==0) found=1;
        }
        if (no_expect) found=(nm==0);
        printf("test %2d %-30s %s (%zu matches)\n",
               t, tests[t].expect, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d passed\n", pass, n);
    mm19b_free();
    return pass==n ? 0 : 1;
}
#endif
