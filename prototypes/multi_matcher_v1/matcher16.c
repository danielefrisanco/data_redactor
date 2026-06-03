/* matcher16.c — v15.2: v15.1 + cross-pattern union first-byte bitmap.
 *
 * v15.1 has a per-pattern first-byte filter: for each pattern p, skip bytes
 * not in eng->first before seeding the VM. But the outer loop in mm16_scan
 * still calls scan_one for every pattern at every position that passes that
 * pattern's own filter — even positions where NO pattern can possibly start.
 *
 * v15.2 adds one 256-bit bitmap at init time: g_union_first = OR of all 88
 * eng->first bitmaps (all-1s for any pattern with has_first_filter == 0).
 * mm16_scan walks the input once and builds a compact list of candidate
 * positions — positions where at least one pattern's first byte matches.
 * The per-pattern loop only visits those positions.
 *
 * On sparse/medium inputs most bytes are alphanumeric noise. The union bitmap
 * rejects them in bulk with a single 4-word bit test per byte (4 uint64_t ANDs
 * and ORs), before any per-pattern work begins. On dense/env inputs almost
 * every byte is a candidate anyway, so the overhead is a flat ~N/8 bitmap check.
 *
 * No change to scan_one semantics — same leftmost-longest, non-overlapping gsub.
 * Allocation: g_candidates is a realloc-once buffer sized to len+1, reused
 * across calls. Zero allocation in the hot path after the first call.
 *
 * Build:  make matcher16.so   (shared lib)
 *         make matcher16       (self-test binary)
 */

#define _GNU_SOURCE
#include "matcher16.h"
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
} pat_engine_t;

static pat_engine_t g_engines[MM88_NUM_PATTERNS];
static int          g_initialized = 0;

/* Cross-pattern union bitmap: OR of all 88 eng->first sets (all-1s for any
 * pattern with has_first_filter == 0).  A byte rejected by this bitmap is
 * rejected by every pattern simultaneously — safe to skip entirely.
 * Applied at the top of scan_one's outer loop before the per-pattern checks. */
static cclass_t     g_union_first;
static int          g_union_filter;  /* 0 = all patterns are unfiltered, skip */

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

void mm16_init(void) {
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
    }
    /* Build cross-pattern union: OR all per-pattern first sets together.
     * If any pattern has no filter (accepts any byte) the union is all-1s
     * and the union filter is a no-op — we disable it in that case. */
    memset(&g_union_first, 0, sizeof(g_union_first));
    int union_full = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS && !union_full; p++) {
        if (!g_engines[p].has_first_filter) {
            union_full = 1;
        } else {
            g_union_first.w[0] |= g_engines[p].first.w[0];
            g_union_first.w[1] |= g_engines[p].first.w[1];
            g_union_first.w[2] |= g_engines[p].first.w[2];
            g_union_first.w[3] |= g_engines[p].first.w[3];
        }
    }
    g_union_filter = !union_full;

    g_initialized = 1;
}

void mm16_free(void) {
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

static size_t scan_one(int p, const char *input, size_t len,
                       mm16_match_t *out, size_t max, size_t count) {
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
    int      gen  = g_gen[p];   /* persists across calls; never reused */

    /* One call bumps gen at most ~2 per input byte (one seed + one step). If the
     * persistent counter lacks headroom for that, clear seen[] and restart at 0
     * once — the only time we pay a full memset. */
    if (gen > INT_MAX - (int)(2 * (len + 2))) {
        memset(seen, 0, pr->n * sizeof(int));
        gen = 0;
    }

    size_t pos = 0;
    while (pos <= len) {
        /* Union first-byte skip: skip bytes rejected by ALL 88 patterns at once.
         * The union bitmap is a safe superset — a byte in the union may still be
         * rejected by this specific pattern's own filter, but a byte outside the
         * union is guaranteed to be rejected by every pattern. Applied before the
         * per-pattern literal and first-byte checks to collapse long noise runs. */
        if (g_union_filter && pos < len) {
            while (pos < len && !cc_test(&g_union_first, (unsigned char)input[pos]))
                pos++;
            if (pos >= len) break;
        }

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

        /* seed a fresh simulation starting at `pos` */
        gen++;
        cl->n = 0; cl->matched = 0;
        addthread(pr, cl, seen, gen, estk, 0, input, len, pos);

        size_t match_end = (size_t)-1;  /* longest accept end for this start */
        size_t sp = pos;
        /* Run while there are live byte-consuming threads OR an accept to record.
         * (A closure can be MATCH-only with no stored threads → cl->n == 0 but
         * cl->matched == 1; we must still record that accept.) */
        while (cl->n > 0 || cl->matched) {
            /* O(1) accept check: cl->matched reflects the closure built for sp. */
            if (cl->matched && sp - pos >= eng->min_len) match_end = sp;
            if (cl->n == 0 || sp == len) break;

            unsigned char c = (unsigned char)input[sp];
            gen++;
            nl->n = 0; nl->matched = 0;
            for (int i = 0; i < cl->n; i++) {
                inst_t *in = &pr->code[cl->list[i]];
                int matches = 0;
                switch (in->op) {
                case OP_CHAR:  matches = (in->ch == c); break;
                case OP_CLASS: matches = cc_test(&in->cc, c); break;
                case OP_ANY:   matches = (c != '\n'); break;
                default: break;  /* only CHAR/CLASS/ANY are stored in list */
                }
                if (matches)
                    addthread(pr, nl, seen, gen, estk, cl->list[i] + 1,
                              input, len, sp + 1);
            }
            /* swap cl <-> nl */
            tlist_t tmp = *cl; *cl = *nl; *nl = tmp;
            sp++;
        }

        if (match_end != (size_t)-1) {
            size_t span = match_end - pos;
            if (count < max) out[count++] = (mm16_match_t){p, pos, span};
            pos = (span == 0) ? pos + 1 : match_end;  /* non-overlapping */
        } else {
            pos++;
        }
    }
    g_gen[p] = gen;   /* persist for the next call */
    return count;
}

size_t mm16_scan(const char *input, size_t len, mm16_match_t *out, size_t max) {
    size_t count = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++)
        count = scan_one(p, input, len, out, max, count);
    return count;
}

const char *mm16_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 8. Self-test
 * ======================================================================== */

#ifdef MM16_MAIN
int main(void) {
    mm16_init();

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
    };
    int n=(int)(sizeof(tests)/sizeof(tests[0]));
    int pass=0;
    mm16_match_t out[256];

    for (int t=0; t<n; t++) {
        size_t len=strlen(tests[t].input);
        size_t nm=mm16_scan(tests[t].input, len, out, 256);
        int found=0, no_expect=strcmp(tests[t].expect,"(none)")==0;
        for (size_t m=0; m<nm; m++) {
            const char *pn=mm16_pattern_name(out[m].pattern_id);
            if (!no_expect && pn && strcmp(pn,tests[t].expect)==0) found=1;
        }
        if (no_expect) found=(nm==0);
        printf("test %2d %-30s %s (%zu matches)\n",
               t, tests[t].expect, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d passed\n", pass, n);
    mm16_free();
    return pass==n ? 0 : 1;
}
#endif
