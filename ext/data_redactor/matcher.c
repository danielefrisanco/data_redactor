/* matcher.c — the v19 multi-pattern engine, ported into the gem.
 *
 * Ported from prototypes/multi_pattern_matcher/matcher19.c (the standalone prototype
 * proven in docs/research_log.md). The matching core — regex parser -> Thompson
 * bytecode -> per-pattern lazy DFA, the v14 first-byte filter, the v12 literal
 * skip, the v18.1 anchor lowering, the v19 pure-digit and IBAN selective merges,
 * and the v19.1 EOL-at-buffer-end fix — is unchanged. Two things differ from the
 * prototype:
 *
 *   1. Pattern source. The prototype baked in a generated MM88_PATTERNS table.
 *      Here the built-in engines are built at mm_init() from the gem's own
 *      pattern_strings[]/boundary_wrapped[]/pattern_required_literal[] arrays
 *      (patterns.{h,c} is the single source of truth — CLAUDE.md), and custom
 *      patterns are appended dynamically via mm_add()/mm_remove(). So engine
 *      storage is a growable array, not a fixed [NUM_PATTERNS] one.
 *
 *   2. Output contract. mm_scan() takes an enable_bits gate and emits ORIGINAL-
 *      frame (pattern_id, start, span) events for ALL enabled patterns in one
 *      pass. The caller applies mm_resolve() (longest-match-wins greedy claim:
 *      longest span at each position wins, equal lengths broken by lower
 *      pattern_id) to pick the final non-overlapping set. See TODO.md §1d Gap 5
 *      and the overlap-resolution specs in spec/data_redactor_spec.rb.
 *
 * The infix-literal classification and the BM_INFIX hint table below are ported
 * from prototypes/multi_pattern_matcher/gen_patterns.rb (which derived them from the
 * same gem arrays at codegen time). They are pure optimisation hints — the
 * first-byte filter computed from the program itself is what guarantees
 * correctness — so a stale hint can only cost speed, never miss a match.
 */

/* _GNU_SOURCE must be defined before any system header so memmem(3) is declared
 * with its correct void* prototype (otherwise it is implicitly int-returning and
 * its result is truncated to a garbage pointer). mkmf also passes -D_GNU_SOURCE
 * on the gem build; the guard avoids a redefinition warning there. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "matcher.h"
#include "patterns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>

/* ========================================================================
 * 0. Utilities
 * ======================================================================== */

/* Named mm_x* (not xmalloc/xcalloc) to avoid clashing with Ruby's same-named
 * macros if a future include pulls in ruby.h. Plain libc malloc/calloc — this
 * engine owns its buffers and does not use Ruby's GC-managed allocator. */
static void *mm_xmalloc(size_t n) {
    void *p = malloc(n); if (!p) { perror("malloc"); exit(1); } return p;
}
static void *mm_xcalloc(size_t n, size_t s) {
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
    } else { fprintf(stderr,"data_redactor matcher: unknown POSIX class [:%.*s:]\n",(int)len,cls); exit(1); }
}

/* ========================================================================
 * 2. Regex parser → AST
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
    ast_node_t *n = mm_xcalloc(1, sizeof(*n)); n->type=t; return n;
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
 * ======================================================================== */

typedef enum {
    OP_CHAR, OP_CLASS, OP_ANY, OP_SPLIT, OP_JMP, OP_BOL, OP_EOL, OP_MATCH,
} opcode_t;

typedef struct {
    opcode_t      op;
    unsigned char ch;
    cclass_t      cc;
    int           x, y;
} inst_t;

typedef struct {
    inst_t  *code;
    int      n;
    int      cap;
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
 * ======================================================================== */

static void emit_node(prog_t *pr, ast_node_t *node);

static void emit_repeat(prog_t *pr, ast_node_t *node) {
    ast_node_t *child = node->left;
    int lo = node->lo, hi = node->hi;

    for (int i = 0; i < lo; i++) emit_node(pr, child);

    if (hi == -1) {
        int l = prog_emit(pr, OP_SPLIT);
        emit_node(pr, child);
        int j = prog_emit(pr, OP_JMP);
        pr->code[j].x = l;
        pr->code[l].x = l + 1;
        pr->code[l].y = pr->n;
    } else {
        int n_opt = hi - lo;
        int *splits = n_opt ? mm_xmalloc(n_opt * sizeof(int)) : NULL;
        for (int i = 0; i < n_opt; i++) {
            splits[i] = prog_emit(pr, OP_SPLIT);
            pr->code[splits[i]].x = splits[i] + 1;
            emit_node(pr, child);
        }
        for (int i = 0; i < n_opt; i++) pr->code[splits[i]].y = pr->n;
        free(splits);
    }
}

static void emit_node(prog_t *pr, ast_node_t *node) {
    if (!node) return;
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
 * 5. Min/max match length
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
 * 6. Per-pattern engine + dynamic storage
 *
 * The prototype used fixed [MM88_NUM_PATTERNS] arrays. To carry custom patterns
 * the storage is now a single growable array `g_eng` of `engine_t`, each owning
 * its program, lazy-DFA cache, and per-scan scratch (so a custom add/remove only
 * touches one slot). Built-ins occupy slots [0, NUM_PATTERNS); customs follow.
 * ======================================================================== */

#define WRAP_PFX "(^|[^0-9A-Za-z])("
#define WRAP_SFX ")([^0-9A-Za-z]|$)"

#define DFA_DEAD       (-1)
#define TRANS_UNFILLED (-2)

typedef struct {
    int     *set_pool;
    size_t   set_pool_n, set_pool_cap;
    int     *set_off;
    int     *set_len;
    int     *matched;
    int     *trans;
    int      n_states, states_cap;
    int     *hash;
    int      hash_cap;
} dfa_t;

typedef struct {
    int      *list;
    int       n;
    int       matched;
} tlist_t;

/* engine_t holds ONLY immutable, compiled state — built once at mm_init()/mm_add()
 * and never written during a scan, so it is safe to share read-only across
 * threads. All per-scan mutable state (NFA scratch, merge cursors) and the lazy
 * DFA cache live in scan_state_t, which is per-thread (t_block below). This
 * split is what lets redact/scan release the GVL: with no shared writes during a
 * scan, concurrent scans on distinct threads cannot race. */
typedef struct {
    prog_t      prog;
    size_t      min_len;
    const char *req_literal;    /* points into a heap copy owned by this engine */
    char       *req_literal_own;
    size_t      req_lit_len;
    int         req_lit_at_start;
    int         can_skip;
    size_t      max_back;
    cclass_t    first;
    int         has_first_filter;
    int         use_dfa;
    int         boundary_wrapped;
    int         keyname_anchored;
    int         has_eol;
    size_t      max_len;
    /* selective-merge membership (built-ins only; customs never join a merge) */
    int         digit_member, digit_lo, digit_hi;
    int         iban_member;
} engine_t;

/* Per-engine MUTABLE scan state. One per engine, owned per-thread (t_state).
 * The DFA cache warms lazily across this thread's scans; the rest is reset each
 * scan. seen_cap==0 / dfa.n_states==0 means "not yet warmed" for this thread. */
typedef struct {
    dfa_t       dfa;
    int        *seen;
    int         seen_cap;
    tlist_t     clist, nlist;
    int        *estack;
    int         gen;
    int         digit_last_end;   /* selective-merge non-overlap cursors */
    size_t      iban_last_end;
} scan_state_t;

static engine_t *g_eng    = NULL;
static int       g_eng_n  = 0;    /* engines built (NUM_PATTERNS + custom_n) */
static int       g_eng_cap= 0;
static int       g_custom_n = 0;
static int       g_initialized = 0;

/* Bumped whenever the pattern set changes (mm_add/mm_remove/mm_clear_custom).
 * A thread whose cached t_gen lags this value drops its whole scan-state cache
 * and rebuilds — the simplest safe invalidation (slot p may now hold a
 * different pattern after mm_remove compacts g_eng). Registration is rare, so
 * the full rebuild is cheap; a surgical per-slot invalidation is a possible
 * future refinement (see TODO §"Full thread safety"). */
static unsigned g_pattern_gen = 0;

/* Per-thread mutable scan state: one scan_state_t per engine, lazily grown to
 * g_eng_n. Held in a heap block whose header carries the element count, so the
 * pthread_key destructor (which frees the block at thread exit) is fully
 * self-contained — it must NOT read __thread storage, which may already be torn
 * down when key destructors run. The __thread pointer is the fast hot-path
 * handle; the key holds the same pointer purely so it can be reclaimed on exit.
 * This bounds memory for processes that churn many short-lived scanning threads;
 * fixed pools (Puma/Sidekiq) just reuse the block for the thread's lifetime. */
typedef struct {
    int          n;          /* number of scan_state_t entries in states[] */
    scan_state_t states[];   /* flexible array member */
} thread_block_t;

static __thread thread_block_t *t_block = NULL;
static __thread unsigned        t_gen   = 0;

static pthread_key_t  t_block_key;
static pthread_once_t t_block_key_once = PTHREAD_ONCE_INIT;

/* IBAN union-pass dispatch (built-ins only): unique 2-byte country prefixes. */
static int g_iban_first[256];
static int g_iban_pair[256][256];
static int g_have_iban_group = 0;
static int g_have_digit_group = 0;

/* BM infix-literal hints for always-candidate patterns, ported verbatim from
 * gen_patterns.rb's BM_INFIX. Matched by pattern NAME so it survives reordering.
 * Pure speed hints; correctness comes from the program's first-byte filter. */
static const struct { const char *name, *lit; } BM_INFIX[] = {
    { "aws_s3_presigned_url",         "X-Amz-Signature=" },
    { "microsoft_teams_webhook",      ".webhook.office.com" },
    { "slack_webhook_url",            "hooks.slack.com" },
    { "sentry_dsn",                   ".ingest.sentry.io" },
    { "hashicorp_terraform_api_token",".atlasv1." },
    { "uri_with_password",            "://" },
    { "bearer_token",                 "earer " },
    { "email",                        "@" },
    { "uuid_v4",                      "-4" },
    { "phone_e164",                   "+" },
    { "launchdarkly_api_key",         "-" },
};

static const char *bm_infix_for(const char *name) {
    for (size_t i = 0; i < sizeof(BM_INFIX)/sizeof(BM_INFIX[0]); i++)
        if (!strcmp(BM_INFIX[i].name, name)) return BM_INFIX[i].lit;
    return NULL;
}

/* True iff `literal` is the literal start of `regex` once backslash escapes are
 * collapsed (mirrors gen_patterns.rb's regex_starts_with_literal?). Used to
 * classify a required literal as start-anchored vs infix. */
static int regex_starts_with_literal(const char *regex, const char *lit) {
    const char *r = regex;
    const char *l = lit;
    while (*l) {
        char rc;
        if (*r == '\\' && *(r+1)) { rc = *(r+1); r += 2; }
        else if (*r)              { rc = *r; r += 1; }
        else                      return 0;
        if (rc != *l) return 0;
        l++;
    }
    return 1;
}

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
        if (!has_c) return 0;
        b = c;
    } else {
        b = a;
    }
    if (*p != '}' || *(p+1) != '\0') return 0;
    *lo = a; *hi = b;
    return 1;
}

static int parse_iban_prefix(const char *re, int boundary_wrapped_flag,
                             unsigned char *c0, unsigned char *c1) {
    if (boundary_wrapped_flag) return 0;
    if (!(re[0] >= 'A' && re[0] <= 'Z')) return 0;
    if (!(re[1] >= 'A' && re[1] <= 'Z')) return 0;
    if (strncmp(re + 2, "[0-9]{2}", 8) != 0) return 0;
    *c0 = (unsigned char)re[0];
    *c1 = (unsigned char)re[1];
    return 1;
}

static void compute_first_set(const prog_t *pr, cclass_t *out, int *full) {
    memset(out, 0, sizeof(*out));
    *full = 0;
    if (pr->n > 2048) { *full = 1; return; }
    uint8_t seen[2048];
    int stack[2048], top = 0;
    memset(seen, 0, (size_t)pr->n);
    stack[top++] = 0;
    while (top > 0) {
        int pc = stack[--top];
        if (pc < 0 || pc >= pr->n || seen[pc]) continue;
        seen[pc] = 1;
        const inst_t *in = &pr->code[pc];
        switch (in->op) {
        case OP_JMP:   stack[top++] = in->x; break;
        case OP_SPLIT: stack[top++] = in->x; stack[top++] = in->y; break;
        case OP_BOL: case OP_EOL: stack[top++] = pc + 1; break;
        case OP_CHAR:  cc_set(out, in->ch); break;
        case OP_CLASS: out->w[0]|=in->cc.w[0]; out->w[1]|=in->cc.w[1];
                       out->w[2]|=in->cc.w[2]; out->w[3]|=in->cc.w[3]; break;
        case OP_ANY:   cc_add_range(out, 0, 255); cc_unset(out, '\n'); break;
        case OP_MATCH: *full = 1; break;
        }
        if (*full) return;
    }
}

static int prog_has_eol(const prog_t *pr) {
    for (int i = 0; i < pr->n; i++)
        if (pr->code[i].op == OP_EOL) return 1;
    return 0;
}

/* Build one engine (program + length bounds + literal/first-byte hints) from a
 * CORE regex and a boundary flag. `name` may be NULL (customs) — it is only used
 * to look up the BM infix hint table. Does NOT touch the merge dispatch tables;
 * the caller records merge membership for built-ins. */
static void engine_build(engine_t *eng, const char *core_regex, int boundary,
                         const char *name) {
    memset(eng, 0, sizeof(*eng));

    const char *src = core_regex;
    char *to_free = NULL;
    if (boundary) {
        size_t len = strlen(WRAP_PFX)+strlen(core_regex)+strlen(WRAP_SFX)+1;
        to_free = mm_xmalloc(len);
        snprintf(to_free, len, "%s%s%s", WRAP_PFX, core_regex, WRAP_SFX);
        src = to_free;
    }

    ast_node_t *ast = parse_regex(src);
    eng->min_len = ast_min_len(ast);
    size_t max_len = ast_max_len(ast);
    emit_node(&eng->prog, ast);
    prog_emit(&eng->prog, OP_MATCH);
    ast_free(ast);
    free(to_free);

    /* The literal-skip hint is attached separately by engine_set_literal() after
     * this build: built-ins get pattern_required_literal[] (start/infix
     * reclassified from the regex) or a BM infix hint; customs get none and take
     * the per-pattern full scan — safe, just unoptimised. `name` is consumed
     * there, not here. */

    /* v14 first-byte filter (correctness-bearing). */
    int full;
    compute_first_set(&eng->prog, &eng->first, &full);
    eng->has_first_filter = !full;

    eng->use_dfa = !full;
    eng->boundary_wrapped = boundary;
    eng->has_eol = prog_has_eol(&eng->prog);
    eng->max_len = max_len;
    (void)name;
}

/* Attach a literal-skip hint to an already-built engine. `lit` may be NULL.
 * Must run after engine_build (reads eng->boundary_wrapped / eng->max_len). */
static void engine_set_literal(engine_t *eng, const char *lit, int at_start) {
    if (!lit) return;
    eng->req_literal_own = strdup(lit);
    if (!eng->req_literal_own) { perror("strdup"); exit(1); }
    eng->req_literal      = eng->req_literal_own;
    eng->req_lit_len      = strlen(lit);
    eng->req_lit_at_start = at_start;

    /* The literal is classified against the CORE regex, but the compiled program
     * is the boundary-wrapped (^|[^0-9A-Za-z])(CORE)([^...]|$) form, whose leading
     * group consumes up to 1 byte before the CORE. So the match can start 1 byte
     * before the literal even for a "start-anchored" literal. Account for that in
     * max_back, else the literal skip jumps past the boundary byte and misses the
     * match (e.g. swiss_ahv "756." in " 756.1234.5678.90"). */
    size_t bw = eng->boundary_wrapped ? 1 : 0;
    if (at_start) {
        eng->can_skip = 1; eng->max_back = bw;
    } else if (eng->max_len != LEN_UNBOUNDED && eng->max_len >= eng->req_lit_len) {
        eng->can_skip = 1; eng->max_back = eng->max_len - eng->req_lit_len;
    } else {
        eng->can_skip = 0;
    }
}

static void engine_free(engine_t *eng) {
    free(eng->prog.code);
    free(eng->req_literal_own);
    memset(eng, 0, sizeof(*eng));
}

/* Free one thread's mutable scan state for an engine (scratch + DFA cache).
 * Used when a thread drops its cache on a pattern-set generation change. */
static void free_scan_state(scan_state_t *st) {
    free(st->seen);
    free(st->clist.list);
    free(st->nlist.list);
    free(st->estack);
    dfa_t *d = &st->dfa;
    free(d->set_pool); free(d->set_off); free(d->set_len);
    free(d->matched);  free(d->trans);   free(d->hash);
    memset(st, 0, sizeof(*st));
}

/* pthread_key destructor: free a thread's whole block at thread exit. Reads only
 * the passed-in pointer + its header count — no __thread access (unsafe here). */
static void free_thread_block(void *p) {
    thread_block_t *b = (thread_block_t *)p;
    if (!b) return;
    for (int i = 0; i < b->n; i++) free_scan_state(&b->states[i]);
    free(b);
}

static void make_t_block_key(void) {
    if (pthread_key_create(&t_block_key, free_thread_block) != 0) {
        perror("pthread_key_create"); exit(1);
    }
}

/* Return this thread's scan_state_t array, synced to the current pattern set.
 * Drops the whole cache if the pattern set changed (generation guard), then
 * lazily grows (zero-initialised) to cover every engine. Called under the
 * custom-pattern mutex during a scan, so g_pattern_gen / g_eng_n are stable.
 * The owning block is registered with t_block_key so it is freed at thread exit;
 * the key value is re-set after any (re)allocation since the block may move. */
static scan_state_t *thread_state(void) {
    pthread_once(&t_block_key_once, make_t_block_key);

    if (t_gen != g_pattern_gen) {
        free_thread_block(t_block);
        t_block = NULL;
        pthread_setspecific(t_block_key, NULL);
        t_gen = g_pattern_gen;
    }
    int have = t_block ? t_block->n : 0;
    if (have < g_eng_n) {
        thread_block_t *nb = realloc(t_block,
            sizeof(thread_block_t) + (size_t)g_eng_n * sizeof(scan_state_t));
        if (!nb) { perror("realloc"); exit(1); }
        memset(&nb->states[have], 0,
               (size_t)(g_eng_n - have) * sizeof(scan_state_t));
        nb->n = g_eng_n;
        t_block = nb;
        pthread_setspecific(t_block_key, nb);
    }
    return t_block->states;
}

/* ========================================================================
 * 7. Thompson VM
 * ======================================================================== */

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
            stk[top++] = in->y;
            stk[top++] = in->x;
            break;
        case OP_BOL:
            if (pos == 0 || input[pos-1] == '\n') stk[top++] = pc + 1;
            break;
        case OP_EOL:
            /* addthread_dfa seeds the position-independent closure with
             * pos=1,len=0 (pos>len), so guard the input[pos] read against
             * pos<len to avoid reading past the buffer for that dummy seed. */
            if (pos == len || (pos < len && input[pos] == '\n')) stk[top++] = pc + 1;
            break;
        case OP_MATCH:
            tl->matched = 1;
            break;
        default:
            tl->list[tl->n++] = pc;
            break;
        }
    }
}

static void addthread_dfa(prog_t *pr, tlist_t *tl, int *seen, int gen, int *stk, int pc0) {
    addthread(pr, tl, seen, gen, stk, pc0, "", 0, 1);
}

/* ========================================================================
 * 8. Lazy DFA construction
 * ======================================================================== */

static int int_cmp(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

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
    /* Start small (8) and double. Each state owns a 1 KB transition row, and the
     * DFA cache is now per-thread, so the initial cap is the per-thread memory
     * floor multiplied across every engine. Most patterns settle at 1-14 states
     * (max 45), so a floor of 8 fits the common case in 8 KB instead of 64 KB
     * (~4x less per-thread memory across 79 DFA engines); the few larger DFAs
     * just do a couple extra doublings during warmup, off the hot path. */
    int newcap = d->states_cap ? d->states_cap * 2 : 8;
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
    d->hash = mm_xmalloc((size_t)newcap * sizeof(int));
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

static int dfa_intern(dfa_t *d, const int *set, int n, int matched) {
    if (d->n_states * 4 >= d->hash_cap * 3) dfa_rehash(d);
    int mask = d->hash_cap - 1;
    unsigned h = dfa_hash(set, n, matched, mask);
    while (d->hash[h] != -1) {
        int sid = d->hash[h];
        if (dfa_set_eq(d, sid, set, n, matched)) return sid;
        h = (h + 1) & (unsigned)mask;
    }
    dfa_grow_states(d);
    int sid = d->n_states++;
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

static void ensure_scratch(engine_t *eng, scan_state_t *st) {
    prog_t *pr = &eng->prog;
    if (st->seen_cap >= pr->n) return;
    st->seen       = realloc(st->seen,       pr->n * sizeof(int));
    st->clist.list = realloc(st->clist.list, pr->n * sizeof(int));
    st->nlist.list = realloc(st->nlist.list, pr->n * sizeof(int));
    st->estack     = realloc(st->estack,     (2 * pr->n + 1) * sizeof(int));
    if (!st->seen || !st->clist.list || !st->nlist.list || !st->estack) {
        perror("realloc"); exit(1);
    }
    memset(st->seen, 0, pr->n * sizeof(int));
    st->seen_cap = pr->n;
}

static int dfa_compute_trans(engine_t *eng, scan_state_t *st, int sid, unsigned char c) {
    prog_t  *pr  = &eng->prog;
    dfa_t   *d   = &st->dfa;
    int     *seen = st->seen;
    int     *estk = st->estack;
    tlist_t *nl   = &st->nlist;

    int gen = ++st->gen;
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
    qsort(nl->list, (size_t)nl->n, sizeof(int), int_cmp);
    int m = 0;
    for (int i = 0; i < nl->n; i++)
        if (i == 0 || nl->list[i] != nl->list[i-1]) nl->list[m++] = nl->list[i];
    int next = dfa_intern(d, nl->list, m, nl->matched);
    d->trans[sid * 256 + c] = next;
    return next;
}

static void dfa_build_start(engine_t *eng, scan_state_t *st) {
    prog_t  *pr  = &eng->prog;
    dfa_t   *d   = &st->dfa;
    int     *seen = st->seen;
    int     *estk = st->estack;
    tlist_t *cl   = &st->clist;

    int gen = ++st->gen;
    cl->n = 0; cl->matched = 0;
    addthread_dfa(pr, cl, seen, gen, estk, 0);
    qsort(cl->list, (size_t)cl->n, sizeof(int), int_cmp);
    int m = 0;
    for (int i = 0; i < cl->n; i++)
        if (i == 0 || cl->list[i] != cl->list[i-1]) cl->list[m++] = cl->list[i];
    dfa_intern(d, cl->list, m, cl->matched);
}

/* ========================================================================
 * 9. Per-pattern scan (scan_one) — identical logic to the prototype
 * ======================================================================== */

static size_t scan_one(int p, scan_state_t *state, const char *input, size_t len,
                       mm_match_t *out, size_t max, size_t count) {
    engine_t     *eng = &g_eng[p];
    scan_state_t *sst = &state[p];
    prog_t       *pr  = &eng->prog;

    ensure_scratch(eng, sst);
    int     *seen = sst->seen;
    int     *estk = sst->estack;
    tlist_t *cl   = &sst->clist, *nl = &sst->nlist;

    if (sst->gen > INT_MAX - (int)(2 * (len + 2))) {
        memset(seen, 0, pr->n * sizeof(int));
        sst->gen = 0;
    }

    dfa_t *d = &sst->dfa;
    if (eng->use_dfa && d->n_states == 0) dfa_build_start(eng, sst);

    size_t pos = 0;
    while (pos <= len) {
        if (eng->can_skip) {
            if (len - pos < eng->req_lit_len) break;
            const char *hit = memmem(input + pos, len - pos,
                                     eng->req_literal, eng->req_lit_len);
            if (!hit) break;
            size_t hpos = (size_t)(hit - input);
            size_t start = hpos > eng->max_back ? hpos - eng->max_back : 0;
            if (start > pos) pos = start;
        }

        if (eng->has_first_filter && pos < len) {
            while (pos < len && !cc_test(&eng->first, (unsigned char)input[pos]))
                pos++;
            if (pos >= len) break;
        }

        size_t match_end = (size_t)-1;
        size_t sp = pos;

        int near_eol = eng->has_eol &&
                       (eng->max_len == LEN_UNBOUNDED ||
                        pos + eng->max_len >= len);
        int use_dfa_here = eng->use_dfa &&
                           !(eng->boundary_wrapped && pos == 0) &&
                           !near_eol;

        if (use_dfa_here) {
            int st = 0;
            while (st != DFA_DEAD) {
                if (d->matched[st] && sp - pos >= eng->min_len) match_end = sp;
                if (sp == len) break;
                int next = d->trans[st * 256 + (unsigned char)input[sp]];
                if (next == TRANS_UNFILLED)
                    next = dfa_compute_trans(eng, sst, st, (unsigned char)input[sp]);
                st = next;
                sp++;
            }
        } else {
            int gen = ++sst->gen;
            cl->n = 0; cl->matched = 0;
            addthread(pr, cl, seen, gen, estk, 0, input, len, pos);
            while (cl->n > 0 || cl->matched) {
                if (cl->matched && sp - pos >= eng->min_len) match_end = sp;
                if (cl->n == 0 || sp == len) break;
                unsigned char c = (unsigned char)input[sp];
                gen = ++sst->gen;
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
            size_t core_so = pos, core_eo = match_end;
            if (eng->boundary_wrapped) {
                /* The wrapper is (^|[^0-9A-Za-z])(CORE)([^0-9A-Za-z]|$). The gem
                 * redacts only CORE and preserves the boundary bytes. The CORE's
                 * outer chars are alphanumeric for every boundary-wrapped pattern,
                 * while a consumed boundary byte is [^0-9A-Za-z]; so a non-alnum
                 * first/last byte of the span is a consumed boundary (^/$ are
                 * zero-width and leave an alnum edge). Strip them to get CORE. */
                if (core_so < core_eo &&
                    !isalnum((unsigned char)input[core_so])) core_so++;
                if (core_eo > core_so &&
                    !isalnum((unsigned char)input[core_eo-1])) core_eo--;
            } else if (eng->keyname_anchored) {
                /* The match is KEY<sep>VALUE (e.g. PASSWORD="hunter2"). We redact
                 * only VALUE and keep KEY<sep> so logs stay greppable. The value
                 * grammar forbids '=' and ':' unquoted, so the FIRST separator in
                 * the span unambiguously ends the key. Advance past it, then past
                 * surrounding whitespace and a single opening/closing quote. */
                size_t s = core_so;
                while (s < core_eo && input[s] != '=' && input[s] != ':') s++;
                if (s < core_eo) s++;                       /* skip the separator */
                while (s < core_eo &&
                       (input[s] == ' ' || input[s] == '\t')) s++;
                if (s < core_eo &&
                    (input[s] == '"' || input[s] == '\'')) {
                    char q = input[s];
                    s++;
                    if (core_eo > s && input[core_eo-1] == q) core_eo--;
                }
                core_so = s;
            }
            if (count < max)
                out[count++] = (mm_match_t){p, core_so, core_eo - core_so};
            pos = (span == 0) ? pos + 1 : match_end;
        } else {
            pos++;
        }
    }
    return count;
}

/* ========================================================================
 * 10. Selective merges (digit run pass + IBAN union pass)
 * ======================================================================== */

static size_t scan_digit_group(scan_state_t *state, const char *input, size_t len,
                               const int *enable_bits, size_t n_bits,
                               mm_match_t *out, size_t max, size_t count) {
    for (int p = 0; p < g_eng_n; p++)
        if (g_eng[p].digit_member) state[p].digit_last_end = 0;

    size_t i = 0;
    while (i < len) {
        unsigned char c = (unsigned char)input[i];
        if (c < '0' || c > '9') { i++; continue; }
        size_t rs = i;
        while (i < len && input[i] >= '0' && input[i] <= '9') i++;
        size_t re = i;
        size_t L  = re - rs;

        size_t end;
        if (re == len)                                   end = re;
        else if (!isalnum((unsigned char)input[re]))     end = re + 1;
        else                                             continue;

        for (int p = 0; p < g_eng_n && count < max; p++) {
            engine_t *eng = &g_eng[p];
            if (!eng->digit_member) continue;
            if ((size_t)p < n_bits && !enable_bits[p]) continue;
            if ((int)L < eng->digit_lo || (int)L > eng->digit_hi) continue;

            size_t start;
            if (rs > 0 && !isalnum((unsigned char)input[rs-1]) &&
                rs - 1 >= (size_t)state[p].digit_last_end) {
                start = rs - 1;
            } else if (rs == 0 || input[rs-1] == '\n') {
                start = rs;
            } else {
                continue;
            }

            /* The boundary-wrapped span is [start, end); the gem redacts only the
             * CORE token (the digit run [rs, re)) and copies the boundary bytes
             * back verbatim. Emit CORE coordinates; keep the per-pattern gsub
             * cursor (digit_last_end) on the FULL span so adjacent runs sharing a
             * separator are resolved exactly as gsub would. */
            (void)start;
            out[count++] = (mm_match_t){p, rs, re - rs};
            state[p].digit_last_end = (int)end;
        }
        if (count >= max) break;
    }
    return count;
}

static size_t scan_iban_group(scan_state_t *state, const char *input, size_t len,
                              const int *enable_bits, size_t n_bits,
                              mm_match_t *out, size_t max, size_t count) {
    for (int p = 0; p < g_eng_n; p++)
        if (g_eng[p].iban_member) {
            state[p].iban_last_end = 0;
            engine_t *eng = &g_eng[p];
            if (eng->use_dfa && state[p].dfa.n_states == 0) {
                ensure_scratch(eng, &state[p]); dfa_build_start(eng, &state[p]);
            }
        }

    size_t i = 0;
    while (i + 1 < len && count < max) {
        unsigned char c0 = (unsigned char)input[i];
        if (!g_iban_first[c0]) { i++; continue; }
        int p = g_iban_pair[c0][(unsigned char)input[i + 1]];
        if (p < 0) { i++; continue; }
        if ((size_t)p < n_bits && !enable_bits[p]) { i++; continue; }
        if (i < state[p].iban_last_end) { i++; continue; }

        engine_t     *eng = &g_eng[p];
        scan_state_t *sst = &state[p];
        dfa_t *d = &sst->dfa;
        size_t match_end = (size_t)-1, sp = i;
        int st = 0;
        while (st != DFA_DEAD) {
            if (d->matched[st] && sp - i >= eng->min_len) match_end = sp;
            if (sp == len) break;
            int next = d->trans[st * 256 + (unsigned char)input[sp]];
            if (next == TRANS_UNFILLED)
                next = dfa_compute_trans(eng, sst, st, (unsigned char)input[sp]);
            st = next;
            sp++;
        }

        if (match_end != (size_t)-1) {
            size_t span = match_end - i;
            out[count++] = (mm_match_t){p, i, span};
            sst->iban_last_end = match_end;
            i = (span == 0) ? i + 1 : match_end;
        } else {
            i++;
        }
    }
    return count;
}

/* ========================================================================
 * 11. Init / add / remove
 * ======================================================================== */

static engine_t *eng_grow_one(void) {
    if (g_eng_n >= g_eng_cap) {
        int newcap = g_eng_cap ? g_eng_cap * 2 : (NUM_PATTERNS + 16);
        g_eng = realloc(g_eng, (size_t)newcap * sizeof(engine_t));
        if (!g_eng) { perror("realloc"); exit(1); }
        g_eng_cap = newcap;
    }
    return &g_eng[g_eng_n++];
}

void mm_init(void) {
    if (g_initialized) return;

    for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++) g_iban_pair[a][b] = -1;

    for (int p = 0; p < NUM_PATTERNS; p++) {
        engine_t *eng = eng_grow_one();
        engine_build(eng, pattern_strings[p], boundary_wrapped[p], pattern_names[p]);
        eng->keyname_anchored = keyname_anchored[p];

        const char *lit = pattern_required_literal[p];
        if (lit) {
            int at_start = regex_starts_with_literal(pattern_strings[p], lit);
            engine_set_literal(eng, lit, at_start);
        } else {
            const char *bm = bm_infix_for(pattern_names[p]);
            if (bm) engine_set_literal(eng, bm, 0);
        }

        int lo, hi;
        if (boundary_wrapped[p] && parse_pure_digit(pattern_strings[p], &lo, &hi)) {
            eng->digit_member = 1; eng->digit_lo = lo; eng->digit_hi = hi;
            g_have_digit_group = 1;
        }
        unsigned char c0, c1;
        if (parse_iban_prefix(pattern_strings[p], boundary_wrapped[p], &c0, &c1)) {
            eng->iban_member = 1;
            g_iban_first[c0] = 1;
            g_iban_pair[c0][c1] = p;
            g_have_iban_group = 1;
        }
    }
    g_custom_n = 0;
    g_initialized = 1;
}

int mm_add(const char *regex, int boundary) {
    if (!g_initialized) mm_init();
    engine_t *eng = eng_grow_one();
    engine_build(eng, regex, boundary, NULL);
    /* Custom patterns never join the selective merges (TODO §1d Gap 4): they keep
     * the per-pattern path. No digit/IBAN membership, no literal-skip hint. */
    g_custom_n++;
    g_pattern_gen++;   /* invalidate every thread's cached scan state */
    return 0;
}

void mm_remove(int idx) {
    int slot = NUM_PATTERNS + idx;
    if (idx < 0 || slot >= g_eng_n) return;
    engine_free(&g_eng[slot]);
    /* compact: shift the trailing customs down one to preserve registration
     * order (slot == NUM_PATTERNS + position). */
    for (int s = slot; s < g_eng_n - 1; s++)
        g_eng[s] = g_eng[s + 1];
    g_eng_n--;
    g_custom_n--;
    /* slot p now holds a DIFFERENT pattern (compaction), so every thread's
     * scan-state cache indexed by p is stale — invalidate. */
    g_pattern_gen++;
}

void mm_clear_custom(void) {
    for (int s = NUM_PATTERNS; s < g_eng_n; s++) engine_free(&g_eng[s]);
    g_eng_n = NUM_PATTERNS;
    g_custom_n = 0;
    g_pattern_gen++;
}

/* ========================================================================
 * 12. Public scan + resolve
 * ======================================================================== */

static inline int enabled(const int *enable_bits, size_t n_bits, int p) {
    if (!enable_bits) return 1;
    if ((size_t)p >= n_bits) return 0;
    return enable_bits[p] != 0;
}

size_t mm_scan(const char *input, size_t len,
               const int *enable_bits, size_t n_bits,
               mm_match_t *out, size_t max) {
    if (!g_initialized) mm_init();
    scan_state_t *state = thread_state();
    size_t count = 0;

    for (int p = 0; p < g_eng_n && count < max; p++) {
        if (g_eng[p].digit_member) continue;
        if (g_eng[p].iban_member)  continue;
        if (!enabled(enable_bits, n_bits, p)) continue;
        count = scan_one(p, state, input, len, out, max, count);
    }
    if (g_have_iban_group && count < max)
        count = scan_iban_group(state, input, len, enable_bits, n_bits, out, max, count);
    if (g_have_digit_group && count < max)
        count = scan_digit_group(state, input, len, enable_bits, n_bits, out, max, count);
    return count;
}

/* Order events for the longest-match-wins greedy claim: ascending start, then
 * descending length (so the longest span at a given start is seen first), then
 * ascending pattern_id (lower index wins a tie of equal length). */
static int ev_cmp_resolve(const void *a, const void *b) {
    const mm_match_t *x = a, *y = b;
    if (x->start != y->start) return x->start < y->start ? -1 : 1;
    if (x->length != y->length) return x->length > y->length ? -1 : 1;
    return x->pattern_id - y->pattern_id;
}

/* Order kept events for emission: ascending start. */
static int ev_cmp_start(const void *a, const void *b) {
    const mm_match_t *x = a, *y = b;
    if (x->start != y->start) return x->start < y->start ? -1 : 1;
    return x->pattern_id - y->pattern_id;
}

size_t mm_resolve(mm_match_t *ev, size_t n) {
    if (n == 0) return 0;
    qsort(ev, n, sizeof(mm_match_t), ev_cmp_resolve);

    /* Greedy claim in (start, -length, pattern_id) order: the longest span at
     * each position is offered first and claims its region; any later (shorter,
     * or equal-length higher-id) event overlapping an already-kept span is
     * dropped. An event is kept iff its span [start, start+length) does not
     * overlap any already-kept span. Match counts are modest, so a linear
     * overlap check against the kept set is used. */
    mm_match_t *kept = mm_xmalloc(n * sizeof(mm_match_t));
    size_t nk = 0;
    for (size_t i = 0; i < n; i++) {
        size_t s = ev[i].start, e = s + ev[i].length;
        int overlaps = 0;
        for (size_t j = 0; j < nk; j++) {
            size_t ks = kept[j].start, ke = ks + kept[j].length;
            if (s < ke && ks < e) { overlaps = 1; break; }
        }
        if (!overlaps) kept[nk++] = ev[i];
    }
    qsort(kept, nk, sizeof(mm_match_t), ev_cmp_start);
    memcpy(ev, kept, nk * sizeof(mm_match_t));
    free(kept);
    return nk;
}

const char *mm_pattern_name(int id) {
    if (id < 0 || id >= NUM_PATTERNS) return NULL;
    return pattern_names[id];
}

int mm_pattern_count(void) {
    return g_eng_n;
}
