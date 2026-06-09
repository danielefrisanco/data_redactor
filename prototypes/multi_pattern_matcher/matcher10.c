/* matcher10.c — v10: 88 per-pattern backtracking NFA, fixed O(1) stack.
 *
 * Zero per-call allocation. Each pattern gets its own NFA (built once at
 * init) and a fixed-size evaluation stack (preallocated at init, reused
 * on every scan call). No DFA cache, no bitmap state-sets, no per-call malloc.
 *
 * Same algorithm class as Onigmo: NFA simulation with a preallocated stack.
 */

#define _GNU_SOURCE
#include "matcher10.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

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
    } else { fprintf(stderr,"matcher10: unknown POSIX class [:%.*s:]\n",(int)len,cls); exit(1); }
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
    ast_node_t *n = xcalloc(1, sizeof(*n)); n->type=t; return n;
}
static void ast_free(ast_node_t *n) {
    if (!n) return; ast_free(n->left); ast_free(n->right); free(n);
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
 * 3. Per-pattern NFA
 * ======================================================================== */

#define PAT_NFA_MAX 1024

typedef enum { LABEL_NONE, LABEL_CHAR, LABEL_CLASS, LABEL_DOT,
               LABEL_BOL, LABEL_EOL } label_t;

typedef struct {
    int      e1, e2;
    label_t  label;
    unsigned char ch;
    cclass_t cc;
    int      is_accept;
} pnfa_state_t;

typedef struct {
    pnfa_state_t states[PAT_NFA_MAX];
    int          n;
    int          start;
} pnfa_t;

static int pnfa_new(pnfa_t *nfa) {
    if (nfa->n >= PAT_NFA_MAX) { fprintf(stderr,"NFA pool full\n"); exit(1); }
    int s=nfa->n++;
    memset(&nfa->states[s], 0, sizeof(nfa->states[s]));
    nfa->states[s].e1=nfa->states[s].e2=-1;
    return s;
}

typedef struct { int start, end; } frag_t;
static frag_t pnfa_build(pnfa_t *nfa, ast_node_t *node);

static frag_t pnfa_build_repeat(pnfa_t *nfa, ast_node_t *node) {
    ast_node_t *child=node->left;
    int lo=node->lo, hi=node->hi;
    frag_t result={-1,-1};
    for (int i=0;i<lo;i++) {
        frag_t f=pnfa_build(nfa,child);
        if (result.start==-1) result=f;
        else { nfa->states[result.end].e1=f.start; result.end=f.end; }
    }
    if (lo==0) {
        int s=pnfa_new(nfa);
        if (result.start==-1) result.start=s;
        result.end=s;
    }
    if (hi==-1) {
        frag_t f=pnfa_build(nfa,child);
        int split=pnfa_new(nfa), exit_st=pnfa_new(nfa);
        nfa->states[split].e1=f.start;
        nfa->states[split].e2=exit_st;
        nfa->states[f.end].e1=split;
        nfa->states[result.end].e1=split;
        result.end=exit_st;
    } else {
        int tail=result.end;
        for (int i=lo;i<hi;i++) {
            frag_t f=pnfa_build(nfa,child);
            int split=pnfa_new(nfa), join=pnfa_new(nfa);
            nfa->states[tail].e1=split; nfa->states[split].e1=f.start;
            nfa->states[split].e2=join; nfa->states[f.end].e1=join;
            tail=join;
        }
        result.end=tail;
    }
    return result;
}

static frag_t pnfa_build(pnfa_t *nfa, ast_node_t *node) {
    if (!node) { int s=pnfa_new(nfa); return (frag_t){s,s}; }
    switch (node->type) {
    case AST_LITERAL: {
        int s=pnfa_new(nfa), e=pnfa_new(nfa);
        nfa->states[s].label=LABEL_CHAR; nfa->states[s].ch=node->ch; nfa->states[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_CCLASS: {
        int s=pnfa_new(nfa), e=pnfa_new(nfa);
        nfa->states[s].label=LABEL_CLASS; nfa->states[s].cc=node->cc; nfa->states[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_DOT: {
        int s=pnfa_new(nfa), e=pnfa_new(nfa);
        nfa->states[s].label=LABEL_DOT; nfa->states[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_ANCHOR_BOL: { int s=pnfa_new(nfa); nfa->states[s].label=LABEL_BOL; return (frag_t){s,s}; }
    case AST_ANCHOR_EOL: { int s=pnfa_new(nfa); nfa->states[s].label=LABEL_EOL; return (frag_t){s,s}; }
    case AST_CONCAT: {
        frag_t L=pnfa_build(nfa,node->left), R=pnfa_build(nfa,node->right);
        nfa->states[L.end].e1=R.start; return (frag_t){L.start,R.end};
    }
    case AST_ALT: {
        frag_t L=pnfa_build(nfa,node->left), R=pnfa_build(nfa,node->right);
        int s=pnfa_new(nfa), e=pnfa_new(nfa);
        nfa->states[s].e1=L.start; nfa->states[s].e2=R.start;
        nfa->states[L.end].e1=e;
        if (nfa->states[R.end].e1==-1) nfa->states[R.end].e1=e;
        else nfa->states[R.end].e2=e;
        return (frag_t){s,e};
    }
    case AST_REPEAT: return pnfa_build_repeat(nfa, node);
    }
    __builtin_unreachable();
}

/* ========================================================================
 * 4. Minimum match length from AST
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

/* ========================================================================
 * 5. Per-pattern engine — precomputed transition table
 *
 * At init time we compute, for every (NFA state, byte) pair, the full set
 * of NFA states reachable after taking that byte transition and then
 * following all epsilon edges. This is stored as a compact flat pool.
 *
 * At scan time: no DFS, no epsilon closure, no stack traversal.
 * Advancing one character is just: for each state in cur, look up
 * trans[state][byte] and union those states into nxt.
 * ======================================================================== */

/* DFS stack used only at init time to compute epsilon closures. */
#define STACK_MAX 4096
typedef struct { int state; size_t pos; } frame_t;

/* Transition entry: offset into the flat pool + count of target states. */
typedef struct { uint16_t off; uint8_t cnt; } trans_entry_t;

/* Per-pattern engine. */
typedef struct {
    pnfa_t        nfa;
    /* trans[s][c]: states reachable from s on byte c (eps-closed). */
    trans_entry_t trans[PAT_NFA_MAX][256];
    int          *trans_pool;    /* flat array of target state ids */
    int           pool_size;
    /* start_closure[]: eps closure of start state (for re-seeding). */
    int          *start_cls;
    int           start_cls_n;
    /* visited[] used only during init eps-closure computation. */
    uint8_t       vis[PAT_NFA_MAX];
    frame_t        stack[STACK_MAX];
    size_t         min_len;
    const char    *req_literal;
    size_t         req_lit_len;
    int            req_lit_at_start;
} pat_engine_t;

static pat_engine_t g_engines[MM88_NUM_PATTERNS];
static int          g_initialized = 0;

/* Compute epsilon closure of state s into out[], using eng->vis[] for
 * deduplication. Returns number of states added. vis[] is NOT cleared
 * by this function — caller manages it for set-union across multiple seeds. */
static int eps_closure(pat_engine_t *eng, int s, int *out, int n_out) {
    if (eng->vis[s]) return n_out;
    frame_t *stk = eng->stack;
    int top = 0;
    eng->vis[s] = 1; out[n_out++] = s;
    stk[top++] = (frame_t){s, 0};
    while (top > 0) {
        int cur = stk[--top].state;
        pnfa_state_t *st = &eng->nfa.states[cur];
        for (int ei = 0; ei < 2; ei++) {
            int t = ei == 0 ? st->e1 : st->e2;
            if (t < 0 || t >= eng->nfa.n || eng->vis[t]) continue;
            eng->vis[t] = 1; out[n_out++] = t;
            if (top < STACK_MAX) stk[top++] = (frame_t){t, 0};
        }
    }
    return n_out;
}

#define WRAP_PFX "(^|[^0-9A-Za-z])("
#define WRAP_SFX ")([^0-9A-Za-z]|$)"

void mm10_init(void) {
    if (g_initialized) return;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        pat_engine_t *eng = &g_engines[p];
        memset(eng, 0, sizeof(*eng));

        /* --- parse + build NFA --- */
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
        free(to_free);

        frag_t frag = pnfa_build(&eng->nfa, ast);
        ast_free(ast);
        eng->nfa.states[frag.end].is_accept = 1;
        eng->nfa.start = frag.start;

        int ns = eng->nfa.n;

        /* --- build transition table --- */
        /* First pass: count total pool entries needed. */
        int tmp[PAT_NFA_MAX];
        int total_pool = 0;
        for (int s = 0; s < ns; s++) {
            pnfa_state_t *st = &eng->nfa.states[s];
            if (st->label == LABEL_NONE || st->e1 < 0) continue;
            /* This state has a byte-consuming transition to st->e1. */
            for (int c = 0; c < 256; c++) {
                int matches = 0;
                switch (st->label) {
                case LABEL_CHAR:  matches = (st->ch == (unsigned char)c); break;
                case LABEL_CLASS: matches = cc_test(&st->cc, (unsigned)c); break;
                case LABEL_DOT:   matches = (c != '\n'); break;
                default: break;
                }
                if (!matches) continue;
                memset(eng->vis, 0, ns);
                int n = eps_closure(eng, st->e1, tmp, 0);
                total_pool += n;
            }
        }

        eng->trans_pool = xmalloc((total_pool + 1) * sizeof(int));
        eng->pool_size  = 0;

        /* Second pass: fill pool and set trans[s][c]. */
        for (int s = 0; s < ns; s++) {
            pnfa_state_t *st = &eng->nfa.states[s];
            if (st->label == LABEL_NONE || st->e1 < 0) {
                /* no byte transition — all trans[s][c] stay {0,0} */
                continue;
            }
            for (int c = 0; c < 256; c++) {
                int matches = 0;
                switch (st->label) {
                case LABEL_CHAR:  matches = (st->ch == (unsigned char)c); break;
                case LABEL_CLASS: matches = cc_test(&st->cc, (unsigned)c); break;
                case LABEL_DOT:   matches = (c != '\n'); break;
                default: break;
                }
                if (!matches) continue;
                memset(eng->vis, 0, ns);
                int n = eps_closure(eng, st->e1, eng->trans_pool + eng->pool_size, 0);
                eng->trans[s][c].off = (uint16_t)eng->pool_size;
                eng->trans[s][c].cnt = (uint8_t)n;
                eng->pool_size += n;
            }
        }

        /* --- precompute start-state epsilon closure --- */
        int start_tmp[PAT_NFA_MAX];
        memset(eng->vis, 0, ns);
        int scn = eps_closure(eng, eng->nfa.start, start_tmp, 0);
        eng->start_cls   = xmalloc(scn * sizeof(int));
        eng->start_cls_n = scn;
        memcpy(eng->start_cls, start_tmp, scn * sizeof(int));

        /* --- literal hints --- */
        const mm88_pattern_def_t *pd = &MM88_PATTERNS[p];
        if (pd->prefix && !pd->prefix_is_infix) {
            eng->req_literal       = pd->prefix;
            eng->req_lit_len       = strlen(pd->prefix);
            eng->req_lit_at_start  = 1;
        } else if (pd->bm_literal) {
            eng->req_literal       = pd->bm_literal;
            eng->req_lit_len       = strlen(pd->bm_literal);
            eng->req_lit_at_start  = 0;
        }
    }
    g_initialized = 1;
}

void mm10_free(void) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        free(g_engines[p].trans_pool); g_engines[p].trans_pool = NULL;
        free(g_engines[p].start_cls);  g_engines[p].start_cls  = NULL;
    }
    g_initialized=0;
}

/* ========================================================================
 * 6. Single-pass table-driven scan
 *
 * One left-to-right sweep over the input per pattern. Active state set
 * stored as a flat array of (state, match_start) pairs — at most nfa->n
 * entries (one per NFA state). Deduplication by state, keeping earliest
 * match_start (leftmost preference).
 *
 * Advancing one character: for each active state s, look up
 * trans[s][c] in the precomputed table and union those target states
 * into the next set. No DFS, no epsilon closure at scan time.
 *
 * Also inject the precomputed start closure at every step so we always
 * try beginning a new match at the current position.
 * ======================================================================== */

typedef struct { int state; size_t mstart; } thread_t;

/* In-scan deduplication: which thread index owns each NFA state, and when. */
typedef struct { int idx; uint32_t gen; } slot_t;
static slot_t g_slot[MM88_NUM_PATTERNS][PAT_NFA_MAX];

/* ADD_STATE: add state s with match start ms into set out[]/n_out,
 * deduplicating via slot[]/gen. Keeps earliest mstart per state. */
#define ADD_STATE(s, ms, out, n_out, slot, gen) do {        \
    slot_t *_sl = &(slot)[(s)];                             \
    if (_sl->gen != (gen)) {                                 \
        _sl->gen = (gen); _sl->idx = (n_out);               \
        (out)[(n_out)++] = (thread_t){(s), (ms)};           \
    } else if ((out)[_sl->idx].mstart > (ms)) {             \
        (out)[_sl->idx].mstart = (ms);                      \
    }                                                        \
} while(0)

static size_t scan_one(int p, const char *input, size_t len,
                       mm10_match_t *out, size_t max, size_t count) {
    pat_engine_t *eng  = &g_engines[p];
    slot_t       *slot = g_slot[p];

    thread_t cur[PAT_NFA_MAX], nxt[PAT_NFA_MAX];
    int n_cur = 0, n_nxt = 0;

    size_t best_start = (size_t)-1, best_end = (size_t)-1;

    /* Generation counter: bump instead of memset slot[]. */
    uint32_t gen = 1;

    /* For prefix patterns: jump to first literal occurrence before seeding. */
    size_t scan_start = 0;
    if (eng->req_literal && eng->req_lit_at_start) {
        const char *hit = memmem(input, len, eng->req_literal, eng->req_lit_len);
        if (!hit) return count;
        scan_start = (size_t)(hit - input);
    }

    /* Seed: start closure at scan_start. */
    for (int i = 0; i < eng->start_cls_n; i++)
        ADD_STATE(eng->start_cls[i], scan_start, cur, n_cur, slot, gen);

    for (size_t pos = scan_start; pos <= len; pos++) {
        /* --- check accepts --- */
        for (int i = 0; i < n_cur; i++) {
            if (!eng->nfa.states[cur[i].state].is_accept) continue;
            size_t span = pos - cur[i].mstart;
            if (span < eng->min_len) continue;
            if (best_end == (size_t)-1 ||
                cur[i].mstart < best_start ||
                (cur[i].mstart == best_start && pos > best_end)) {
                best_start = cur[i].mstart;
                best_end   = pos;
            }
        }

        if (pos == len) break;
        unsigned char c = (unsigned char)input[pos];

        /* --- build nxt via precomputed transition table --- */
        n_nxt = 0;
        if (++gen == 0) { memset(slot, 0, eng->nfa.n * sizeof(*slot)); gen = 1; }

        for (int i = 0; i < n_cur; i++) {
            trans_entry_t te = eng->trans[cur[i].state][c];
            int *targets = eng->trans_pool + te.off;
            for (int k = 0; k < te.cnt; k++)
                ADD_STATE(targets[k], cur[i].mstart, nxt, n_nxt, slot, gen);
        }

        /* --- dead end: emit best, reset cur to start closure, continue --- */
        if (n_nxt == 0) {
            if (best_end != (size_t)-1 && count < max) {
                size_t span = best_end - best_start;
                int ok = 1;
                if (eng->req_literal && !eng->req_lit_at_start)
                    ok = (memmem(input + best_start, span,
                                 eng->req_literal, eng->req_lit_len) != NULL);
                if (ok) out[count++] = (mm10_match_t){p, best_start, span};
                pos = best_end;
            }
            best_start = best_end = (size_t)-1;
            /* Prefix skip: jump to next literal occurrence. */
            if (eng->req_literal && eng->req_lit_at_start) {
                const char *hit = memmem(input + pos + 1, len - pos - 1,
                                         eng->req_literal, eng->req_lit_len);
                if (!hit) break;
                pos = (size_t)(hit - input);
            }
            /* Reseed cur[] from start closure at pos+1 (next byte after dead end).
             * The loop will pos++ at end, so we seed with pos+1 here and the
             * next iteration starts at pos+2 — off by one. Instead we seed cur
             * directly and use 'continue' to skip the memcpy and the pos++. */
            n_cur = 0;
            if (++gen == 0) { memset(slot, 0, eng->nfa.n * sizeof(*slot)); gen = 1; }
            for (int i = 0; i < eng->start_cls_n; i++)
                ADD_STATE(eng->start_cls[i], pos + 1, cur, n_cur, slot, gen);
            /* pos++ at loop end advances to pos+1 — exactly where we seeded. */
            continue;
        }

        memcpy(cur, nxt, n_nxt * sizeof(thread_t));
        n_cur = n_nxt;
    }

    /* emit pending match at end-of-input */
    if (best_end != (size_t)-1 && count < max) {
        size_t span = best_end - best_start;
        int ok = 1;
        if (eng->req_literal && !eng->req_lit_at_start)
            ok = (memmem(input + best_start, span,
                         eng->req_literal, eng->req_lit_len) != NULL);
        if (ok) out[count++] = (mm10_match_t){p, best_start, span};
    }

    return count;
}

#undef ADD_STATE

size_t mm10_scan(const char *input, size_t len, mm10_match_t *out, size_t max) {
    size_t count = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++)
        count = scan_one(p, input, len, out, max, count);
    return count;
}

const char *mm10_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 8. Self-test
 * ======================================================================== */

#ifdef MM10_MAIN
int main(void) {
    mm10_init();

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
    mm10_match_t out[256];

    for (int t=0; t<n; t++) {
        size_t len=strlen(tests[t].input);
        size_t nm=mm10_scan(tests[t].input, len, out, 256);
        int found=0, no_expect=strcmp(tests[t].expect,"(none)")==0;
        for (size_t m=0; m<nm; m++) {
            const char *pn=mm10_pattern_name(out[m].pattern_id);
            if (!no_expect && pn && strcmp(pn,tests[t].expect)==0) found=1;
        }
        if (no_expect) found=(nm==0);
        printf("test %2d %-30s %s (%zu matches)\n",
               t, tests[t].expect, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d passed\n", pass, n);
    mm10_free();
    return pass==n ? 0 : 1;
}
#endif
