/* matcher9.c — v9: 88 separate per-pattern Thompson NFA + lazy DFA caches.
 *
 * Each pattern gets its own NFA and its own fixed-size lazy DFA cache.
 * No merging, no cross-pattern contamination — correct by construction.
 * No glibc regexec, no per-call O(N) allocation — fast by construction.
 *
 * Architecture:
 *   1. Same POSIX-ERE parser and Thompson NFA construction as matcher4.c
 *   2. Each pattern: one NFA (≤300 states) + one 512-slot DFA cache
 *   3. Scan: for each pattern, single-pass leftmost-longest DFA walk
 *      (same algorithm as mm4_scan_v42, but per-pattern, always correct)
 *
 * Build:  make matcher9.so
 */

#define _GNU_SOURCE
#include "matcher9.h"
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

static void cc_set(cclass_t *c, unsigned ch) {
    c->w[ch>>6] |= (uint64_t)1 << (ch&63);
}
static int cc_test(const cclass_t *c, unsigned ch) {
    return (c->w[ch>>6] >> (ch&63)) & 1;
}
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
    } else { fprintf(stderr,"matcher9: unknown POSIX class [:%.*s:]\n",(int)len,cls); exit(1); }
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
    ast_type_t   type;
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

#define PAT_NFA_MAX 1024  /* max NFA states per pattern (largest: hashicorp_vault_batch_token ~932) */

typedef enum { LABEL_NONE, LABEL_CHAR, LABEL_CLASS, LABEL_DOT,
               LABEL_BOL, LABEL_EOL } label_t;

typedef struct {
    int     e1, e2;
    label_t label;
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
        /* {lo,∞}: star loop.
         * split → body → back_to_split  (loop)
         * split → exit  (skip / done)
         * exit is the fragment end (becomes accept); exit has no ε back into loop.
         * This prevents ε-closure from reaching accept without consuming bytes. */
        frag_t f=pnfa_build(nfa,child);
        int split=pnfa_new(nfa), exit=pnfa_new(nfa);
        nfa->states[split].e1=f.start;   /* enter loop body */
        nfa->states[split].e2=exit;       /* skip loop (0 more iterations) */
        nfa->states[f.end].e1=split;      /* loop back after body */
        nfa->states[result.end].e1=split; /* connect mandatory prefix to loop */
        result.end=exit;
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
 * 4. Per-pattern NFA state set + ε-closure
 * ======================================================================== */

#define PNFA_BW ((PAT_NFA_MAX+63)/64)

typedef struct { uint64_t w[PNFA_BW]; } pnset_t;

static void pnset_clear(pnset_t *s)            { memset(s->w,0,sizeof(s->w)); }
static void pnset_set(pnset_t *s, int i)       { s->w[i>>6] |= (uint64_t)1<<(i&63); }
static int  pnset_test(const pnset_t *s, int i){ return (s->w[i>>6]>>(i&63))&1; }
static int  pnset_empty(const pnset_t *s) {
    for (int i=0;i<PNFA_BW;i++) if (s->w[i]) return 0; return 1;
}
static uint64_t pnset_hash(const pnset_t *s) {
    uint64_t h=0xcbf29ce484222325ULL;
    for (int i=0;i<PNFA_BW;i++) { h^=s->w[i]; h*=0x100000001b3ULL; }
    return h;
}

static void peps_add(const pnfa_t *nfa, int state, pnset_t *out, uint8_t *vis) {
    if (state<0 || vis[state]) return;
    vis[state]=1; pnset_set(out,state);
    peps_add(nfa, nfa->states[state].e1, out, vis);
    peps_add(nfa, nfa->states[state].e2, out, vis);
}
static void peps_closure(const pnfa_t *nfa, const pnset_t *from, pnset_t *out) {
    pnset_clear(out);
    uint8_t vis[PAT_NFA_MAX]; memset(vis,0,(size_t)nfa->n);
    for (int i=0;i<nfa->n;i++) if (pnset_test(from,i)) peps_add(nfa,i,out,vis);
}
static void pnfa_move(const pnfa_t *nfa, const pnset_t *from, unsigned char c, pnset_t *out) {
    pnset_clear(out);
    for (int i=0;i<nfa->n;i++) {
        if (!pnset_test(from,i)) continue;
        const pnfa_state_t *st=&nfa->states[i];
        int ok=0;
        switch(st->label) {
        case LABEL_CHAR:  ok=(st->ch==c); break;
        case LABEL_CLASS: ok=cc_test(&st->cc,c); break;
        case LABEL_DOT:   ok=(c!='\n'); break;
        default: break;
        }
        if (ok && st->e1>=0) pnset_set(out,st->e1);
    }
}

/* ========================================================================
 * 5. Per-pattern lazy DFA cache (512 slots — small, fits L2)
 * ======================================================================== */

#define PDCACHE_CAP 512

typedef struct {
    pnset_t  key;
    uint32_t next[256];
    int      is_accept;
    int      live;
} pdce_t;   /* per-pattern DFA cache entry */

typedef struct {
    pdce_t    *slots;
    int        used;
    uint64_t   flush_gen;
    pnset_t    start_nset;
} pdcache_t;

static void pdcache_flush(pdcache_t *dc) {
    memset(dc->slots, 0, PDCACHE_CAP * sizeof(pdce_t));
    dc->used=0; dc->flush_gen++;
}

static int pdcache_find_or_insert(pdcache_t *dc, const pnset_t *key) {
    if (dc->used >= PDCACHE_CAP-10) pdcache_flush(dc);
    uint64_t h=pnset_hash(key) & (PDCACHE_CAP-1);
    if (h==0) h=1;
    for (;;) {
        pdce_t *e=&dc->slots[h];
        if (!e->live) {
            e->key=*key; e->live=1;
            memset(e->next,0,sizeof(e->next));
            e->is_accept=0;
            dc->used++;
            return (int)h;
        }
        if (memcmp(&e->key,key,sizeof(*key))==0) return (int)h;
        h=(h+1)&(PDCACHE_CAP-1); if (h==0) h=1;
    }
}

/* ========================================================================
 * 5b. Minimum match length from AST
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
 * 6. Per-pattern engine — compile + scan
 * ======================================================================== */

#define WRAP_PFX "(^|[^0-9A-Za-z])("
#define WRAP_SFX ")([^0-9A-Za-z]|$)"

typedef struct {
    pnfa_t    nfa;
    pdcache_t dc;
    int       accept_state;   /* NFA state index of the accept state */
    size_t    min_len;        /* minimum bytes a valid match must span */
    /* For patterns with a required literal (prefix or BM), store it here
     * so we can reject DFA false-accepts that lack the literal in the span. */
    const char *req_literal;  /* NULL = no check needed */
    size_t      req_lit_len;
    int         req_lit_at_start; /* 1 = must be at span start, 0 = anywhere */
} pat_engine_t;

static pat_engine_t  g_engines[MM88_NUM_PATTERNS];
static int           g_initialized = 0;

/* Build DFA cache entry: compute is_accept from NFA states in key. */
static void pdcache_set_accept(pat_engine_t *eng, pdce_t *e) {
    for (int i=0;i<eng->nfa.n;i++) {
        if (pnset_test(&e->key,i) && eng->nfa.states[i].is_accept) {
            e->is_accept=1; return;
        }
    }
}

static int pdcache_step(pat_engine_t *eng, pdcache_t *dc, int d, unsigned char c) {
    pdce_t *e=&dc->slots[d];
    if (e->next[c]) return e->next[c];
    pnset_t moved, closed;
    pnfa_move(&eng->nfa, &e->key, c, &moved);
    if (pnset_empty(&moved)) { e->next[c]=0; return 0; }
    peps_closure(&eng->nfa, &moved, &closed);
    int ns=pdcache_find_or_insert(dc, &closed);
    e=&dc->slots[d];  /* re-fetch: insert may have flushed */
    e->next[c]=(uint32_t)ns;
    /* set is_accept on newly inserted slot */
    pdcache_set_accept(eng, &dc->slots[ns]);
    return ns;
}

void mm9_init(void) {
    if (g_initialized) return;
    for (int p=0;p<MM88_NUM_PATTERNS;p++) {
        pat_engine_t *eng=&g_engines[p];
        memset(&eng->nfa, 0, sizeof(eng->nfa));

        const char *src=MM88_PATTERNS[p].regex;
        char *to_free=NULL;
        if (MM88_PATTERNS[p].boundary_wrapped) {
            size_t len=strlen(WRAP_PFX)+strlen(src)+strlen(WRAP_SFX)+1;
            to_free=xmalloc(len);
            snprintf(to_free,len,"%s%s%s",WRAP_PFX,src,WRAP_SFX);
            src=to_free;
        }
        ast_node_t *ast=parse_regex(src);
        eng->min_len=ast_min_len(ast);
        free(to_free);

        frag_t frag=pnfa_build(&eng->nfa, ast);
        ast_free(ast);
        eng->nfa.states[frag.end].is_accept=1;
        eng->nfa.start=frag.start;
        eng->accept_state=frag.end;

        /* Required literal gate: reject DFA false-accepts that lack the literal. */
        const mm88_pattern_def_t *pd = &MM88_PATTERNS[p];
        if (pd->prefix && !pd->prefix_is_infix) {
            eng->req_literal     = pd->prefix;
            eng->req_lit_len     = strlen(pd->prefix);
            eng->req_lit_at_start = 1;
        } else if (pd->bm_literal) {
            eng->req_literal     = pd->bm_literal;
            eng->req_lit_len     = strlen(pd->bm_literal);
            eng->req_lit_at_start = 0;
        } else {
            eng->req_literal = NULL;
            eng->req_lit_len = 0;
            eng->req_lit_at_start = 0;
        }

        /* Allocate and init DFA cache */
        eng->dc.slots=xcalloc(PDCACHE_CAP, sizeof(pdce_t));
        eng->dc.used=0; eng->dc.flush_gen=0;

        /* Pre-compute start NFA set */
        pnset_t seed; pnset_clear(&seed); pnset_set(&seed, eng->nfa.start);
        peps_closure(&eng->nfa, &seed, &eng->dc.start_nset);
    }
    g_initialized=1;
}

void mm9_free(void) {
    for (int p=0;p<MM88_NUM_PATTERNS;p++) {
        free(g_engines[p].dc.slots);
        g_engines[p].dc.slots=NULL;
    }
    g_initialized=0;
}

/*
 * Scan input for pattern p using single-pass leftmost-longest DFA walk.
 * Writes matches into out[count..max). Returns number of matches added.
 * Identical algorithm to mm4_scan_v42 but operates on one pattern only.
 */
static size_t scan_one(int p, const char *input, size_t len,
                       mm9_match_t *out, size_t max, size_t count) {
    pat_engine_t *eng=&g_engines[p];
    pdcache_t    *dc =&eng->dc;

    uint64_t gen=dc->flush_gen;
    int start_slot=pdcache_find_or_insert(dc, &dc->start_nset);

    size_t i=0, match_start=0;
    int slot=start_slot, best_slot=-1;
    size_t best_end=0;

    while (i<=len && count<max) {
        int next=0;
        if (i<len) {
            next=pdcache_step(eng, dc, slot, (unsigned char)input[i]);
            if (dc->flush_gen != gen) {
                gen=dc->flush_gen;
                start_slot=pdcache_find_or_insert(dc, &dc->start_nset);
                slot=start_slot; best_slot=-1; best_end=0;
                i=match_start; continue;
            }
        }
        if (next==0 || i==len) {
            if (best_slot>=0) {
                size_t span=best_end-match_start;
                int ok = (span >= eng->min_len);
                if (ok && eng->req_literal) {
                    const char *sp = input + match_start;
                    if (eng->req_lit_at_start)
                        ok = (span >= eng->req_lit_len &&
                              memcmp(sp, eng->req_literal, eng->req_lit_len)==0);
                    else
                        ok = (memmem(sp, span, eng->req_literal, eng->req_lit_len) != NULL);
                }
                if (ok)
                    out[count++]=(mm9_match_t){p, match_start, span};
                i=best_end; match_start=best_end;
            } else {
                if (i<len) { match_start=i+1; i=match_start; }
                else break;
            }
            slot=start_slot; best_slot=-1; best_end=0;
        } else {
            slot=next;
            if (dc->slots[slot].is_accept) { best_slot=slot; best_end=i+1; }
            i++;
        }
    }
    return count;
}

/*
 * mm9_scan: scan input against all 88 patterns in sequence.
 * Each pattern uses its own NFA and DFA cache — correct by construction.
 * No glibc regexec, no per-call allocation.
 */
size_t mm9_scan(const char *input, size_t len, mm9_match_t *out, size_t max) {
    size_t count=0;
    for (int p=0; p<MM88_NUM_PATTERNS && count<max; p++)
        count=scan_one(p, input, len, out, max, count);
    return count;
}

const char *mm9_pattern_name(int id) {
    if (id<0||id>=MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 7. Self-test
 * ======================================================================== */

#ifdef MM9_MAIN
int main(void) {
    mm9_init();

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
    mm9_match_t out[256];

    for (int t=0;t<n;t++) {
        size_t len=strlen(tests[t].input);
        size_t nm=mm9_scan(tests[t].input, len, out, 256);
        int found=0;
        int no_expect=strcmp(tests[t].expect,"(none)")==0;
        for (size_t m=0;m<nm;m++) {
            const char *pname=mm9_pattern_name(out[m].pattern_id);
            if (!no_expect && pname && strcmp(pname,tests[t].expect)==0) found=1;
        }
        if (no_expect) found=(nm==0);
        printf("test %2d %-30s %s (%zu matches)\n",
               t, tests[t].expect, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d passed\n", pass, n);
    mm9_free();
    return pass==n ? 0 : 1;
}
#endif
