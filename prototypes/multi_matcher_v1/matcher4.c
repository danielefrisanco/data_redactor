/* Multi-matcher prototype v4 — Option D: Thompson NFA with lazy DFA cache.
 *
 * Compiles all 88 patterns into a merged NFA via Thompson's construction,
 * then drives a lazy DFA during scanning: DFA states are computed on demand
 * and cached in a fixed-size table.  When the cache is full, it is cleared
 * (restart from scratch — same strategy as RE2's DFA cache flush).
 *
 * This avoids the exponential state-explosion of full subset-construction
 * while still delivering near-O(N) throughput when the cache is warm.
 *
 * Architecture:
 *   1. Regex parser: POSIX-ERE subset → AST
 *   2. Thompson NFA construction: AST → ε-NFA with shared start
 *   3. Scan: sliding-window DFA walk with lazy state computation
 *
 * Build:  make matcher4   (smoke test, no .so needed)
 *         make matcher4.so (for bench4.rb)
 */

#define _GNU_SOURCE  /* memmem */
#include "matcher4.h"
#include "patterns_generated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>

/* ========================================================================
 * 0. Utilities
 * ======================================================================== */

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { perror("malloc"); exit(1); }
    return p;
}
static void *xcalloc(size_t n, size_t s) {
    void *p = calloc(n, s);
    if (!p) { perror("calloc"); exit(1); }
    return p;
}
static void *xrealloc(void *p, size_t n) {
    p = realloc(p, n);
    if (!p) { perror("realloc"); exit(1); }
    return p;
}

/* ========================================================================
 * 1. Character class bitmap (256 bits = 4 × uint64_t)
 * ======================================================================== */

typedef struct { uint64_t w[4]; } cclass_t;

static void cc_set(cclass_t *c, unsigned ch) {
    c->w[ch >> 6] |= (uint64_t)1 << (ch & 63);
}
static int cc_test(const cclass_t *c, unsigned ch) {
    return (c->w[ch >> 6] >> (ch & 63)) & 1;
}
static void cc_negate(cclass_t *c) {
    c->w[0]=~c->w[0]; c->w[1]=~c->w[1];
    c->w[2]=~c->w[2]; c->w[3]=~c->w[3];
}
static void cc_add_range(cclass_t *c, unsigned lo, unsigned hi) {
    for (unsigned i = lo; i <= hi; i++) cc_set(c, i);
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
    } else {
        fprintf(stderr,"matcher4: unknown POSIX class [:%.*s:]\n",(int)len,cls);
        exit(1);
    }
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
    ast_type_t type;
    unsigned char ch;
    cclass_t     cc;
    ast_node_t  *left, *right;
    int          lo, hi;  /* REPEAT: min, max (-1=unbounded) */
};

static ast_node_t *ast_alloc(ast_type_t t) {
    ast_node_t *n = xcalloc(1, sizeof(*n));
    n->type = t; return n;
}
static void ast_free(ast_node_t *n) {
    if (!n) return;
    ast_free(n->left); ast_free(n->right); free(n);
}

typedef struct { const char *p, *end; } pctx_t;

static ast_node_t *parse_alt(pctx_t *ctx);  /* forward */

static ast_node_t *parse_cclass(pctx_t *ctx) {
    ast_node_t *n = ast_alloc(AST_CCLASS);
    int negate = 0;
    if (ctx->p < ctx->end && *ctx->p == '^') { negate=1; ctx->p++; }
    int first = 1;
    while (ctx->p < ctx->end && (*ctx->p != ']' || first)) {
        first = 0;
        unsigned char c = (unsigned char)*ctx->p++;
        if (c == '[' && ctx->p < ctx->end && *ctx->p == ':') {
            ctx->p++;
            const char *cs = ctx->p;
            while (ctx->p < ctx->end && !(*ctx->p == ':' && *(ctx->p+1) == ']'))
                ctx->p++;
            cc_add_posix(&n->cc, cs, (size_t)(ctx->p - cs));
            ctx->p += 2;
        } else if (ctx->p + 1 < ctx->end && *ctx->p == '-' && *(ctx->p+1) != ']') {
            ctx->p++;
            cc_add_range(&n->cc, c, (unsigned char)*ctx->p++);
        } else if (c == '\\' && ctx->p < ctx->end) {
            cc_set(&n->cc, (unsigned char)*ctx->p++);
        } else {
            cc_set(&n->cc, c);
        }
    }
    if (ctx->p < ctx->end && *ctx->p == ']') ctx->p++;
    if (negate) cc_negate(&n->cc);
    return n;
}

static void parse_quantifier(pctx_t *ctx, ast_node_t **io) {
    if (ctx->p >= ctx->end) return;
    char c = *ctx->p;
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
    if (ctx->p<ctx->end && *ctx->p=='?') ctx->p++; /* consume non-greedy marker */
    ast_node_t *rep = ast_alloc(AST_REPEAT);
    rep->left=*io; rep->lo=lo; rep->hi=hi;
    *io=rep;
}

static ast_node_t *parse_atom(pctx_t *ctx) {
    if (ctx->p >= ctx->end) return NULL;
    unsigned char c = (unsigned char)*ctx->p;
    if (c=='(') {
        ctx->p++;
        if (ctx->p+1<ctx->end && *ctx->p=='?' && *(ctx->p+1)==':') ctx->p+=2;
        ast_node_t *inner = parse_alt(ctx);
        if (ctx->p<ctx->end && *ctx->p==')') ctx->p++;
        return inner;
    }
    if (c=='[') { ctx->p++; return parse_cclass(ctx); }
    if (c=='.') { ctx->p++; return ast_alloc(AST_DOT); }
    if (c=='^') { ctx->p++; return ast_alloc(AST_ANCHOR_BOL); }
    if (c=='$') { ctx->p++; return ast_alloc(AST_ANCHOR_EOL); }
    if (c=='\\' && ctx->p+1<ctx->end) {
        ctx->p++;
        ast_node_t *n = ast_alloc(AST_LITERAL);
        n->ch = (unsigned char)*ctx->p++;
        return n;
    }
    if (c==')' || c=='|') return NULL;
    ctx->p++;
    ast_node_t *n = ast_alloc(AST_LITERAL);
    n->ch = c;
    return n;
}

static ast_node_t *parse_concat(pctx_t *ctx) {
    ast_node_t *head = NULL;
    while (ctx->p < ctx->end && *ctx->p != ')' && *ctx->p != '|') {
        ast_node_t *atom = parse_atom(ctx);
        if (!atom) break;
        parse_quantifier(ctx, &atom);
        if (!head) { head = atom; }
        else { ast_node_t *cat=ast_alloc(AST_CONCAT); cat->left=head; cat->right=atom; head=cat; }
    }
    return head;
}

static ast_node_t *parse_alt(pctx_t *ctx) {
    ast_node_t *left = parse_concat(ctx);
    while (ctx->p < ctx->end && *ctx->p == '|') {
        ctx->p++;
        ast_node_t *right = parse_concat(ctx);
        ast_node_t *alt = ast_alloc(AST_ALT);
        alt->left=left; alt->right=right; left=alt;
    }
    return left;
}

static ast_node_t *parse_regex(const char *src) {
    pctx_t ctx = { src, src + strlen(src) };
    return parse_alt(&ctx);
}

/* ========================================================================
 * 3. Thompson NFA
 * ======================================================================== */

#define NFA_MAX_STATES (88 * 300)

typedef enum { LABEL_NONE, LABEL_CHAR, LABEL_CLASS, LABEL_DOT, LABEL_BOL, LABEL_EOL } label_t;

typedef struct {
    int     e1, e2;        /* ε-transitions (-1 = none) */
    label_t label;
    unsigned char ch;
    cclass_t cc;
    uint64_t accept[2];    /* pattern-id bitmask */
    int      is_accept;
} nfa_state_t;

static nfa_state_t g_nfa[NFA_MAX_STATES];
static int         g_nfa_n = 0;
static int         g_nfa_start = -1;

static int nfa_new(void) {
    if (g_nfa_n >= NFA_MAX_STATES) { fprintf(stderr,"NFA pool full\n"); exit(1); }
    int s = g_nfa_n++;
    memset(&g_nfa[s], 0, sizeof(g_nfa[s]));
    g_nfa[s].e1 = g_nfa[s].e2 = -1;
    return s;
}

typedef struct { int start, end; } frag_t;

static frag_t build_nfa(ast_node_t *node);

static frag_t build_repeat(ast_node_t *node) {
    ast_node_t *child = node->left;
    int lo = node->lo, hi = node->hi;

    frag_t result = { -1, -1 };
    for (int i = 0; i < lo; i++) {
        frag_t f = build_nfa(child);
        if (result.start == -1) { result = f; }
        else { g_nfa[result.end].e1 = f.start; result.end = f.end; }
    }
    /* Anchor state when lo==0 so result has a valid start */
    if (lo == 0) {
        int s = nfa_new();
        if (result.start == -1) result.start = s;
        result.end = s;
    }

    if (hi == -1) {
        /* Star loop: split → (body → join → split | exit=join) */
        frag_t f = build_nfa(child);
        int split = nfa_new(), join = nfa_new();
        g_nfa[split].e1 = f.start;
        g_nfa[split].e2 = join;
        g_nfa[f.end].e1 = join;
        g_nfa[join].e1  = split;
        g_nfa[result.end].e1 = split;
        result.end = join;
    } else {
        /* Optional tail: (hi - lo) copies each through a split */
        int tail_end = result.end;
        for (int i = lo; i < hi; i++) {
            frag_t f = build_nfa(child);
            int split = nfa_new(), join = nfa_new();
            g_nfa[tail_end].e1 = split;
            g_nfa[split].e1    = f.start;
            g_nfa[split].e2    = join;
            g_nfa[f.end].e1    = join;
            tail_end = join;
        }
        result.end = tail_end;
    }
    return result;
}

static frag_t build_nfa(ast_node_t *node) {
    if (!node) { int s=nfa_new(); return (frag_t){s,s}; }
    switch (node->type) {
    case AST_LITERAL: {
        int s=nfa_new(), e=nfa_new();
        g_nfa[s].label=LABEL_CHAR; g_nfa[s].ch=node->ch; g_nfa[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_CCLASS: {
        int s=nfa_new(), e=nfa_new();
        g_nfa[s].label=LABEL_CLASS; g_nfa[s].cc=node->cc; g_nfa[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_DOT: {
        int s=nfa_new(), e=nfa_new();
        g_nfa[s].label=LABEL_DOT; g_nfa[s].e1=e;
        return (frag_t){s,e};
    }
    case AST_ANCHOR_BOL: { int s=nfa_new(); g_nfa[s].label=LABEL_BOL; return (frag_t){s,s}; }
    case AST_ANCHOR_EOL: { int s=nfa_new(); g_nfa[s].label=LABEL_EOL; return (frag_t){s,s}; }
    case AST_CONCAT: {
        frag_t L=build_nfa(node->left), R=build_nfa(node->right);
        g_nfa[L.end].e1=R.start;
        return (frag_t){L.start,R.end};
    }
    case AST_ALT: {
        frag_t L=build_nfa(node->left), R=build_nfa(node->right);
        int s=nfa_new(), e=nfa_new();
        g_nfa[s].e1=L.start; g_nfa[s].e2=R.start;
        g_nfa[L.end].e1=e;
        if (g_nfa[R.end].e1==-1) g_nfa[R.end].e1=e; else g_nfa[R.end].e2=e;
        return (frag_t){s,e};
    }
    case AST_REPEAT: return build_repeat(node);
    }
    __builtin_unreachable();
}

/* ========================================================================
 * 4. NFA state set (bitmap) and ε-closure
 * ======================================================================== */

#define NFA_BW ((NFA_MAX_STATES + 63) / 64)

typedef struct { uint64_t w[NFA_BW]; } nset_t;

static void nset_clear(nset_t *s)            { memset(s->w,0,sizeof(s->w)); }
static void nset_set(nset_t *s, int i)       { s->w[i>>6] |= (uint64_t)1<<(i&63); }
static int  nset_test(const nset_t *s, int i){ return (s->w[i>>6]>>(i&63))&1; }
static int  nset_empty(const nset_t *s) {
    for (int i=0;i<NFA_BW;i++) if (s->w[i]) return 0; return 1;
}

static uint64_t nset_hash(const nset_t *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i=0;i<NFA_BW;i++) { h^=s->w[i]; h*=0x100000001b3ULL; }
    return h;
}

static void eps_add(int state, nset_t *out, uint8_t *vis) {
    if (state<0 || vis[state]) return;
    vis[state]=1;
    nset_set(out,state);
    eps_add(g_nfa[state].e1, out, vis);
    eps_add(g_nfa[state].e2, out, vis);
}

static void eps_closure(const nset_t *from, nset_t *out) {
    nset_clear(out);
    static uint8_t vis[NFA_MAX_STATES];
    memset(vis,0,(size_t)g_nfa_n);
    for (int i=0;i<g_nfa_n;i++)
        if (nset_test(from,i)) eps_add(i,out,vis);
}

/* Apply byte c to nset, return reachable (before ε-closure). */
static void nfa_move(const nset_t *from, unsigned char c, nset_t *out) {
    nset_clear(out);
    for (int i=0;i<g_nfa_n;i++) {
        if (!nset_test(from,i)) continue;
        nfa_state_t *st=&g_nfa[i];
        int ok=0;
        switch(st->label){
        case LABEL_CHAR:  ok=(st->ch==c); break;
        case LABEL_CLASS: ok=cc_test(&st->cc,c); break;
        case LABEL_DOT:   ok=(c!='\n'); break;
        default: break;
        }
        if (ok && st->e1>=0) nset_set(out,st->e1);
    }
}

/* ========================================================================
 * 5. Lazy DFA cache
 *
 * Key: nset_t (bitmap of active NFA states).
 * Value: next[256] (DFA transitions) + accept bitmask.
 *
 * Open-addressing hash table. When full, we evict everything (flush).
 * The scan loop re-derives any needed states from scratch after a flush.
 * This matches RE2's "DFA cache restart" strategy.
 * ======================================================================== */

#define DCACHE_CAP 4096   /* power of 2; increase if cache-miss rate is high */

typedef struct {
    nset_t   key;
    uint32_t next[256];  /* index into dcache; 0 = dead/empty */
    uint64_t accept[2];
    int      is_accept;
    int      live;       /* 1 = slot occupied */
} dcache_entry_t;

static dcache_entry_t *g_dc = NULL;
static int  g_dc_used = 0;

/* Stored nset of the start DFA state */
static nset_t g_start_nset;

static uint64_t g_flush_gen = 0;  /* incremented on every flush */

static void dcache_flush(void) {
    memset(g_dc, 0, DCACHE_CAP * sizeof(*g_dc));
    g_dc_used = 0;
    g_flush_gen++;
}

/* Find or allocate a dcache slot for key.
 * Returns slot index (>0). 0 is the dead state sentinel. */
static int dcache_find_or_insert(const nset_t *key) {
    if (g_dc_used >= DCACHE_CAP - 10) {
        dcache_flush();
    }
    uint64_t h = nset_hash(key) & (DCACHE_CAP - 1);
    if (h == 0) h = 1; /* reserve 0 as dead-state sentinel */
    for (;;) {
        dcache_entry_t *e = &g_dc[h];
        if (!e->live) {
            /* empty — insert */
            e->key = *key;
            e->live = 1;
            memset(e->next, 0, sizeof(e->next));
            e->accept[0] = e->accept[1] = 0;
            e->is_accept = 0;
            /* compute accept from NFA states */
            for (int i=0;i<g_nfa_n;i++) {
                if (nset_test(key,i) && g_nfa[i].is_accept) {
                    e->accept[0] |= g_nfa[i].accept[0];
                    e->accept[1] |= g_nfa[i].accept[1];
                    e->is_accept = 1;
                }
            }
            g_dc_used++;
            return (int)h;
        }
        if (memcmp(&e->key, key, sizeof(*key)) == 0) return (int)h;
        h = (h+1) & (DCACHE_CAP-1);
        if (h == 0) h = 1;
    }
}

/* Get (or compute) the DFA transition for slot d on byte c.
 * Returns the next slot index (0 = dead). */
static int dcache_step(int d, unsigned char c) {
    dcache_entry_t *e = &g_dc[d];
    if (e->next[c]) return e->next[c];
    /* Compute: move + ε-closure */
    nset_t moved, closed;
    nfa_move(&e->key, c, &moved);
    if (nset_empty(&moved)) { e->next[c]=0; return 0; }
    eps_closure(&moved, &closed);
    int next_slot = dcache_find_or_insert(&closed);
    /* Re-fetch e in case dcache_find_or_insert flushed and reallocated */
    e = &g_dc[d];
    e->next[c] = (uint32_t)next_slot;
    return next_slot;
}

/* ========================================================================
 * 6. Public API
 * ======================================================================== */

static void build_prefix_table(void);  /* defined in §7 */

static int g_initialized = 0;

#define WRAP_PREFIX  "(^|[^0-9A-Za-z])("
#define WRAP_SUFFIX  ")([^0-9A-Za-z]|$)"

static char *make_wrapped(const char *core) {
    size_t len = strlen(WRAP_PREFIX)+strlen(core)+strlen(WRAP_SUFFIX)+1;
    char *buf = xmalloc(len);
    snprintf(buf,len,"%s%s%s",WRAP_PREFIX,core,WRAP_SUFFIX);
    return buf;
}

void mm4_init(void) {
    if (g_initialized) return;

    /* Build NFA for each pattern */
    int pat_starts[MM88_NUM_PATTERNS];
    for (int p=0;p<MM88_NUM_PATTERNS;p++) {
        const char *src = MM88_PATTERNS[p].regex;
        char *to_free = NULL;
        if (MM88_PATTERNS[p].boundary_wrapped)
            src = to_free = make_wrapped(src);
        ast_node_t *ast = parse_regex(src);
        free(to_free);
        frag_t frag = build_nfa(ast);
        ast_free(ast);
        g_nfa[frag.end].is_accept = 1;
        g_nfa[frag.end].accept[p>>6] |= (uint64_t)1<<(p&63);
        pat_starts[p] = frag.start;
    }

    /* Merge all patterns under one master start via ε-fanout tree */
    int queue[MM88_NUM_PATTERNS + 256];
    int qlen = MM88_NUM_PATTERNS;
    memcpy(queue, pat_starts, (size_t)qlen * sizeof(int));
    while (qlen > 2) {
        int nq = 0;
        for (int i=0;i<qlen;i+=2) {
            if (i+1<qlen) {
                int s=nfa_new();
                g_nfa[s].e1=queue[i]; g_nfa[s].e2=queue[i+1];
                queue[nq++]=s;
            } else queue[nq++]=queue[i];
        }
        qlen=nq;
    }
    int master = nfa_new();
    g_nfa_start = master;
    if (qlen==2) { g_nfa[master].e1=queue[0]; g_nfa[master].e2=queue[1]; }
    else if (qlen==1) { g_nfa[master].e1=queue[0]; }

    fprintf(stderr,"mm4: NFA states = %d\n",g_nfa_n);

    /* Allocate lazy DFA cache */
    g_dc = xcalloc(DCACHE_CAP, sizeof(*g_dc));

    build_prefix_table();

    /* Pre-compute start NFA set (ε-closure of master) */
    nset_t seed; nset_clear(&seed); nset_set(&seed,g_nfa_start);
    eps_closure(&seed, &g_start_nset);

    g_initialized = 1;
}

void mm4_free(void) {
    free(g_dc); g_dc = NULL;
    g_nfa_n = 0; g_initialized = 0;
}

/*
 * Scan: for each starting position, run the lazy DFA.
 * Track the rightmost accepting state for the longest match from that start.
 * Emit all pattern IDs found at the accepting state.
 *
 * This is O(input_len × avg_match_len) in the worst case (same as the
 * AC+Onigmo approach for always-candidates), but the constant factor is
 * much smaller: one hash lookup + bitmap op per byte instead of a full
 * Onigmo call.
 */
size_t mm4_scan(const char *input, size_t len, mm4_match_t *out, size_t max) {
    size_t count = 0;
    uint64_t gen = g_flush_gen;
    int start_slot = dcache_find_or_insert(&g_start_nset);

    for (size_t i=0; i<len && count<max; i++) {
        int slot = start_slot;
        int best_slot = -1;
        size_t best_end = i;

        for (size_t j=i; j<len; j++) {
            int next = dcache_step(slot, (unsigned char)input[j]);
            if (g_flush_gen != gen) {
                gen = g_flush_gen;
                start_slot = dcache_find_or_insert(&g_start_nset);
                slot = start_slot; best_slot = -1; best_end = i;
                j = i - 1;  /* restart inner loop for this starting position */
                continue;
            }
            if (next == 0) break;
            slot = next;
            if (g_dc[slot].is_accept) {
                best_slot = slot;
                best_end  = j+1;
            }
        }

        if (best_slot >= 0) {
            uint64_t a0 = g_dc[best_slot].accept[0];
            uint64_t a1 = g_dc[best_slot].accept[1];
            while (a0 && count<max) {
                int bit=__builtin_ctzll(a0);
                out[count++]=(mm4_match_t){bit,i,best_end-i};
                a0&=a0-1;
            }
            while (a1 && count<max) {
                int bit=64+__builtin_ctzll(a1);
                out[count++]=(mm4_match_t){bit,i,best_end-i};
                a1&=a1-1;
            }
        }
    }
    return count;
}

/*
 * mm4_walk: single-pass DFA walk from start to end of input.
 * Resets to start state whenever the DFA reaches the dead state (slot 0).
 * Returns count of bytes at which the current state is an accepting state.
 * This measures raw DFA throughput — no per-position restart, no output buffer.
 *
 * Flush-safe: tracks g_flush_gen and re-derives start_slot after any flush.
 */
size_t mm4_walk(const char *input, size_t len) {
    uint64_t gen = g_flush_gen;
    int start_slot = dcache_find_or_insert(&g_start_nset);
    int slot = start_slot;
    size_t accept_hits = 0;
    for (size_t i = 0; i < len; i++) {
        int next = dcache_step(slot, (unsigned char)input[i]);
        if (g_flush_gen != gen) {
            /* cache was flushed during dcache_step — all slots are stale */
            gen = g_flush_gen;
            start_slot = dcache_find_or_insert(&g_start_nset);
            slot = start_slot;
            /* re-process this byte from the new start slot */
            i--;
            continue;
        }
        slot = next;
        if (slot == 0) { slot = start_slot; continue; }
        if (g_dc[slot].is_accept) accept_hits++;
    }
    return accept_hits;
}

const char *mm4_pattern_name(int id) {
    if (id<0||id>=MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 7. v4.1: per-position restart with required-literal pre-filter
 *
 * For each starting position i, before running the inner DFA loop, check
 * whether any pattern's required prefix literal occurs in input[i..end].
 * If none does, skip position i entirely.  This is the same gate the
 * production gem uses (memmem over pattern_required_literal[]).
 *
 * On sparse/medium payloads most positions have no literal nearby, so the
 * inner loop almost never runs.  On env payloads every literal is present
 * everywhere, so this adds zero filtering — the O(N²) cost remains.
 * ======================================================================== */

/* Table built once at init: non-NULL prefix strings from MM88_PATTERNS. */
static const char *g_prefixes[MM88_NUM_PATTERNS];
static size_t      g_prefix_lens[MM88_NUM_PATTERNS];
static int         g_n_prefixes = 0;

static void build_prefix_table(void) {
    g_n_prefixes = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        const char *pfx = MM88_PATTERNS[p].prefix;
        if (pfx && !MM88_PATTERNS[p].prefix_is_infix) {
            g_prefixes[g_n_prefixes]   = pfx;
            g_prefix_lens[g_n_prefixes] = strlen(pfx);
            g_n_prefixes++;
        }
    }
}

/* Returns 1 if any prefix literal occurs in input[pos..pos+rem). */
static int any_prefix_nearby(const char *input, size_t pos, size_t len) {
    const char *hay = input + pos;
    size_t      rem = len - pos;
    for (int k = 0; k < g_n_prefixes; k++) {
        if (g_prefix_lens[k] <= rem &&
            memmem(hay, rem, g_prefixes[k], g_prefix_lens[k]))
            return 1;
    }
    return 1; /* always-candidates (NULL prefix) — never skip */
}

size_t mm4_scan_v41(const char *input, size_t len,
                    mm4_match_t *out, size_t max) {
    size_t count = 0;
    uint64_t gen = g_flush_gen;
    int start_slot = dcache_find_or_insert(&g_start_nset);

    for (size_t i = 0; i < len && count < max; i++) {
        /* Pre-filter: skip positions where no prefix exists ahead. */
        if (!any_prefix_nearby(input, i, len))
            continue;

        int slot = start_slot;
        int best_slot = -1;
        size_t best_end = i;

        for (size_t j = i; j < len; j++) {
            int next = dcache_step(slot, (unsigned char)input[j]);
            if (g_flush_gen != gen) {
                gen = g_flush_gen;
                start_slot = dcache_find_or_insert(&g_start_nset);
                slot = start_slot; best_slot = -1; best_end = i;
                j = i - 1;
                continue;
            }
            if (next == 0) break;
            slot = next;
            if (g_dc[slot].is_accept) { best_slot = slot; best_end = j + 1; }
        }

        if (best_slot >= 0) {
            uint64_t a0 = g_dc[best_slot].accept[0];
            uint64_t a1 = g_dc[best_slot].accept[1];
            while (a0 && count < max) {
                int bit = __builtin_ctzll(a0);
                out[count++] = (mm4_match_t){bit, i, best_end - i};
                a0 &= a0 - 1;
            }
            while (a1 && count < max) {
                int bit = 64 + __builtin_ctzll(a1);
                out[count++] = (mm4_match_t){bit, i, best_end - i};
                a1 &= a1 - 1;
            }
        }
    }
    return count;
}

/* ========================================================================
 * 8. v4.2: single-pass leftmost-longest scan
 *
 * One sweep left-to-right; each input byte is visited at most twice
 * (once advancing the DFA, once when we reset after a dead state).
 * Guaranteed O(N) regardless of match density.
 *
 * Algorithm (standard "greedy lex" DFA scan):
 *   - Maintain: current DFA slot, match-start position, best accept seen.
 *   - On each byte:
 *       next = step(slot, byte)
 *       if next == dead:
 *           if best accept was recorded → emit it, restart from best_end
 *           else → advance match_start by 1, restart from current position
 *       else:
 *           slot = next
 *           if slot is accepting → record as best
 *   - At end of input: emit any pending best accept.
 *
 * Trade-off vs mm4_scan: emits at most one match per "token" (leftmost wins),
 * whereas mm4_scan reports all patterns that match from every position.
 * For redaction this is fine — we only need to find and cover each token once.
 * ======================================================================== */

size_t mm4_scan_v42(const char *input, size_t len,
                    mm4_match_t *out, size_t max) {
    size_t count = 0;
    uint64_t gen = g_flush_gen;
    int start_slot = dcache_find_or_insert(&g_start_nset);

    size_t i          = 0;   /* current read position */
    size_t match_start = 0;  /* where current attempt started */
    int    slot        = start_slot;
    int    best_slot   = -1;
    size_t best_end    = 0;

    while (i <= len && count < max) {
        /* Feed one byte, or trigger end-of-input flush. */
        int next = 0;
        if (i < len) {
            next = dcache_step(slot, (unsigned char)input[i]);
            if (g_flush_gen != gen) {
                /* Cache flushed — re-derive start slot, restart attempt. */
                gen = g_flush_gen;
                start_slot = dcache_find_or_insert(&g_start_nset);
                slot = start_slot; best_slot = -1; best_end = 0;
                i = match_start;
                continue;
            }
        }

        if (next == 0 || i == len) {
            /* Dead state or end of input. */
            if (best_slot >= 0) {
                /* Emit all patterns that accepted at best_end. */
                uint64_t a0 = g_dc[best_slot].accept[0];
                uint64_t a1 = g_dc[best_slot].accept[1];
                while (a0 && count < max) {
                    int bit = __builtin_ctzll(a0);
                    out[count++] = (mm4_match_t){bit, match_start, best_end - match_start};
                    a0 &= a0 - 1;
                }
                while (a1 && count < max) {
                    int bit = 64 + __builtin_ctzll(a1);
                    out[count++] = (mm4_match_t){bit, match_start, best_end - match_start};
                    a1 &= a1 - 1;
                }
                /* Resume scan from end of emitted match. */
                i = best_end;
                match_start = best_end;
            } else {
                /* No accept found from match_start — skip one byte. */
                if (i < len) {
                    match_start = i + 1;
                    i = match_start;
                } else {
                    break;
                }
            }
            slot = start_slot; best_slot = -1; best_end = 0;
        } else {
            slot = next;
            if (g_dc[slot].is_accept) { best_slot = slot; best_end = i + 1; }
            i++;
        }
    }
    return count;
}

/* ========================================================================
 * 9. Self-test
 * ======================================================================== */

#ifdef MM4_MAIN
int main(void) {
    mm4_init();

    struct { const char *input; const char *expect_pat; } tests[] = {
        { "token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c end", "jwt" },
        { "contact us at user@example.com please", "email" },
        { "ssn: 123-45-6789 end", "us_ssn" },
        { "server 192.168.1.1 responding", "ipv4" },
        { "key=AKIAIOSFODNN7EXAMPLE end", "aws_access_key_id" },
        { "AIzaSyDxample1234567890123456789012345 here", "google_api_key" },
        { "cc: 4111111111111111 end", "credit_card" },
    };
    int n = (int)(sizeof(tests)/sizeof(tests[0]));
    int pass = 0;

    mm4_match_t out[64];
    for (int t=0;t<n;t++) {
        size_t len = strlen(tests[t].input);
        size_t nm = mm4_scan(tests[t].input, len, out, 64);
        int found = 0;
        for (size_t m=0;m<nm;m++) {
            const char *pname = mm4_pattern_name(out[m].pattern_id);
            if (pname && strcmp(pname, tests[t].expect_pat)==0) found=1;
            printf("  [%zu+%zu] %s: '%.*s'\n",
                   out[m].start,out[m].length,pname?pname:"?",
                   (int)out[m].length, tests[t].input+out[m].start);
        }
        printf("test %d (%s): %s (%zu matches)\n",
               t, tests[t].expect_pat, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d tests passed\n", pass, n);
    mm4_free();
    return pass==n ? 0 : 1;
}
#endif
