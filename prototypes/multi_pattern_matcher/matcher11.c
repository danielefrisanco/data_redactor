/* matcher11.c — v11: 88 per-pattern Thompson bytecode VM. Zero dependencies.
 *
 * Each pattern is compiled once (at init) from POSIX-ERE to a flat bytecode
 * program. Scanning runs a classic two-list Thompson simulation (Cox 2009,
 * "Regular Expression Matching: the Virtual Machine Approach") over the
 * bytecode — no DFA cache, no precomputed transition table, no per-call malloc.
 *
 * Semantics match Ruby's String#gsub per pattern: leftmost-longest,
 * non-overlapping matches, scanned left to right. Boundary-wrapped patterns
 * are wrapped in (^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$) before compilation,
 * exactly like the pure-Ruby reference.
 *
 * Build:  make matcher11.so   (shared lib)
 *         make matcher11       (self-test binary)
 */

#define _GNU_SOURCE
#include "matcher11.h"
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
    } else { fprintf(stderr,"matcher11: unknown POSIX class [:%.*s:]\n",(int)len,cls); exit(1); }
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
} pat_engine_t;

static pat_engine_t g_engines[MM88_NUM_PATTERNS];
static int          g_initialized = 0;

#define WRAP_PFX "(^|[^0-9A-Za-z])("
#define WRAP_SFX ")([^0-9A-Za-z]|$)"

void mm11_init(void) {
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
    }
    g_initialized = 1;
}

void mm11_free(void) {
    for (int p = 0; p < MM88_NUM_PATTERNS; p++) {
        free(g_engines[p].prog.code);
        g_engines[p].prog.code = NULL;
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

/* Per-pattern scratch, sized at first use to prog.n. */
typedef struct {
    int      *list;   /* pc list */
    int       n;
} tlist_t;

static int      *g_seen[MM88_NUM_PATTERNS];   /* seen[pc] = generation */
static int       g_seen_cap[MM88_NUM_PATTERNS];
static tlist_t   g_clist[MM88_NUM_PATTERNS], g_nlist[MM88_NUM_PATTERNS];

/* addthread: epsilon-close pc into list `tl`, dedup via seen[]/gen.
 * pos is the current input position (for BOL/EOL evaluation). */
static void addthread(prog_t *pr, tlist_t *tl, int *seen, int gen,
                      int pc, const char *input, size_t len, size_t pos) {
    if (seen[pc] == gen) return;
    seen[pc] = gen;
    inst_t *in = &pr->code[pc];
    switch (in->op) {
    case OP_JMP:
        addthread(pr, tl, seen, gen, in->x, input, len, pos);
        break;
    case OP_SPLIT:
        addthread(pr, tl, seen, gen, in->x, input, len, pos);
        addthread(pr, tl, seen, gen, in->y, input, len, pos);
        break;
    case OP_BOL:
        if (pos == 0 || input[pos-1] == '\n')
            addthread(pr, tl, seen, gen, pc+1, input, len, pos);
        break;
    case OP_EOL:
        if (pos == len || input[pos] == '\n')
            addthread(pr, tl, seen, gen, pc+1, input, len, pos);
        break;
    default:
        /* byte-consuming op or MATCH — a real thread */
        tl->list[tl->n++] = pc;
        break;
    }
}

static size_t scan_one(int p, const char *input, size_t len,
                       mm11_match_t *out, size_t max, size_t count) {
    pat_engine_t *eng = &g_engines[p];
    prog_t       *pr  = &eng->prog;

    /* ensure scratch is large enough for this pattern's program */
    if (g_seen_cap[p] < pr->n) {
        g_seen[p]        = realloc(g_seen[p],        pr->n * sizeof(int));
        g_clist[p].list  = realloc(g_clist[p].list,  pr->n * sizeof(int));
        g_nlist[p].list  = realloc(g_nlist[p].list,  pr->n * sizeof(int));
        if (!g_seen[p] || !g_clist[p].list || !g_nlist[p].list) { perror("realloc"); exit(1); }
        memset(g_seen[p], 0, pr->n * sizeof(int));
        g_seen_cap[p] = pr->n;
    }
    int     *seen = g_seen[p];
    tlist_t *cl   = &g_clist[p], *nl = &g_nlist[p];
    int      gen  = 0;

    size_t pos = 0;
    while (pos <= len) {
        /* For prefix patterns, jump straight to the next literal occurrence. */
        if (eng->req_literal && eng->req_lit_at_start) {
            if (len - pos < eng->req_lit_len) break;
            const char *hit = memmem(input + pos, len - pos,
                                     eng->req_literal, eng->req_lit_len);
            if (!hit) break;
            pos = (size_t)(hit - input);
        }

        /* seed a fresh simulation starting at `pos` */
        gen++;
        cl->n = 0;
        addthread(pr, cl, seen, gen, 0, input, len, pos);

        size_t match_end = (size_t)-1;  /* longest accept end for this start */
        size_t sp = pos;
        while (cl->n > 0) {
            /* check accepts in the current list */
            for (int i = 0; i < cl->n; i++) {
                if (pr->code[cl->list[i]].op == OP_MATCH) {
                    if (sp - pos >= eng->min_len) match_end = sp;
                    break;  /* leftmost thread on list = highest priority */
                }
            }
            if (sp == len) break;

            unsigned char c = (unsigned char)input[sp];
            gen++;
            nl->n = 0;
            for (int i = 0; i < cl->n; i++) {
                inst_t *in = &pr->code[cl->list[i]];
                int matches = 0;
                switch (in->op) {
                case OP_CHAR:  matches = (in->ch == c); break;
                case OP_CLASS: matches = cc_test(&in->cc, c); break;
                case OP_ANY:   matches = (c != '\n'); break;
                default: break;  /* MATCH: dropped; handled above */
                }
                if (matches)
                    addthread(pr, nl, seen, gen, cl->list[i] + 1,
                              input, len, sp + 1);
            }
            /* swap cl <-> nl */
            tlist_t tmp = *cl; *cl = *nl; *nl = tmp;
            sp++;
        }

        if (match_end != (size_t)-1) {
            size_t span = match_end - pos;
            if (count < max) out[count++] = (mm11_match_t){p, pos, span};
            pos = (span == 0) ? pos + 1 : match_end;  /* non-overlapping */
        } else {
            pos++;
        }
    }
    return count;
}

size_t mm11_scan(const char *input, size_t len, mm11_match_t *out, size_t max) {
    size_t count = 0;
    for (int p = 0; p < MM88_NUM_PATTERNS && count < max; p++)
        count = scan_one(p, input, len, out, max, count);
    return count;
}

const char *mm11_pattern_name(int id) {
    if (id < 0 || id >= MM88_NUM_PATTERNS) return NULL;
    return MM88_PATTERNS[id].name;
}

/* ========================================================================
 * 8. Self-test
 * ======================================================================== */

#ifdef MM11_MAIN
int main(void) {
    mm11_init();

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
    mm11_match_t out[256];

    for (int t=0; t<n; t++) {
        size_t len=strlen(tests[t].input);
        size_t nm=mm11_scan(tests[t].input, len, out, 256);
        int found=0, no_expect=strcmp(tests[t].expect,"(none)")==0;
        for (size_t m=0; m<nm; m++) {
            const char *pn=mm11_pattern_name(out[m].pattern_id);
            if (!no_expect && pn && strcmp(pn,tests[t].expect)==0) found=1;
        }
        if (no_expect) found=(nm==0);
        printf("test %2d %-30s %s (%zu matches)\n",
               t, tests[t].expect, found?"PASS":"FAIL", nm);
        if (found) pass++;
    }
    printf("\n%d/%d passed\n", pass, n);
    mm11_free();
    return pass==n ? 0 : 1;
}
#endif
