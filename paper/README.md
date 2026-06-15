# Paper — planning & decisions

Working notes for the paper drawn from `docs/research_log.md`. This file is the
orientation for the `paper/` folder: thesis, target venue, authorship, writing
rules, contributions, the experiment backlog, and a decisions log. It is *not*
the paper — it is what we agree before drafting, so we don't relitigate.

Source of truth for results/numbers stays `docs/research_log.md`. This file
points at it; it does not duplicate the data.

---

## 1. Thesis (opener — locked for now)

> We report on replacing the regex engine behind a data-redaction library to
> improve performance under four production constraints — zero runtime
> dependencies, byte-for-byte-identical output to the incumbent, robustness
> across all match densities, and thread-safety in a managed runtime — and find,
> across a sequence of prototypes, that the speed-optimal engine is ruled out by
> those constraints, and that the pre-filter pipeline usually assumed best for
> multi-pattern matching does not hold across densities; the best shippable
> design is a per-pattern lazy DFA with two domain-specific merges.

**Shape:** objective (performance) *subject to* four constraints. The tension
that carries the paper: the change that would most improve performance (a JIT
engine) is exactly what the constraints forbid.

**The hook / starting tension:** the incumbent is a pure-Ruby `gsub` loop. The C
extension that was supposed to be faster was ~5× *slower* than the Ruby it
replaced (0.2× on our payloads). "A C extension that finally beats the Ruby loop
it replaces, across all densities" is the concrete goal — not speed in the
abstract.

**Mechanism of the hook — do NOT write this as a language result.** "C slower
than Ruby" is a category error and a reviewer will poke at it. The variable was
never the language; it was the regex engine each side calls. The C extension used
glibc `regexec`, which allocates O(N) state-log per call and has no BM-style
pre-filter (88 patterns × ~1 MB ≈ ~88 MB allocated per `redact` call). Ruby's
`gsub` calls Onigmo, which compiles a BM shift table and uses a fixed-size match
stack (O(1) allocation). The pure-Ruby loop was simply calling the *better
engine*; "C" bought essentially nothing because both ultimately dispatch to a
regex library and Ruby's was the better one. This reframes the paper from "make C
beat Ruby" to "the C-vs-Ruby framing is a category error — the real axis is engine
choice under constraints." (Research log §6.1, §8.6, conclusion.)

**Three spines, blended (not mutually exclusive):**
- #1 *the fastest engine isn't the shippable engine* — the abstract/framing.
- #2 *pre-filtering has a density crossover* — the sharpest single result (money
  figure), referenced in the opener, not the headline.
- #3 *a search across a sequence of prototypes* — the method/structure; the
  negative results are the meat, not an appendix.

---

## 2. Objective & constraints (the evaluation spine)

**Objective.** Beat the incumbent (pure-Ruby `gsub` loop) on performance,
*robustly across match densities* — optimize worst-case across sparse / medium /
dense / env, not peak on one payload. All-density robustness is part of the
objective; in the opener it is listed as a constraint for readability.

**Gates (binary, disqualifying — an engine either passes or is ineligible):**
1. **Zero runtime dependencies** — disqualifies PCRE2 JIT (needs `libpcre2` +
   `mmap(PROT_EXEC)`; the fastest option, ruled out here).
2. **Byte-for-byte-identical output to the incumbent** — disqualifies the merged
   NFA (v4.2: 31% correctness on overlapping alphabets). The exact-output oracle
   is unusually strong for a matcher paper — emphasize it.
3. **Thread-safety in a managed runtime (Ruby/GVL)** — disqualified the prototype
   globals until the immutable/mutable + per-thread refactor (gem 0.12.0–0.13.0).

The evaluation section follows this order: **gates first** (who is even
eligible), **then the density curve** (who is actually fast where it counts).

---

## 3. Target venue

- **arXiv first, unconditionally** (cs.PL + cs.DS) — establishes priority, costs
  nothing, gives a citable URL. Do this regardless of journal timing.
- **Software: Practice & Experience (Wiley)** — primary target. Scope is
  literally "practical experience"; no novel-algorithm bar; single-author normal;
  no travel; reproducible-artifact + root-cause-profiling story fits its house
  style. Accepts LaTeX (Wiley `WileyNJD-v2` class).
- **USENIX HotOS / ;login:** — optional fast side-channel for the density-crossover
  insight (5-page position paper), months not a year. Only if we want early
  feedback; not required.
- **Not targeting** ATC / EuroSys / OOPSLA for the first submission — a stretch
  for a solo experience report with no new algorithm. Do not reframe toward them.

**Format:** LaTeX. Write directly in the venue's class, don't reformat later.
Plan: draft in `acmart` for arXiv, port to `WileyNJD-v2` for S:P&E. Benchmark
tables **generated** from bench output into `booktabs`, not hand-typed
(reproducibility — §6).

---

## 4. Authorship & AI disclosure (settled — do not relitigate)

- **Daniele Frisanco, sole author.** Claude (Anthropic) cannot be a listed author:
  ACM / IEEE / USENIX / Wiley all require an author to take accountability and
  consent to publication, which an AI tool cannot. The accepted practice is
  disclosure, not byline.
- **Disclosure sentence** (acknowledgments / methods), wording TBD:
  *"Claude (Anthropic) was used for drafting, literature triage, and
  code/benchmark implementation; the author reviewed and is responsible for all
  content."*
- If a human co-author is ever wanted (helps competitive venues), that is a
  separate conversation — would be a person who can take accountability.

---

## 5. Writing rules (tone — enforce throughout)

- **No superlatives / strong adjectives** ("catastrophically", "dramatically",
  "huge"). State the mechanism and the number instead.
- **Claim the mechanism generally; claim the magnitude locally.** A reviewer can
  say "that's just your setup" about a magnitude, not about a mechanism we scoped.
  - ❌ "AC+BM catastrophically degrades on dense input."
  - ✅ "In our configuration, the pre-filter stops paying off as hit density rises:
    when most positions survive the filter, its coordination cost is no longer
    amortized; on our env-style payload the pipelined JIT was ~3× slower than the
    same JIT without the pipeline."
- **Scope every empirical claim** — "in our configuration", "on our pattern set",
  "on our payloads". Our results are *our* results; the value is the measured
  mechanism, not a universal verdict.
- **Honesty as contribution.** Report the null results (v15.2 union bitmap, v17
  precomputed init) and the abandoned designs with reasons. The search is the
  science.
- **Specialization, not a new algorithm.** The selective merges are structural
  recognition of disjoint subsets, not a grouping heuristic — frame as such, do
  not borrow citations (PLOS One / FREME / DPI grouping) whose method we did not
  use. (See research log §"Related work — where v19's selective merge sits".)

---

## 6. Open experiments / backlog before submission

Tracked from research log §14.4. `[ ]` = not done, `[~]` = partial/draft.

- [~] **Benchmark rigor** — hardware/OS/lib versions captured in
      `paper/data/environment.md`. Sweep reports min/median/mean over reps.
      STILL OPEN: numbers are a single session on a shared laptop under the
      `powersave` governor with other apps running — MUST RE-RUN clean (quiet
      machine, `performance` governor, more reps) before any submission. Today's
      curve is a DRAFT for shape, not final magnitudes. (See §9 caveats.)
- [~] **Density-crossover sweep** — DONE as a draft: `bench_density_sweep.rb`
      sweeps 21 log-spaced densities × 10 engines → `paper/data/density_sweep.csv`;
      figures `paper/figures/density_overview.{pdf,png}` (all engines, log y — the
      hook) + `density_crossover.{pdf,png}` (fast engines, linear y — the money
      figure). Finding reframed (§9):
      the pipeline is *strictly dominated* by plain JIT at every density (no
      crossover between them); the genuine crossover is pipeline-vs-pure-Ruby at
      ~11 hits/KB. Re-run pending (rigor item above).
- [ ] **Profiling evidence** — perf / callgrind showing cycles in glibc (alloc)
      vs Onigmo (BM) vs v19 (table lookup). Supports "bottleneck is per-call
      state-log allocation, not missing BM".
- [ ] **Reproducibility artifact** — self-contained Makefile / Docker packaging
      prototypes + bench scripts. S:P&E encourages; arXiv benefits.
- [x] **Table generation** — `paper/plot_density_sweep.py` turns the CSV →
      `booktabs` LaTeX (`paper/data/density_table.tex`) + the figure + the
      crossover report. Numbers are generated, not hand-typed.
- [x] **Incumbent baseline reproduction** — the original pre-v19 glibc engine is
      no longer in the shipped gem (0.13.0 ships v19; `redact.c` calls `mm_scan`).
      Rather than build an old gem, `matcher_glibc.{c,h}` REPRODUCES it (plain
      sequential `regexec`, no AC/BM, boundary-wrapped, scan-only). Verified to
      find the same matches as v19 (400/400 on a multi-pattern sample). The paper
      MUST state we benchmark against a *reproduction*, not the original code.
- [ ] **In-gem vs prototype reconciliation** — already noted in research log
      (2.21×/… prototype vs 2.33×/… in-gem); make sure the paper states which
      number is which and why.
- [ ] **AI-use methodology write-up** — beyond the one-line §4 disclosure, write a
      concrete account of HOW the author used Claude, in the author's voice. This
      is both honest disclosure and methodologically interesting (the search was a
      human-directed, AI-executed loop). Cover, with who-did-what kept explicit:
      - the author SET the direction and the hypotheses — e.g. how the author
        thought the algorithm should work (the per-pattern vs merged intuition,
        the selective-merge idea), the constraint box, the thesis framing;
      - the author DIRECTED Claude to do the literature research / triage, build
        the prototypes and the benchmark harness, run the sweeps, and draft prose;
      - the author REVIEWED, corrected, and is accountable for every result and
        claim (caught the c_today mislabel, set the re-run/no-fabrication policy,
        locked tone rules).
      Decide placement: a short "How this paper was produced" note (methods or an
      appendix) vs. expanding the §4 \acks sentence. Keep it factual, first-person,
      no overclaiming in either direction (neither "all AI" nor hiding the tooling).
      Source material: this repo's git history + the planning decisions log (§10).

---

## 7. Paper outline (draft — from research log §14.1, restructured to the spine)

1. **Introduction** — the hook (C extension slower than the Ruby it replaced);
   objective + four constraints; contributions.
2. **Background** — data redaction, the 88-pattern set, the pure-Ruby baseline,
   why a C extension was expected to win.
3. **The constraint box** — the three gates + the all-density objective; why each
   gate disqualifies an otherwise-attractive option.
4. **Method — the prototype search** — the ladder, how each was measured, the
   exact-output oracle, the four payloads.
5. **Findings** —
   5.1 root cause of the incumbent C extension's slowness (allocation, not BM);
   5.2 the pre-filter density crossover (#2, money figure);
   5.3 the per-pattern lazy DFA + two selective merges (the shippable design);
   5.4 prototype→production hardening (GVL-free re-entrancy).
6. **Evaluation** — gates first, then density curve; vs Ruby / glibc / Onigmo /
   PCRE2 JIT.
7. **Discussion / threats to validity** — scope of claims, where it generalizes.
8. **Related work** — Cox lazy DFA (used as-is), RE2::Set / RegexSet state
   explosion (the wall we avoid), and the explicit *non*-citation of grouping
   heuristics.
9. **Conclusion.**

---

## 9. Density-sweep findings & caveats (2026-06-14, DRAFT data)

Artifacts: `bench_density_sweep.rb`, `paper/data/density_sweep.csv`,
`paper/figures/density_overview.{pdf,png}` + `density_crossover.{pdf,png}`,
`paper/plot_density_sweep.py`,
`paper/data/density_table.tex`, `paper/data/environment.md`.

**Findings (clean run 2026-06-15 for the fast engines; glibc baseline is the
powersave draft — see caveat 1):**
- The AC+BM+PCRE2-JIT **pipeline is slower than the same JIT without the pipeline
  at EVERY sampled density** — strictly dominated, not a crossover between the two.
  The penalty grows monotonically with hit density: **1.20× at 0.10 hits/KB
  (sparsest) → 11.01× at 38.3 hits/KB (densest)** [clean run; draft was ~10.2×].
- The genuine crossover is **pipeline vs pure-Ruby at ~12.0 hits/KB** [clean run;
  draft ~11]: below it the pipeline beats the Ruby loop; above it the optimized C
  pipeline is slower than the Ruby it was meant to replace. The sharp §5.2 sentence.
- Mechanism (state generally, magnitude locally): a literal/AC pre-filter only
  pays off by *rejecting* positions; as more positions carry a hit, fewer are
  rejected, so the filter's per-position cost is paid without the skip benefit.
  Onigmo (also BM-pre-filtered) climbs with density too — independent corroboration.
- v19 (shipped) stays low and flat across all densities — visually the robust
  choice, which is the whole point of the all-density objective.

**Caveats — MUST address before using these numbers in the paper:**
1. **Two operating points (provenance split).** The fast/shippable engines are
   the CLEAN run (machine idle, reps=10, `density_sweep.csv`). The glibc baseline
   reuses the DRAFT run (shared laptop, powersave, reps=5, `density_sweep_draft.csv`):
   a clean re-run of the slow incumbent at the dense strides is impractical (it
   was already the dominant cost of the draft sweep and grows with density —
   research_log §8.5), and we do NOT fabricate/extrapolate its numbers. This is
   fine and even useful: the baseline sits ~10× above every shippable engine, so
   its shape is unchanged by the governor, and "still buried while the fast engines
   ran with MORE resources" only widens the gap. The figure caption and
   environment.md must disclose this split.
2. **"c_today" line is mislabeled in raw CSV** — `DataRedactor.redact` in gem
   0.13.0 already runs v19, so that line is *v19-in-gem*, NOT the old engine. The
   plot relabels it "v19 in-gem (DataRedactor.redact)". Useful: it shows the
   prototype→production overhead (in-gem vs raw v19 scan).
3. **The glibc baseline is a REPRODUCTION** (`matcher_glibc.so`), not the original
   pre-v19 gem code, which is gone from the shipping gem. The paper must say we
   benchmark against a faithful reproduction (plain sequential regexec, no AC/BM)
   because the gem has since been improved — not against the original code.
4. **`env` payload not in the sweep** — different construction (all-secrets), lives
   in `bench_realistic.rb`. The sweep is the `build_spaced` density axis only.

---

## 9b. Building the paper

Skeleton: `main.tex` (acmart, `[acmsmall,nonacm]` for an arXiv-style preprint),
`refs.bib` (seeded from research log §3/§14.3 — several entries need a citation
check, marked TODO), `Makefile` (latexmk), `.gitignore` (LaTeX artifacts).

No LaTeX toolchain is installed locally yet. To build:
```
sudo apt install texlive-latex-recommended texlive-latex-extra \
                 texlive-fonts-recommended texlive-publishers latexmk
cd paper && make            # -> main.pdf
make figures                # regenerate figures + density_table.tex from CSV
```
`texlive-publishers` provides `acmart.cls`. Alternatively upload `paper/` to
Overleaf. Section bodies are TODO stubs; figures, the generated table, and the
bibliography are already wired in. Port `\documentclass` to `WileyNJD-v2` for the
S:P&E submission.

---

## 10. Decisions log

- **2026-06-14** — Folder created; planning before files (this doc).
- **2026-06-14** — Authorship: Daniele Frisanco sole author + AI disclosure.
- **2026-06-14** — Venue: arXiv → S:P&E primary; HotOS optional; not ATC/EuroSys/
  OOPSLA first.
- **2026-06-14** — Format: LaTeX (`acmart` for arXiv, `WileyNJD-v2` for S:P&E).
- **2026-06-14** — Thesis opener locked (§1, "B with sequence" wording).
- **2026-06-14** — Model: performance *objective* subject to 3 binary gates;
  all-density robustness is the objective's worst-case axis but listed as a
  constraint in the opener for readability.
- **2026-06-14** — Tone rule: no superlatives; claim mechanism generally,
  magnitude locally; scope every claim.
- **2026-06-14** — Density sweep run (draft). Finding reframed: pipeline strictly
  dominated by plain JIT (not a crossover); real crossover is pipeline-vs-Ruby at
  ~11 hits/KB. Numbers are draft (shared laptop, powersave) — flagged for clean
  re-run before submission.
- **2026-06-14** — Incumbent baseline: reproduce the pre-v19 glibc engine as a
  prototype (`matcher_glibc`) and state in the paper we test against a
  *reproduction* (gem has since shipped v19), not the original code.
- **2026-06-14** — Scaffolded the acmart skeleton (`main.tex`, `refs.bib`,
  `Makefile`, `.gitignore`). No local LaTeX toolchain yet — install later or use
  Overleaf (§9b). Figures + table + bib wired; section bodies are TODO stubs.
- **2026-06-15** — Clean re-run policy: only re-measure tests that finish in
  ~1-2 min; do NOT re-run the slow ones (glibc baseline on dense strides). For
  those, state in the paper that a full re-run is impractical given the measured
  cost — do NOT fabricate/extrapolate numbers. Draft (powersave) glibc baseline
  preserved in `density_sweep_draft.csv` as the documented reference.
- **2026-06-15** — Powersave draft data is KEPT and USED as a second operating
  point: "even under constrained CPU resources (powersave, shared machine), the
  shippable engines stay fast and the crossover holds" — a robustness result,
  not throwaway. Clean (performance-mode) run is the headline; powersave is the
  corroborating second condition.
- **2026-06-15** — Clean fast-engine sweep DONE (21 strides × 9 engines, reps=10,
  machine idle; `density_sweep.csv`, 189 rows). Confirms+sharpens the draft:
  pipeline strictly dominated, penalty 1.20×→11.01×; pipeline-vs-Ruby crossover
  ~12.0 hits/KB. `plot_density_sweep.py` now takes `--baseline-csv` and splices
  the glibc baseline from `density_sweep_draft.csv` (powersave) into the clean
  fast-engine data — the two-operating-point figure. Glibc legend label and
  caption disclose the powersave provenance.
- **2026-06-15** — LaTeX toolchain installed; skeleton compiles to a 5-page PDF
  (`main.pdf`, committed). Drafted §3 (constraint box) + §5.1/§5.2 (findings).
  Fixes: dropped unused `siunitx`; `\resizebox` the density table to fit
  `acmsmall`; ignore `*.cut` build artifact.
- **2026-06-15** — Author asked for an AI-use methodology write-up (backlog §6):
  a concrete, first-person account of how the author used Claude — set the
  hypotheses/algorithm intuition, directed the research/benchmark/prototype work,
  reviewed and is accountable for results. Beyond the boilerplate §4 disclosure;
  framed as honest methodology (human-directed, AI-executed search loop), not
  self-deprecation or AI-credit. Placement (methods note vs appendix vs expanded
  \acks) TBD.
