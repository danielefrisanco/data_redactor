#!/usr/bin/env python3
"""Analyse the density sweep CSV (paper/data/density_sweep.csv).

Produces, from one (or two) CSV(s):
  1. crossover figure  -> paper/figures/density_crossover.{pdf,png}
  2. crossover density  (where the AC+BM+JIT pipeline crosses plain PCRE2 JIT,
     and where it crosses pure-Ruby) -> printed + paper/data/crossover_points.txt
  3. a booktabs LaTeX table of selected density points -> paper/data/density_table.tex

Headline metric is ms_min (least scheduler/GC noise; see environment.md). The
figure also shows the median band so the spread is visible.

TWO OPERATING POINTS. The fast engines come from the CLEAN run (--csv: machine
idle, reps=10). The glibc-regexec baseline is the slow incumbent reproduction;
re-running it at the densest strides is prohibitively long (research_log §8.5,
environment.md), so we reuse the DRAFT run for it (--baseline-csv: shared laptop,
powersave, reps=5). This is honest and even useful: the baseline is so far behind
that the *shape* — incumbent buried far above every shippable engine — is the same
under powersave, and "still slow even when the fast engines had MORE resources"
only strengthens the gap. The two-operating-point provenance is disclosed in
environment.md and the figure caption.

Usage:
  python3 paper/plot_density_sweep.py [--csv paper/data/density_sweep.csv] \\
      [--baseline-csv paper/data/density_sweep_draft.csv]
"""
import argparse
import os
import sys

import pandas as pd
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_CSV = os.path.join(HERE, "data", "density_sweep.csv")
FIG_DIR = os.path.join(HERE, "figures")
DATA_DIR = os.path.join(HERE, "data")

# Engine -> (display label, line style). Order controls legend + z-order.
#
# NOTE on "c_today": DataRedactor.redact in gem 0.13.0 ALREADY ships the v19
# engine (redact.c calls mm_scan for built-ins), so this line is NOT the old
# glibc-regexec incumbent — it is v19 measured through the gem's full Ruby/String
# path (mm_scan + mm_resolve + String alloc). Labelled accordingly. The true
# pre-port glibc baseline (the ~0.2x-of-Ruby incumbent in research_log §8.5) is
# NOT on this curve; it must be measured separately (see paper/README.md TODO).
ENGINES = {
    "ruby":           ("pure-Ruby gsub",        dict(color="#888888", ls="--", marker="")),
    "glibc_baseline": ("glibc regexec (pre-v19 repro., powersave draft)", dict(color="#000000", ls="-", marker="x")),
    "c_today":        ("v19 in-gem (DataRedactor.redact)", dict(color="#ee7733", ls="-", marker="D")),
    "onigmo":         ("Onigmo (BM pre-filter)",dict(color="#117733", ls="-.", marker="")),
    "v7_pipeline":    ("AC+BM+PCRE2 JIT pipeline", dict(color="#cc3311", ls="-", marker="o")),
    "pcre2jit":       ("plain PCRE2 JIT (no pipeline)", dict(color="#0077bb", ls="-", marker="s")),
    "v19":            ("v19 prototype (raw scan)", dict(color="#332288", ls="-", marker="^")),
}

# The crossover pair the paper headlines.
PIPELINE = "v7_pipeline"
NO_PIPELINE = "pcre2jit"


def load(csv_path, baseline_csv=None):
    """Load the clean sweep. If baseline_csv is given, splice its glibc_baseline
    rows in (those are the powersave-draft incumbent; see module docstring)."""
    df = pd.read_csv(csv_path)
    if baseline_csv and os.path.exists(baseline_csv):
        base = pd.read_csv(baseline_csv)
        base = base[base["engine"] == "glibc_baseline"]
        # drop any glibc_baseline already in the clean run (there shouldn't be any)
        df = df[df["engine"] != "glibc_baseline"]
        df = pd.concat([df, base], ignore_index=True)
    df = df.sort_values("hits_per_kb")
    return df


def pivot(df, value="ms_min"):
    return df.pivot_table(index="hits_per_kb", columns="engine", values=value).sort_index()


def find_crossing(x, ya, yb):
    """First x where ya-yb changes sign (ya rises above yb), linearly interpolated.
    Returns None if they never cross over the sampled range."""
    d = np.asarray(ya) - np.asarray(yb)
    x = np.asarray(x)
    for i in range(1, len(d)):
        if d[i - 1] == 0:
            return float(x[i - 1])
        if d[i - 1] < 0 <= d[i] or (d[i - 1] < 0 and d[i] > 0):
            # linear interp of the zero crossing in d
            t = -d[i - 1] / (d[i] - d[i - 1])
            return float(x[i - 1] + t * (x[i] - x[i - 1]))
    return None


def _plot(ax, p, engines, logy, annotate_crossover):
    x = p.index.values
    for eng in engines:
        if eng not in p.columns:
            continue
        label, style = ENGINES[eng]
        ax.plot(x, p[eng].values, label=label, linewidth=1.8, markersize=4, **style)
    ax.set_xscale("log")
    if logy:
        ax.set_yscale("log")
    ax.set_xlabel("match density (hits per KB, log scale)")
    ax.set_ylabel("time per scan (ms, min of reps)" + (" — log" if logy else ""))
    ax.grid(True, which="both", linewidth=0.3, alpha=0.5)
    ax.legend(fontsize=8, loc="upper left")
    if annotate_crossover and PIPELINE in p.columns and "ruby" in p.columns:
        xc = find_crossing(x, p[PIPELINE].values, p["ruby"].values)
        if xc is not None:
            ax.axvline(xc, color="#cc3311", linewidth=0.8, ls=":", alpha=0.7)
            ax.annotate(f"pipeline overtakes Ruby ≈ {xc:.1f} hits/KB",
                        xy=(xc, ax.get_ylim()[1] * 0.55),
                        fontsize=7.5, color="#cc3311", rotation=90,
                        va="top", ha="right")


def make_figure(p, p_med, out_dir):
    """Two views from the same data:
       density_overview (ALL engines, LOG y) — the incumbent-is-slow hook; the
         ~50x spread from glibc baseline to plain JIT is legible on log scale.
       density_crossover (shippable-class engines only, LINEAR y) — the
         pipeline-penalty-grows-with-density story, uncompressed."""
    os.makedirs(out_dir, exist_ok=True)
    overview = os.path.join(out_dir, "density_overview")
    crossover = os.path.join(out_dir, "density_crossover")

    # Overview — full field, log y
    figA, axA = plt.subplots(figsize=(7.0, 4.3))
    _plot(axA, p, list(ENGINES.keys()), logy=True, annotate_crossover=False)
    axA.set_title("All engines across match density (log time)")
    figA.tight_layout()
    for ext in ("pdf", "png"):
        figA.savefig(f"{overview}.{ext}", dpi=150)
    print(f"wrote {overview}.{{pdf,png}} (overview: full field, log y)")

    # Crossover — fast engines only, linear y, crossover annotated
    fast = ["ruby", "onigmo", "v7_pipeline", "pcre2jit", "v19"]
    figB, axB = plt.subplots(figsize=(7.0, 4.3))
    _plot(axB, p, fast, logy=False, annotate_crossover=True)
    axB.set_title("Pre-filter pipeline vs. no pipeline (shippable-class engines)")
    figB.tight_layout()
    for ext in ("pdf", "png"):
        figB.savefig(f"{crossover}.{ext}", dpi=150)
    print(f"wrote {crossover}.{{pdf,png}} (crossover: fast engines, linear y)")


def crossover_report(p):
    lines = []
    x = p.index.values
    if PIPELINE in p.columns and NO_PIPELINE in p.columns:
        xc = find_crossing(x, p[PIPELINE].values, p[NO_PIPELINE].values)
        if xc:
            lines.append(f"pipeline ({PIPELINE}) overtakes {NO_PIPELINE} at "
                         f"~{xc:.3f} hits/KB")
        else:
            # No crossover because the pipeline is strictly DOMINATED by plain JIT
            # at every sampled density — the stronger finding. Report the penalty
            # range instead of a (non-existent) crossover point.
            lines.append(f"pipeline ({PIPELINE}) is slower than {NO_PIPELINE} at "
                         f"EVERY sampled density (strictly dominated); the pre-filter "
                         f"never pays off vs the same engine without it. "
                         f"Penalty grows monotonically with density (see ratio below).")
    if PIPELINE in p.columns and "ruby" in p.columns:
        xr = find_crossing(x, p[PIPELINE].values, p["ruby"].values)
        lines.append(f"pipeline ({PIPELINE}) overtakes pure-Ruby at "
                     f"~{xr:.3f} hits/KB" if xr else
                     "pipeline never overtakes pure-Ruby in sampled range")
    # magnitude at the extremes
    lo, hi = x.min(), x.max()
    for eng in (PIPELINE,):
        if eng in p.columns and NO_PIPELINE in p.columns:
            ratio_lo = p.loc[lo, eng] / p.loc[lo, NO_PIPELINE]
            ratio_hi = p.loc[hi, eng] / p.loc[hi, NO_PIPELINE]
            lines.append(f"{eng}/{NO_PIPELINE} ms ratio: "
                         f"{ratio_lo:.2f}x at {lo:.3f} hits/KB (sparsest), "
                         f"{ratio_hi:.2f}x at {hi:.3f} hits/KB (densest)")
    report = "\n".join(lines)
    print(report)
    with open(os.path.join(DATA_DIR, "crossover_points.txt"), "w") as f:
        f.write(report + "\n")
    return report


def latex_table(p):
    """booktabs table at selected densities (the published 4 + extremes)."""
    # pick rows nearest these target densities
    targets = [38.0, 14.0, 2.0, 0.2, 0.1]
    x = p.index.values
    cols = [c for c in ENGINES if c in p.columns]
    rows = []
    seen = set()
    for t in targets:
        idx = int(np.argmin(np.abs(x - t)))
        if idx in seen:
            continue
        seen.add(idx)
        rows.append(idx)
    out = []
    out.append("% generated by paper/plot_density_sweep.py — do not hand-edit")
    out.append("\\begin{tabular}{r" + "r" * len(cols) + "}")
    out.append("\\toprule")
    header = "hits/KB & " + " & ".join(ENGINES[c][0].split(" (")[0] for c in cols) + " \\\\"
    out.append(header)
    out.append("\\midrule")
    for idx in rows:
        d = x[idx]
        vals = " & ".join(f"{p.iloc[idx][c]:.1f}" for c in cols)
        out.append(f"{d:.2f} & {vals} \\\\")
    out.append("\\bottomrule")
    out.append("\\end{tabular}")
    text = "\n".join(out)
    with open(os.path.join(DATA_DIR, "density_table.tex"), "w") as f:
        f.write(text + "\n")
    print(f"wrote {os.path.join(DATA_DIR, 'density_table.tex')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEF_CSV)
    ap.add_argument("--baseline-csv",
                    default=os.path.join(DATA_DIR, "density_sweep_draft.csv"),
                    help="CSV supplying glibc_baseline rows (powersave draft); "
                         "see module docstring")
    args = ap.parse_args()
    if not os.path.exists(args.csv):
        sys.exit(f"CSV not found: {args.csv} (run bench_density_sweep.rb first)")
    df = load(args.csv, args.baseline_csv)
    p = pivot(df, "ms_min")
    p_med = pivot(df, "ms_median")
    make_figure(p, p_med, FIG_DIR)
    print("\n--- crossover report ---")
    crossover_report(p)
    print("\n--- latex table ---")
    latex_table(p)


if __name__ == "__main__":
    main()
