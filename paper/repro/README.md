# Reproducibility artifact

Self-contained bundle to rebuild the prototypes and regenerate the paper's
quantitative results: the match-density sweep (Fig. 1–2, Table 2), the Callgrind
instruction-attribution table (§5.1, Table 1), and the figures. Everything runs
from one Docker image that pins the toolchain in
[`../data/environment.md`](../data/environment.md).

## Quick start

From the **repo root** (so the whole tree is in the build context):

```sh
docker build -t dr-repro -f paper/repro/Dockerfile .

# Regenerate everything (writes back into your checkout via the bind mount):
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro all

# Or one stage at a time:
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro build
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro sweep
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro profile
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro figures
docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro verify
```

Drop `-v "$PWD:/work"` to keep all regenerated files inside the container instead
of writing them back to your working copy.

## Make targets

| Target | What it does | Outputs |
|--------|--------------|---------|
| `build` | `bundle install`, `rake compile` (the gem), and `make` the prototype engines the sweep loads | the gem `.so`, prototype `.so`s |
| `sweep` | run `bench_density_sweep.rb` across the density range | `paper/data/density_sweep.csv` |
| `profile` | run `profile_engines.sh` (Callgrind on glibc / Onigmo / v19) | `paper/data/profile_*.txt`, `profile_summary.csv` |
| `figures` | `plot_density_sweep.py` + `gen_profile_table.py` | `paper/figures/*.pdf`, `paper/data/density_table.tex`, `profile_table.tex` |
| `all` | `build sweep profile figures` | all of the above |
| `verify` | assert the regenerated outputs exist and are non-empty | — |

Knobs: `make sweep ITERS=10 REPS=10` to match the paper's clean run (defaults are
the faster draft settings).

## What reproduces, and what does not

- **Reproducible exactly:** the Callgrind instruction attribution (`profile`) —
  it counts instructions retired, not cycles, so it is deterministic across runs
  and machines. The match counts (18 146/scan, identical across all three
  engines) are a built-in cross-engine correctness check.
- **Reproducible in shape, not in absolute ms:** the density sweep. Absolute
  milliseconds depend on the host CPU, governor, and thermal headroom (see the
  caveats in [`../data/environment.md`](../data/environment.md)). The
  **qualitative results the paper claims** — the pre-filter pipeline's penalty
  growing with density, the crossover against pure-Ruby near ~12 hits/KB, the
  flat lazy-DFA curve — are properties of the designs and hold regardless of
  hardware.
- **Not re-run by this artifact:** the glibc baseline column of the density table
  is reused from an earlier `powersave` run by design (re-measuring the slow
  incumbent across the dense strides is impractical; see §7). The artifact
  regenerates everything else.

## Building the PDF

The image carries the prototypes/benchmark toolchain, not a full LaTeX install.
Build `paper/main.pdf` with a TeX distribution on the host:

```sh
make -C paper        # needs texlive (see paper/Makefile header for packages)
```

## Running without Docker

The same targets work on a host matching `../data/environment.md`. Install the
prerequisites the Dockerfile lists (`build-essential`, `ruby`/`ruby-dev`,
`bundler`, `libonig-dev`, `libpcre2-dev`, `valgrind`, and Python `pandas`/`numpy`/
`matplotlib`), then run `make -C paper/repro all` directly.
