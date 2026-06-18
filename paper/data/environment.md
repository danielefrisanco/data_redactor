# Benchmark environment

Captured 2026-06-14 for the density sweep (`density_sweep.csv`) and the §14.4
rigor pass. Pin this with every results file so the paper's "experimental setup"
section is reproducible.

## Hardware
- **CPU:** AMD Ryzen 7 PRO 6850U with Radeon Graphics (Zen 3+, x86_64)
- **Cores/threads:** 8 cores / 16 threads (2 threads per core), 1 socket
- **Cache:** L1d 256 KiB (8×32K), L1i 256 KiB, L2 4 MiB (8×512K), L3 16 MiB (shared)
- **Memory:** 30 GiB total
- Relevant ISA flags: avx2, bmi1/bmi2, sha_ni, aes, vaes, clflushopt, rdseed

## OS / kernel
- Ubuntu 22.04.5 LTS
- Kernel 6.8.0-124-generic

## Toolchain / libraries
- Ruby 3.1.4p223 (x86_64-linux)
- gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04.3)
- glibc 2.35 (Ubuntu GLIBC 2.35-0ubuntu3.13)
- libonig 6.9.7.1-2build1 (Onigmo/Oniguruma — the Onigmo baseline)
- libpcre2 10.39-3ubuntu0.1 (PCRE2 JIT baseline)

## Timing caveats (disclose in paper)
- **Runs.** (1) CLEAN (fast engines): 2026-06-14, iters=10/reps=10, machine
  otherwise idle, performance clock. (2) glibc baseline (performance):
  `density_sweep_glibc_perf.csv`, 2026-06-18, iters=10/reps=10, machine idle,
  governor verified at `performance` (16 cores), cores at ~4.6-4.7 GHz under load.
  These two together are the numbers the paper uses, at one consistent operating
  point. An older DRAFT (`density_sweep_draft.csv`, iters=10/reps=5, shared laptop,
  power-saving) is retained for provenance only and is no longer used by the table
  or figures.
- **CPU governor.** On this AMD `amd-pstate` (active, `amd-pstate-epp`) system, the
  cores run at full clock (~4.7 GHz under load; policy max 4.77 GHz) at the
  performance operating point. For the CLEAN fast-engine run the governor readout
  showed `powersave` but the silicon boosted to ~4.7 GHz under load (i.e. effectively
  performance, confirmed by the per-scan times); for the 2026-06-18 glibc run the
  governor was explicitly switched to `performance` and verified across all 16 cores.
  Headline metric is **ms_min over reps**, which captures the best (fully-boosted)
  reps; median/mean are recorded to show spread.
- The CROSSOVER SHAPE is robust regardless (all engines run in one process under
  identical conditions); only absolute ms carry any governor sensitivity, and the
  ordering/crossover were identical under the older power-saving draft.
- Laptop part (mobile Ryzen): thermal throttling possible on long runs. Sweep
  inits/frees each engine per stride to avoid one engine's heat biasing the next.
- Single-process, single-thread timing (GVL held); the GVL-release / parallelism
  results are a separate measurement, not part of this sweep.

## Methodology (this sweep)
- Payload: `build_spaced(stride)` from `bench_density_sweep.rb` — identical noise
  (Lorem ipsum) + 8-hit rotation as `bench_realistic.rb`, fixed seed 42, ~1 MB
  buffer. Only the stride varies.
- Per (stride, engine): init once, 1 warmup scan, then `reps` reps of `iters`
  timed scans; record min / median / mean of per-rep ms/scan.
- Strides: log-spaced 5..10000 unioned with the published {50, 500, 5000}.
- `env` payload (all-secrets, separate builder) is NOT in this sweep — it lives in
  `bench_realistic.rb` because it uses a different construction.
