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
- **Two runs exist.** (1) DRAFT: 2026-06-14, iters=10/reps=5, shared laptop with
  other apps running, `powersave`. (2) CLEAN: 2026-06-14, iters=10/reps=10,
  machine otherwise idle, frequency cap removed. The CLEAN run is the one whose
  numbers the paper should use.
- **CPU governor on the CLEAN run.** `performance` was requested
  (`cpupower frequency-set -g performance`) but on this AMD `amd-pstate` system the
  kernel kept reporting `powersave` (only `powersave`/`performance` are offered and
  the active-mode driver did not honor the switch). In practice cores boost to
  ~4.7 GHz under load (observed; policy max 4.77 GHz). Mitigation: the headline
  metric is **ms_min over reps**, which captures the best (fully-boosted) reps and
  discards downclocked ones, so per-rep frequency wander is largely filtered.
  median/mean are also recorded to show spread.
- The CROSSOVER SHAPE is robust regardless (all engines run in one process under
  identical conditions); only absolute ms carry the governor caveat.
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
