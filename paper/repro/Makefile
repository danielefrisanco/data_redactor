# paper/repro/Makefile — reviewer-facing entrypoint for the reproducibility
# artifact. Run inside the Docker image (paper/repro/Dockerfile), which pins the
# toolchain, or on a host that matches paper/data/environment.md.
#
#   make build     compile the gem + all prototype engines the sweep needs
#   make sweep      regenerate paper/data/density_sweep.csv (the density sweep)
#   make profile    regenerate the Callgrind instruction-attribution tables
#   make figures    regenerate figures + density/profile LaTeX tables from data
#   make all        build sweep profile figures
#   make verify     sanity-check the regenerated outputs exist and are non-empty
#
# NOTE: absolute milliseconds depend on the host CPU; the qualitative results
# (the density crossover, the profiling attribution) do not. See README.md.

# Repo root is two levels up from paper/repro/.
ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
PROTO := $(ROOT)/prototypes/multi_pattern_matcher
PAPER := $(ROOT)/paper
DATA  := $(PAPER)/data

# Engine .so set the density sweep loads (bench_density_sweep.rb), plus the
# standalone glibc baseline reproduction.
SWEEP_SOS := matcher_glibc.so matcher7.so matcher7_plain.so \
             matcher7_plain_onig.so matcher15.so matcher18.so \
             matcher18_1.so matcher19.so

# Sweep size knobs (override on the command line, e.g. `make sweep REPS=10`).
ITERS ?= 10
REPS  ?= 5

.PHONY: all build sweep profile figures verify clean

all: build sweep profile figures

build:
	cd $(ROOT) && bundle install
	cd $(ROOT) && bundle exec rake compile
	cd $(PROTO) && $(MAKE) $(SWEEP_SOS)

sweep:
	cd $(PROTO) && bundle exec ruby bench_density_sweep.rb \
	    --csv $(DATA)/density_sweep.csv --iters $(ITERS) --reps $(REPS)

profile:
	cd $(PROTO) && ./profile_engines.sh 1

figures:
	cd $(PAPER) && $(PYTHON) plot_density_sweep.py
	cd $(PAPER) && $(PYTHON) gen_profile_table.py

PYTHON ?= python3

verify:
	@for f in $(DATA)/density_sweep.csv $(DATA)/density_table.tex \
	          $(DATA)/profile_summary.csv $(DATA)/profile_table.tex \
	          $(PAPER)/figures/density_overview.pdf; do \
	    if [ -s "$$f" ]; then echo "ok   $$f"; \
	    else echo "MISSING/EMPTY  $$f"; exit 1; fi; \
	done
	@echo "All reproducibility outputs present."

clean:
	cd $(PROTO) && $(MAKE) clean
