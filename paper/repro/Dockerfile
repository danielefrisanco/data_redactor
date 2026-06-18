# Reproducibility artifact for the data_redactor performance paper.
#
# Pins the toolchain documented in paper/data/environment.md (Ubuntu 22.04, gcc
# 11, glibc 2.35, libonig 6.9, libpcre2 10.39) so a reviewer can rebuild the
# prototypes and regenerate the density sweep, the Callgrind profiling table, and
# the figures with one command. See paper/repro/README.md.
#
# Build (from the repo root, so the whole tree is in context):
#   docker build -t dr-repro -f paper/repro/Dockerfile .
# Run a target:
#   docker run --rm -v "$PWD:/work" dr-repro make -C paper/repro all
#
# Bind-mounting the repo (-v "$PWD:/work") writes regenerated CSVs/figures back to
# your checkout. Omit the mount to keep everything inside the container.
#
# Base: official Ruby 3.1 (matches the Ruby 3.1.4 of environment.md and the
# bundler 2.6.9 pinned in Gemfile.lock, which needs Ruby >= 3.1). Debian-based;
# the gcc/glibc point releases differ slightly from the Ubuntu 22.04 host of
# environment.md, which only affects absolute timings, not the reproduced shape.
FROM ruby:3.1

ENV DEBIAN_FRONTEND=noninteractive

# The two optional regex libraries the pipeline prototypes link (libonig for
# v3/v5/onigmo, libpcre2 for v7), valgrind for the profiling target, and the
# Python stack for the figures/tables. build-essential/gcc/make/ruby are already
# in the base image. Use a venv so pip does not fight Debian's PEP 668 guard.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libonig-dev \
        libpcre2-dev \
        valgrind \
        python3 python3-venv python3-pip \
        ca-certificates \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir pandas numpy matplotlib \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:${PATH}"

# Default: the repo is bind-mounted (or COPYed) at /work.
WORKDIR /work

# If no bind mount is used, the image still carries a copy of the tree.
COPY . /work

CMD ["make", "-C", "paper/repro", "all"]
