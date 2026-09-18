# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation
#
# Multi-stage build — three stages:
#   deps    : compile Cargo dependencies only (cached layer, rebuilt only on Cargo.lock change)
#   builder : compile grype-verify binary
#   grype   : download grype CLI into a scratch-like stage
#   runtime : minimal Debian slim image with grype + grype-verify
#
# Build:
#   podman build -t grype-verify:latest .
#   podman build --build-arg GRYPE_VERSION=0.115.0 -t grype-verify:0.115 .
#
# Run scan:
#   podman run --rm \
#     -v /path/to/grype-db:/data/grype-db \
#     -v /path/to/checks:/data/checks \
#     -v /path/to/sbom.spdx.json:/sbom.spdx.json:ro \
#     grype-verify:latest scan /sbom.spdx.json --output table --fail-on critical
#
# Run API server:
#   podman run -d --name grype-api \
#     -v /path/to/checks:/data/checks \
#     -p 8080:8080 \
#     grype-verify:latest serve --bind 0.0.0.0 --port 8080
#
# Quick status:
#   podman run --rm -v /path/to/checks:/data/checks grype-verify:latest status

ARG RUST_VERSION=1
ARG DEBIAN_VERSION=bookworm
ARG GRYPE_VERSION=0.115.0

# ── Stage 1: compile Cargo dependencies (cache-friendly) ──────────────────────
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS deps

WORKDIR /build
COPY Cargo.toml Cargo.lock ./

# Build a dummy binary so Cargo compiles and caches all dependencies.
# The real source is compiled in the next stage; only Cargo.lock changes
# invalidate this layer.
RUN mkdir src \
    && echo 'fn main(){}' > src/main.rs \
    && cargo build --release \
    && rm -rf src target/release/grype-verify* target/release/.fingerprint/grype-verify*

# ── Stage 2: compile grype-verify ─────────────────────────────────────────────
FROM deps AS builder

COPY src/ ./src/
# Force Cargo to relink the binary against the already-compiled deps.
RUN touch src/main.rs \
    && cargo build --release \
    && strip target/release/grype-verify

# ── Stage 3: download grype CLI ───────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS grype-dl

ARG GRYPE_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSfL \
         https://raw.githubusercontent.com/anchore/grype/main/install.sh \
       | sh -s -- -b /usr/local/bin "v${GRYPE_VERSION}"

# ── Stage 4: runtime image ────────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# ca-certificates is needed for grype's HTTPS DB update.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=grype-dl  /usr/local/bin/grype        /usr/local/bin/grype
COPY --from=builder   /build/target/release/grype-verify /usr/local/bin/grype-verify

# /data/grype-db  – grype vulnerability database cache (mount a persistent volume)
# /data/checks    – SQLite checks database (mount a persistent volume)
# /data/sarif     – SARIF reports written via --sarif-file (mount to retrieve them)
VOLUME ["/data/grype-db", "/data/checks", "/data/sarif"]

ENV GRYPE_DB_CACHE_DIR=/data/grype-db \
    GRYPE_CHECKS_DB=/data/checks/grype-checks.db

# REST API port (only relevant for the `serve` subcommand)
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD grype-verify status || exit 1

ENTRYPOINT ["grype-verify"]
CMD ["--help"]
