# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the `certrelay` binary.
#
# Stage 1 ("builder") compiles the Rust workspace against musl on Alpine,
# producing a statically-linked binary. Stage 2 ("runtime") copies only
# the binary, a tiny entrypoint, and the minimum runtime packages
# (ca-certificates + tini) into a clean Alpine image, so the resulting
# image contains no Rust toolchain, no source code and no C build chain.
#
# Build:    docker build -t certrelay:latest .
# Run:      docker run --rm -p 7778:7778 -v certrelay-data:/data \
#               --env-file <(grep ^export setup-spaced-prod-env.sh | sed 's/^export //') \
#               certrelay:latest

# NOTE on RUST_VERSION:
#   Cargo.toml declares `rust-version = "1.85"` as the workspace MSRV, but
#   the locked transitive deps (spaces_*, icu_*, borsh_utils, sip7, ...)
#   already require rustc >= 1.88. We pin to a comfortably newer stable
#   here so `cargo build --locked` succeeds without touching Cargo.lock.
#   Override at build time with: --build-arg RUST_VERSION=1.91 (etc).
ARG RUST_VERSION=1.90
ARG RUST_ALPINE_VERSION=3.21
ARG RUNTIME_ALPINE_VERSION=3.21

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine${RUST_ALPINE_VERSION} AS builder

# Build-time toolchain needed for:
#   build-base, musl-dev      -> C toolchain for rusqlite (bundled sqlite),
#                                yuki and other native deps
#   clang, llvm                -> some -sys crates prefer clang
#   cmake                     -> aws-lc / ring style native builds
#   perl                      -> ring's build.rs
#   pkgconf, linux-headers    -> assorted -sys crates
#   git                       -> resolving any git deps in Cargo.lock
#
# NONE of these end up in the final image.
RUN apk add --no-cache \
        build-base \
        musl-dev \
        clang \
        llvm \
        cmake \
        perl \
        pkgconf \
        linux-headers \
        git

# NOTE: do NOT set `RUSTFLAGS="-C target-feature=-crt-static"`. On the
# rust:*-alpine images the default Rust target is *-unknown-linux-musl
# with crt-static enabled, which produces a fully static binary that
# needs nothing from the runtime image. Disabling crt-static would force
# a dynamic dependency on libgcc_s.so.1 / libunwind, which aren't present
# in the clean `alpine:*` runtime stage and would fail with
# "Error loading shared library libgcc_s.so.1" at container start.
ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10

WORKDIR /src

# Copy the whole workspace. The .dockerignore keeps `target/`, `data/`,
# language-binding build artefacts and other noise out of the context.
COPY . .

# Build three binaries from the workspace:
#   * certrelay (the relay server itself)
#   * fabric    (the Fabric client CLI - used by HEALTHCHECK to verify the
#               relay can actually resolve a subname end-to-end, including
#               cert-chain decoding and verification)
#   * monitor   (bootstrap relay health monitor - polls BOOTSTRAP_RELAYS)
# BuildKit caches the cargo registry and target dir across rebuilds, but
# nothing from those caches is copied into the runtime image.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked \
        -p relay --bin certrelay \
        -p relay --bin monitor \
        -p fabric-resolver --bin fabric \
 && cp /src/target/release/certrelay /usr/local/bin/certrelay \
 && cp /src/target/release/monitor   /usr/local/bin/monitor \
 && cp /src/target/release/fabric    /usr/local/bin/fabric \
 && strip /usr/local/bin/certrelay /usr/local/bin/monitor /usr/local/bin/fabric

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM alpine:${RUNTIME_ALPINE_VERSION} AS runtime

# ca-certificates -> outbound HTTPS to checkpoint/peer relays
# tini            -> proper PID 1 / signal forwarding
# tzdata          -> stable timestamp formatting in logs
RUN apk add --no-cache \
        ca-certificates \
        tini \
        tzdata \
 && addgroup -S certrelay \
 && adduser  -S -G certrelay -h /data -s /sbin/nologin certrelay \
 && mkdir -p /data \
 && chown -R certrelay:certrelay /data

# Binaries + entrypoint + healthcheck
COPY --from=builder /usr/local/bin/certrelay /usr/local/bin/certrelay
COPY --from=builder /usr/local/bin/monitor   /usr/local/bin/monitor
COPY --from=builder /usr/local/bin/fabric    /usr/local/bin/fabric
COPY docker-entrypoint.sh   /usr/local/bin/docker-entrypoint.sh
COPY docker-healthcheck.sh  /usr/local/bin/docker-healthcheck.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
             /usr/local/bin/docker-healthcheck.sh \
             /usr/local/bin/certrelay \
             /usr/local/bin/monitor \
             /usr/local/bin/fabric

# Sensible container-friendly defaults. Every one of these can be overridden
# at `docker run` time via `-e VAR=value` or `--env-file`. The names match
# the env vars exported by ./setup-spaced-prod-env.sh and the `env = ...`
# attributes declared on the `Args` struct in relay/src/app.rs.
ENV CERTRELAY_CHAIN=mainnet \
    CERTRELAY_DATA_DIR=/data \
    CERTRELAY_BIND=0.0.0.0 \
    CERTRELAY_PORT=7778 \
    CERTRELAY_BOOTSTRAP=false \
    CERTRELAY_ANCHOR_REFRESH=300 \
    RUST_LOG=info \
    CHECK_INTERVAL=30 \
    REQUEST_TIMEOUT=15

VOLUME ["/data"]
EXPOSE 7778/tcp

# HEALTHCHECK contract:
#   * --start-period=120s   first 2 minutes after start are graced so the
#                           anchor-refresh / checkpoint work doesn't flap
#                           the status from "starting" to "unhealthy"
#   * --interval=30s        normal cadence between probes
#   * --timeout=15s         covers wget(/peers, 5s) + fabric resolve(~5s)
#   * --retries=3           three consecutive failures => unhealthy
#
# Liveness (always): GET /peers must return 200.
# Resolve  (opt-in): if CERTRELAY_HEALTHCHECK_HANDLE is set, the bundled
#                    `fabric` CLI must resolve that handle against this
#                    relay and return a zone JSON containing the handle.
HEALTHCHECK --interval=30s --timeout=15s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/docker-healthcheck.sh"]

USER certrelay
WORKDIR /data

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["certrelay"]
