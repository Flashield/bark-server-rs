# Multi-stage build mirroring upstream bark-server's deploy/Dockerfile
# ergonomics: a builder image producing the single binary, a minimal runtime
# with ca-certificates + tzdata, the TIMEZONE build-arg pattern, a /data
# volume, port 8080 — plus a non-root runtime user.

# ---------------------------------------------------------------------------
# Builder: current Rust toolchain on slim Debian. gcc/libc6-dev are needed
# for the bundled SQLite C sources (rusqlite "bundled") and glibc linking.
# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder

# Injected into the binary via option_env! (see src/lib.rs); mirror
# upstream's ldflags version/commit/build-date stamping. Overridable:
#   docker build --build-arg BARK_SERVER_COMMIT=$(git rev-parse HEAD) ...
ARG BARK_SERVER_VERSION=0.1.0
ARG BARK_SERVER_COMMIT=unknown
ARG BARK_SERVER_BUILD_DATE=unknown
ENV BARK_SERVER_VERSION=${BARK_SERVER_VERSION} \
    BARK_SERVER_COMMIT=${BARK_SERVER_COMMIT} \
    BARK_SERVER_BUILD_DATE=${BARK_SERVER_BUILD_DATE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin bark-server

# ---------------------------------------------------------------------------
# Runtime: slim Debian with CA roots (outbound HTTPS to APNs) and tzdata,
# like upstream's alpine runtime stage. The binary links glibc dynamically;
# SQLite is compiled in.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="bark-server-rs" \
      org.opencontainers.image.description="Push relay for the Bark iOS App plus SSE realtime mirroring (Rust rewrite of Finb/bark-server)" \
      org.opencontainers.image.source="https://github.com/Flashield/bark-server-rs" \
      org.opencontainers.image.licenses="MIT"

# Default timezone; override with `--build-arg TIMEZONE=...` or `-e TZ=...`.
ARG TIMEZONE=Asia/Shanghai
ENV TZ=${TIMEZONE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin bark \
    && mkdir -p /data \
    && chown bark:bark /data

COPY --from=builder /build/target/release/bark-server /usr/local/bin/bark-server

# SQLite store lives here (single file bark.db, like upstream's bbolt file).
VOLUME /data

EXPOSE 8080

USER bark

ENTRYPOINT ["/usr/local/bin/bark-server"]
