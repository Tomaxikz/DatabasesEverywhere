# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock build.rs ./
COPY bins ./bins
COPY migrations ./migrations
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin dbev \
    && cp /app/target/release/dbev /usr/local/bin/dbev

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates fuse3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/dbev /usr/local/bin/dbev

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/var/log/dbev", "/run/dbev"]

ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]

