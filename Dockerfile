FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates fuse3 \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

COPY .docker/${TARGETPLATFORM#linux/}/dbev /usr/local/bin/dbev

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/var/log/dbev", "/run/dbev"]

ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]
