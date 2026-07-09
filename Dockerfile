FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates fuse3 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /etc/databases-everywhere /var/lib/dbev /var/log/dbev /run/dbev

ARG TARGETPLATFORM

COPY --chown=0:0 --chmod=0555 .docker/${TARGETPLATFORM#linux/}/dbev /usr/local/bin/dbev

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/var/log/dbev", "/run/dbev"]

# Root is currently required only by the FuseQuota/SYS_ADMIN deployment. The
# Docker socket remains a root-equivalent capability; use a dedicated host/VM.
USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]
