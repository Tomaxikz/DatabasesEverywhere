FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

# The base image is digest-pinned; package versions intentionally follow its
# Debian security repository instead of freezing vulnerable package revisions.
# hadolint ignore=DL3008
RUN apt-get update --error-on=any \
    && apt-get upgrade -y --with-new-pkgs --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates fuse3 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /etc/databases-everywhere /var/lib/dbev/logs /var/log/dbev /run/dbev

ARG TARGETPLATFORM

COPY --chown=0:0 --chmod=0555 .docker/${TARGETPLATFORM#linux/}/dbev /usr/local/bin/dbev

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/var/log/dbev", "/run/dbev"]

# Root is currently required only by the FuseQuota/SYS_ADMIN deployment. The
# Docker socket remains a root-equivalent capability; use a dedicated host/VM.
# hadolint ignore=DL3002
USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]
