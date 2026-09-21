FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

# The base image is digest-pinned; package versions intentionally follow its
# Ubuntu security repository instead of freezing vulnerable package revisions.
# hadolint ignore=DL3008
RUN apt-get update --error-on=any \
    && apt-get upgrade -y --with-new-pkgs --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates fuse3 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /etc/databases-everywhere /var/lib/dbev/logs /var/log/dbev /run/dbev

ARG TARGETPLATFORM

COPY --chown=0:0 --chmod=0555 .docker/${TARGETPLATFORM#linux/}/dbev /usr/local/bin/dbev

# Fail the build if the copied GNU binary or required FUSE/cleanup tools cannot run.
RUN dbev --version && fusermount3 --version && umount --version

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/var/log/dbev", "/run/dbev"]

# Root is currently required only by the FuseQuota/SYS_ADMIN deployment. The
# Docker socket remains a root-equivalent capability; use a dedicated host/VM.
# hadolint ignore=DL3002
USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]
