FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

LABEL org.opencontainers.image.title="DatabasesEverywhere"
LABEL org.opencontainers.image.description="Container-backed database hosting daemon"
LABEL org.opencontainers.image.source="https://github.com/Tomaxikz/DatabasesEverywhere"

# The base image is digest-pinned; package versions intentionally follow its
# Ubuntu security repository instead of freezing vulnerable package revisions.
# hadolint ignore=DL3008
RUN apt-get update --error-on=any \
    && apt-get upgrade -y --with-new-pkgs --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        ca-certificates fuse3 btrfs-progs xfsprogs quota \
    && rm -rf /var/lib/apt/lists/* \
    && echo user_allow_other >> /etc/fuse.conf \
    && install -d -m 0700 /etc/databases-everywhere /var/lib/dbev /run/dbev

ARG TARGETPLATFORM

COPY --chown=0:0 --chmod=0555 .docker/${TARGETPLATFORM#linux/}/dbev /usr/local/bin/dbev

# Fail the build if the copied GNU binary or the FUSE, quota and cleanup tools
# cannot run. ZFS tools are left out: they must match the host's kernel module.
RUN dbev --version && fusermount3 --version && umount --version \
    && btrfs --version && xfs_quota -V && setquota -V

VOLUME ["/etc/databases-everywhere", "/var/lib/dbev", "/run/dbev"]

# Root is currently required only by the FuseQuota/SYS_ADMIN deployment. The
# Docker socket remains a root-equivalent capability; use a dedicated host/VM.
# hadolint ignore=DL3002
USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/dbev"]
CMD ["daemon"]
