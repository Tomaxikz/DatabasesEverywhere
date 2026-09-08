# Docker deployment

DBEV uses host networking and the host runtime socket. Socket access is
**host-root-equivalent**; use a trusted host/VM. See [node setup](../../docs/operations/setup.md).

## Start

Save the panel-generated config to `/etc/databases-everywhere/config.yml`.
Review [compose.yml](compose.yml), including:

- FuseQuota needs `/dev/fuse`, `SYS_ADMIN`, and `user_allow_other` in the host's
  `/etc/fuse.conf`. Remove FUSE-only mounts/permissions and the AppArmor
  override when using another storage mode.
- Host process/cgroup mounts support CPU burst reconciliation.
- Mount the configured certificate directories; storage ancestors need safe permissions.

From the repository root, replace `<version>` with a reviewed release or use
an immutable image digest:

```bash
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:<version>'
docker compose --project-directory . -f deploy/docker/compose.yml up -d
```

## Build the image

The [Dockerfile](Dockerfile) copies prebuilt binaries from
`.docker/<architecture>/dbev`; [release CI](../../.github/workflows/release.yml)
stages them automatically. After staging, run from the repository root:

```bash
docker build --no-cache -f deploy/docker/Dockerfile .
```

Keep `.dockerignore` aligned with those paths. Fresh builds apply Debian package
updates; rebuild and rescan to verify fixes. Existing published images do not change.
