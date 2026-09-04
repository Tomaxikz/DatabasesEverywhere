# Docker deployment

DBEV uses host networking and the host runtime socket to manage database
containers. Runtime-socket access is **host-root-equivalent**; deploy only on a
trusted host/VM. See [node setup](../../docs/operations/setup.md).

## Start

Create the host config at `/etc/databases-everywhere/config.yml`, then review
the mounts and security comments in [compose.yml](compose.yml):

- Runtime storage is created at boot; custom parent directories must have
  safe ownership and permissions.
- FuseQuota needs `/dev/fuse`, `SYS_ADMIN`, and a host `/etc/fuse.conf`
  containing `user_allow_other`. Remove FUSE-specific mounts/permissions and
  the AppArmor override when your selected storage mode does not use FUSE.
- Host process/cgroup mounts support CPU burst reconciliation.
- Mount any certificate directories referenced by the config.

From the repository root, choose a published version or immutable digest:

```bash
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:<version>'
docker compose --project-directory . -f deploy/docker/compose.yml up -d
```

Replace the placeholder; Compose refuses an unset image. Keep
`--project-directory .` so the project name and `.env` resolve consistently.
Storage mounts use absolute host paths.

## Build the image

The [Dockerfile](Dockerfile) packages prebuilt binaries, not Rust source.
[Release CI](../../.github/workflows/release.yml) stages them under
`.docker/<architecture>/dbev` and publishes the multi-platform image.

After staging binaries, build with the repository root as context:

```bash
docker build -f deploy/docker/Dockerfile .
```

Keep `.dockerignore` aligned with the Dockerfile and staging paths.
