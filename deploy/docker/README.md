# Docker deployment

DBEV uses host networking and the host runtime socket. Socket access is
**host-root-equivalent**; use a trusted host/VM. See [node setup](../../docs/operations/setup.md).

## Start

Compose runs from a deployment folder that holds everything for the node:

```text
/opt/dbev/
├── compose.yml          copy of compose.yml
├── .env                 optional, copy of .env.example
└── config/
    └── config.yml       the panel-generated node config
```

Create it and add the panel-generated config. The config holds the API token,
so keep its folder `0700` and the file `0600`:

```bash
sudo install -d /opt/dbev
sudo install -m 0644 deploy/docker/compose.yml /opt/dbev/compose.yml
sudo install -m 0644 deploy/docker/.env.example /opt/dbev/.env
sudo install -d -m 0700 /opt/dbev/config
sudo install -m 0600 /path/to/panel-config.yml /opt/dbev/config/config.yml
```

Compose runs the newest release (`:latest`) and pulls it on every `up`. To stay
on one version, set `DBEV_IMAGE` in `/opt/dbev/.env`. Then start it from that
folder:

```bash
cd /opt/dbev
sudo docker compose up -d
sudo docker compose ps
```

`docker compose logs -f dbev` follows the daemon. Relative paths in
`compose.yml` resolve against its own folder, so
`docker compose -f /opt/dbev/compose.yml ...` works from anywhere too.
Compose refuses to start when `config/` is missing.

Before the first start, review [compose.yml](compose.yml):

- FuseQuota needs `/dev/fuse`, `SYS_ADMIN`, the AppArmor override, and
  `user_allow_other` in the host's `/etc/fuse.conf`. Remove those four when
  the node uses native quotas or `soft_scanner`.
- `/var/lib/dbev` and `/run/dbev` keep the same path inside and outside the
  container, because DBEV hands those host paths to Docker for the database
  containers. Change them only together with `paths` in the config.
- Host process/cgroup mounts support CPU burst reconciliation.
- Mount the configured certificate directories; storage ancestors need safe permissions.
- The healthcheck opens a TCP connection to the management API. Set
  `DBEV_HEALTHCHECK_HOST` and `DBEV_HEALTHCHECK_PORT` in `.env` when
  `api.host` or `api.port` differ from `127.0.0.1:8090`.
- Container logs rotate at 5 × 20 MB; the daemon keeps its own rotated log
  under `/var/lib/dbev/logs`.

To run straight from a repository checkout instead, put the config in
`deploy/docker/config/config.yml` and the environment in `deploy/docker/.env`
(both git-ignored), then run `docker compose -f deploy/docker/compose.yml up -d`.

### Updates and config changes

Run `sudo docker compose up -d` to pull the newest release and replace the
daemon container, or change `DBEV_IMAGE` in `.env` first to move to a pinned
version. After editing `config/config.yml`, run
`sudo docker compose restart dbev`. Managed database containers keep running
through both; the daemon drains its connections first, so a restart takes a
few seconds.

### Moving from `/etc/databases-everywhere`

Earlier versions of this file mounted the host's `/etc/databases-everywhere`.
Either copy that folder into the deployment folder:

```bash
sudo install -d -m 0700 /opt/dbev/config
sudo cp -a /etc/databases-everywhere/. /opt/dbev/config/
```

or keep it where it is with `DBEV_CONFIG_DIR=/etc/databases-everywhere` in `.env`.

## Build the image

The [Dockerfile](Dockerfile) copies prebuilt binaries from
`.docker/<architecture>/dbev`; [release CI](../../.github/workflows/release.yml)
stages them automatically. After staging, run from the repository root:

```bash
docker build --no-cache -f deploy/docker/Dockerfile .
```

The runtime uses a digest-pinned Ubuntu 24.04 LTS base, retaining glibc, CA
certificates, FUSE 3, and the mount-cleanup utilities. It does not change the
host OS or the images used by managed database containers. The Docker build
checks that `dbev`, `fusermount3`, and `umount` execute before image scanning.

Keep `.dockerignore` aligned with those paths. Fresh builds apply Ubuntu package
updates; rebuild and rescan to verify fixes. Existing published images do not change.
