# DatabasesEverywhere

A Linux daemon for panel-managed PostgreSQL, MySQL, MariaDB, MongoDB,
ClickHouse, Redis, Valkey, and Qdrant. Supports dedicated containers and
server-owned shared pools.

## Clone the repository

```bash
git clone https://github.com/Tomaxikz/DatabasesEverywhere.git
cd DatabasesEverywhere
```

## Install

Requires Linux (glibc 2.35+), Docker or Podman, `curl`, and a supported
[storage backend](docs/operations/disk-limits.md).

### Download and install

Run as root to download and install the latest release for your architecture:

```bash
curl -fL "https://github.com/Tomaxikz/DatabasesEverywhere/releases/latest/download/dbev-$(uname -m | sed 's/^aarch64$/arm64/; s/^amd64$/x86_64/')-linux" -o /usr/local/bin/dbev &&
chmod +x /usr/local/bin/dbev
```

To pin a [release](https://github.com/Tomaxikz/DatabasesEverywhere/releases),
replace `releases/latest/download` with `releases/download/vX.Y.Z`.

### Configure and start

Save your panel-generated configuration to
`/etc/databases-everywhere/config.yml`; see the [example](config/example.yml).

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

Setup starts or restarts a root-run service. Protect management credentials
and use TLS across untrusted networks.

## Documentation

[Node setup](docs/operations/setup.md) · [Docker](deploy/docker/README.md) ·
[API and operator guides](docs/README.md) · [Build and test](docs/development.md) ·
[Security](SECURITY.md)
