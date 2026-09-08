# DatabasesEverywhere

A Linux daemon for panel-managed PostgreSQL, MySQL, MariaDB, MongoDB,
ClickHouse, Redis, Valkey, and Qdrant. Supports dedicated containers and
server-owned shared pools.

## Install

Requires Linux (glibc 2.35+), Docker or Podman, `curl`, the GitHub CLI
(`gh`), and a supported [storage backend](docs/operations/disk-limits.md).

### Download and install

Download the latest release for your architecture and verify its build attestation:

```bash
(
  set -eu
  case "$(uname -m)" in
    x86_64|amd64) DBEV_ARCH=x86_64 ;;
    aarch64|arm64) DBEV_ARCH=arm64 ;;
    riscv64) DBEV_ARCH=riscv64 ;;
    *) echo "Unsupported architecture" >&2; exit 1 ;;
  esac
  DBEV_DOWNLOAD="$(mktemp)"
  trap 'rm -f -- "$DBEV_DOWNLOAD"' EXIT
  curl --fail --location \
    "https://github.com/Tomaxikz/DatabasesEverywhere/releases/latest/download/dbev-${DBEV_ARCH}-linux" \
    -o "$DBEV_DOWNLOAD"
  gh attestation verify "$DBEV_DOWNLOAD" --repo Tomaxikz/DatabasesEverywhere
  sudo install -m 0755 "$DBEV_DOWNLOAD" /usr/local/bin/dbev
)
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
