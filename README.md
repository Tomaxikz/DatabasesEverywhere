# DatabasesEverywhere

A Linux daemon for hosting databases behind a control panel.

Run each database in a **dedicated container** or place multiple tenants in a
**shared engine pool**. The panel chooses placement; DBEV handles provisioning,
credentials, gateway routing, limits, and recovery.

## Features

- PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey, and Qdrant.
- Dedicated deployments for all engines; shared pools for the five SQL/document engines.
- Authenticated protocol gateways over private container sockets.
- CPU, memory, and disk limits for dedicated instances; shared-pool limits and tenant disk enforcement.
- Imports, exports, scheduled backups, and dedicated/shared migrations.
- REST management and live WebSocket monitoring.

See [engine compatibility and placement](docs/api/instances.md) for supported
versions and limitations.

## Get started

Requires Linux with glibc 2.35+, Docker or Podman, and the
[storage prerequisites](docs/operations/disk-limits.md).
Release binaries support x86-64, ARM64, and RISC-V 64.

### Download and install

Pull the latest release for your architecture. This uses `curl` and the GitHub
CLI (`gh`) to verify the binary's build attestation before installing it:

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

For a pinned [release](https://github.com/Tomaxikz/DatabasesEverywhere/releases),
replace `releases/latest/download` with `releases/download/vX.Y.Z` in the URL.
Pin reviewed versions in automated deployments.

### Configure and start

Save the panel-generated configuration to
`/etc/databases-everywhere/config.yml`; see the [example config](config/example.yml).
Then install and start the systemd service:

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

Setup runs the manager as root and starts or restarts the service. Database
containers remain network-isolated. Protect management access and use TLS
across untrusted networks.

Follow [node setup](docs/operations/setup.md) for installation, configuration,
upgrades, and logs, or [Docker deployment](deploy/docker/README.md) for Compose.

## Documentation

- [Documentation index](docs/README.md)
- [API contract](docs/api/openapi.yml) and [panel authentication](docs/api/auth.md)
- [Development and checks](docs/development.md)
- [Private security reporting](SECURITY.md)
