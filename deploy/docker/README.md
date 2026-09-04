# Docker deployment

The daemon uses host networking and manages database containers through the
host container runtime. Read the security comments in [compose.yml](compose.yml)
and the [node setup guide](../../docs/operations/setup.md) before starting it.

Create the host configuration and required directories first. From the
repository root, select a published version or immutable digest:

```bash
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:<version-or-tag>'
docker compose --project-directory . -f deploy/docker/compose.yml up -d
```

Replace the placeholder with the image tag or digest you intend to deploy.
Keep `--project-directory .` when running from the repository root so Compose
continues to use that directory for the project name and `.env` file. Volume
paths remain absolute host paths, preserving the daemon's storage locations.

## Building the image

The [Dockerfile](Dockerfile) packages prebuilt release binaries; it does not
compile Rust. Its build context is the repository root, with binaries staged
under `.docker/<architecture>/dbev` by the release workflow:

```bash
docker build -f deploy/docker/Dockerfile .
```

[Release CI](../../.github/workflows/release.yml) stages those binaries and
builds/publishes the multi-platform image. Keep the root `.dockerignore`
allowlist in sync with the Dockerfile path and binary staging directory.
