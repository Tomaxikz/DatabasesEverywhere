# Security

Report security issues privately. Do not open a public GitHub issue for
vulnerabilities.

## Supported Versions

Security fixes are provided for the latest released version.

## Sensitive Data

Do not commit or share:

- Daemon API tokens.
- Panel tokens.
- Database passwords.
- TLS private keys.
- Full connection URLs containing passwords.
- Backup or export files containing customer data.

## Deployment Notes

- Keep backend database ports private. Public access should go through DBE
  gateway listeners.
- Keep `daemon.allow_public_backend_ports` disabled in production.
- Use TLS for the API when exposing it over a network.
- Use a firewall so only intended API and database gateway ports are reachable.
- Use `disk.mode: fuse_quota` or a strict native quota mode for production disk
  enforcement.
- Keep Docker or Podman restricted to the daemon host. Do not expose the
  container engine socket publicly.

## Vulnerability Reports

Include:

- Affected version or commit.
- Deployment type: Docker or Podman.
- Database protocol involved, if any.
- Reproduction steps.
- Logs with secrets removed.

We will prioritize issues involving authentication bypass, cross-instance data
access, path traversal, artifact download leaks, container escape risk, or quota
enforcement bypass.
