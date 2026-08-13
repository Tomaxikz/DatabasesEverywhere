CREATE TABLE instance_auth_hardening_attestations (
    instance_id TEXT PRIMARY KEY NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('postgres', 'mysql')),
    container_id TEXT NOT NULL CHECK (length(container_id) BETWEEN 12 AND 128),
    container_started_at TEXT NOT NULL CHECK (length(container_started_at) BETWEEN 1 AND 128),
    hardening_revision INTEGER NOT NULL CHECK (hardening_revision > 0),
    credential_binding TEXT NOT NULL CHECK (length(credential_binding) BETWEEN 16 AND 256),
    hardened_at TEXT NOT NULL,
    FOREIGN KEY (instance_id) REFERENCES instance_metadata(instance_id) ON DELETE CASCADE
);
