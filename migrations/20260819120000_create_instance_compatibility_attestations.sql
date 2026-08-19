CREATE TABLE instance_compatibility_attestations (
    instance_id TEXT PRIMARY KEY NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('postgres', 'redis', 'valkey', 'mariadb', 'mysql', 'mongodb', 'clickhouse', 'qdrant')),
    container_id TEXT NOT NULL CHECK (length(container_id) BETWEEN 12 AND 128),
    image_id TEXT NOT NULL CHECK (length(image_id) BETWEEN 12 AND 256),
    probe_revision INTEGER NOT NULL CHECK (probe_revision > 0),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 128),
    compatible INTEGER NOT NULL CHECK (compatible IN (0, 1)),
    diagnostic TEXT CHECK (diagnostic IS NULL OR length(diagnostic) BETWEEN 1 AND 512),
    probed_at TEXT NOT NULL,
    FOREIGN KEY (instance_id) REFERENCES instance_metadata(instance_id) ON DELETE CASCADE
);
