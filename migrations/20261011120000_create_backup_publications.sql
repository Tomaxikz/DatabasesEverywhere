-- Publications whose outcome is not yet settled. A row is committed before a
-- backup is uploaded and deleted once the backup is known to be published
-- for an instance that still exists, or once every object of the backup id
-- has been removed. Recovery uses the recorded storage target and never
-- touches a different one.
CREATE TABLE backup_publications (
    backup_id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    storage_kind TEXT NOT NULL CHECK (storage_kind IN ('local', 's3', 'kopia')),
    -- Root path, endpoint/bucket/prefix or repository config of the target.
    storage_identity TEXT NOT NULL,
    -- Online backup job that produced the artifact, when there is one.
    job_id TEXT,
    -- publishing: upload started, outcome unknown.
    -- unpublish: every object of this backup id must be removed.
    state TEXT NOT NULL CHECK (state IN ('publishing', 'unpublish')),
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_backup_publications_instance ON backup_publications(instance_id, created_at);
