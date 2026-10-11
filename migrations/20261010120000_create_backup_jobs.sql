-- Durable online backup coordinator journal. A job row and every owned
-- resource row are committed before the corresponding resource exists, so
-- startup recovery can clean up exactly what an interrupted job created and
-- nothing else. No secrets or raw engine output belong here.
CREATE TABLE backup_jobs (
    job_id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    backup_id TEXT NOT NULL,
    strategy TEXT NOT NULL CHECK (length(strategy) BETWEEN 1 AND 64),
    -- Container id plus process start time of the captured runtime.
    runtime_generation TEXT NOT NULL,
    -- JSON identity of the source (protocol, runtime id, image).
    source_identity TEXT NOT NULL,
    staging_path TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'admitted', 'capturing', 'captured', 'validated', 'published',
        'failed', 'cleanup_pending'
    )),
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_backup_jobs_state ON backup_jobs(state, updated_at);
CREATE INDEX idx_backup_jobs_instance ON backup_jobs(instance_id, created_at);

CREATE TABLE backup_job_resources (
    job_id TEXT NOT NULL REFERENCES backup_jobs(job_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN (
        'server_session', 'replication_slot', 'helper_process',
        'helper_container', 'snapshot'
    )),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    survives_restart INTEGER NOT NULL CHECK (survives_restart IN (0, 1)),
    released INTEGER NOT NULL DEFAULT 0 CHECK (released IN (0, 1)),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (job_id, kind, name)
);
