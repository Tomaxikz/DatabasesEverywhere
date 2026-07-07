CREATE TABLE import_export_jobs (
    job_id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    artifact_path TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_import_export_jobs_instance
    ON import_export_jobs(instance_id, created_at);

CREATE INDEX idx_import_export_jobs_status
    ON import_export_jobs(status, updated_at);
