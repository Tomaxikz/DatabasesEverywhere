CREATE TABLE import_uploads (
    upload_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(upload_id) BETWEEN 1 AND 128),
    instance_id TEXT NOT NULL
        CHECK (length(instance_id) BETWEEN 1 AND 128),
    original_filename TEXT NOT NULL
        CHECK (
            length(original_filename) BETWEEN 1 AND 255
            AND instr(original_filename, char(0)) = 0
            AND instr(original_filename, '/') = 0
            AND instr(original_filename, '\') = 0
            AND original_filename NOT IN ('.', '..')
        ),
    stored_filename TEXT NOT NULL
        CHECK (
            length(stored_filename) BETWEEN 1 AND 255
            AND instr(stored_filename, char(0)) = 0
            AND instr(stored_filename, '/') = 0
            AND instr(stored_filename, '\') = 0
            AND stored_filename NOT IN ('.', '..')
        ),
    protocol TEXT NOT NULL
        CHECK (protocol IN (
            'postgres',
            'redis',
            'valkey',
            'mariadb',
            'mysql',
            'mongodb',
            'clickhouse',
            'qdrant'
        )),
    archive_format TEXT
        CHECK (archive_format IS NULL OR archive_format IN (
            'plain',
            'gzip',
            'bzip2',
            'tar',
            'tar.gz',
            'zip'
        )),
    state TEXT NOT NULL
        CHECK (state IN (
            'uploading',
            'uploaded',
            'processing',
            'ready',
            'failed',
            'importing',
            'consumed',
            'deleting'
        )),
    size_bytes INTEGER NOT NULL
        CHECK (size_bytes > 0),
    sha256 TEXT
        CHECK (
            sha256 IS NULL
            OR (
                length(sha256) = 64
                AND sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
    catalog_json TEXT
        CHECK (
            catalog_json IS NULL
            OR (length(CAST(catalog_json AS BLOB)) <= 1048576 AND json_valid(catalog_json))
        ),
    last_error TEXT
        CHECK (
            last_error IS NULL
            OR (
                length(CAST(last_error AS BLOB)) BETWEEN 1 AND 16384
                AND instr(last_error, char(0)) = 0
            )
        ),
    claimed_job_id TEXT
        CHECK (claimed_job_id IS NULL OR length(claimed_job_id) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64),
    expires_at TEXT NOT NULL CHECK (length(expires_at) BETWEEN 1 AND 64),
    CHECK (
        state NOT IN ('uploaded', 'processing', 'ready', 'importing', 'consumed')
        OR sha256 IS NOT NULL
    ),
    CHECK (
        (state IN ('importing', 'consumed') AND claimed_job_id IS NOT NULL)
        OR (state NOT IN ('importing', 'consumed') AND claimed_job_id IS NULL)
    ),
    FOREIGN KEY (instance_id) REFERENCES instance_metadata(instance_id) ON DELETE CASCADE
);

CREATE INDEX idx_import_uploads_instance_active
    ON import_uploads(instance_id, state, created_at DESC);

CREATE INDEX idx_import_uploads_expiry
    ON import_uploads(expires_at)
    WHERE state NOT IN ('importing', 'consumed');

CREATE UNIQUE INDEX uq_import_uploads_claimed_job
    ON import_uploads(claimed_job_id)
    WHERE claimed_job_id IS NOT NULL;

CREATE UNIQUE INDEX uq_import_uploads_stored_filename
    ON import_uploads(instance_id, stored_filename);
