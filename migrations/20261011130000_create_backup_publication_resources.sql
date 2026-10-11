-- Remote resources of an unsettled publication that cannot be found again
-- from its backup id alone: the Kopia snapshot source path (checkpoint
-- snapshots carry no tags) and S3 multipart upload ids. A row is committed
-- before the resource can exist, or right after the provider assigns its id,
-- and is removed together with its publication once cleanup is confirmed.
CREATE TABLE backup_publication_resources (
    backup_id TEXT NOT NULL
        REFERENCES backup_publications(backup_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('kopia_source_path', 's3_multipart_upload')),
    -- Kopia source path, or the S3 object key.
    locator TEXT NOT NULL,
    -- S3 upload id; empty for Kopia.
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (backup_id, kind, locator, detail)
);
