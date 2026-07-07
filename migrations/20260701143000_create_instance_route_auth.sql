CREATE TABLE IF NOT EXISTS instance_route_auth (
    instance_id TEXT PRIMARY KEY NOT NULL,
    mariadb_native_password_sha1_stage2 TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
