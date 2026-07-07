CREATE TABLE instance_metadata (
    instance_id TEXT PRIMARY KEY NOT NULL,
    schema_version INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    status TEXT NOT NULL,
    public_host TEXT NOT NULL,
    public_port INTEGER NOT NULL,
    backend_kind TEXT NOT NULL,
    backend_socket_path TEXT,
    backend_host TEXT,
    backend_port INTEGER,
    runtime_kind TEXT NOT NULL,
    container_name TEXT NOT NULL,
    network TEXT NOT NULL,
    database_name TEXT NOT NULL,
    database_username TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_instance_metadata_postgres_route
    ON instance_metadata(protocol, database_username, database_name);

CREATE INDEX idx_instance_metadata_redis_route
    ON instance_metadata(protocol, database_username);
