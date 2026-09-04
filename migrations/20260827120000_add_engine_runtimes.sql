CREATE TABLE engine_runtimes (
    runtime_id TEXT PRIMARY KEY NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    protocol TEXT NOT NULL CHECK (protocol IN (
        'postgres', 'redis', 'valkey', 'mariadb', 'mysql', 'mongodb', 'clickhouse', 'qdrant'
    )),
    deployment_mode TEXT NOT NULL CHECK (deployment_mode IN ('dedicated', 'shared')),
    status TEXT NOT NULL CHECK (status IN (
        'creating', 'booting', 'running', 'stopped', 'failed', 'quarantined', 'deleting'
    )),
    backend_kind TEXT NOT NULL CHECK (backend_kind IN ('unix_socket', 'docker_tcp')),
    backend_socket_path TEXT,
    backend_host TEXT,
    backend_port INTEGER,
    runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('docker', 'podman')),
    container_name TEXT NOT NULL,
    network TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    limit_cpu_cores REAL NOT NULL CHECK (limit_cpu_cores > 0),
    limit_memory_mib INTEGER NOT NULL CHECK (limit_memory_mib > 0),
    limit_disk_mib INTEGER NOT NULL CHECK (limit_disk_mib > 0),
    image TEXT NOT NULL,
    database_version TEXT CHECK (
        database_version IS NULL
        OR (database_version = trim(database_version) AND database_version <> '')
    ),
    compatibility_container_id TEXT,
    compatibility_image_id TEXT,
    compatibility_probe_revision INTEGER,
    compatibility_key TEXT NOT NULL,
    max_tenants INTEGER NOT NULL CHECK (max_tenants > 0),
    tenant_count INTEGER NOT NULL DEFAULT 0 CHECK (tenant_count >= 0 AND tenant_count <= max_tenants),
    reserved_cpu_cores REAL NOT NULL DEFAULT 0 CHECK (
        reserved_cpu_cores >= 0 AND reserved_cpu_cores <= limit_cpu_cores
    ),
    reserved_memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (
        reserved_memory_mib >= 0 AND reserved_memory_mib <= limit_memory_mib
    ),
    reserved_disk_mib INTEGER NOT NULL DEFAULT 0 CHECK (
        reserved_disk_mib >= 0 AND reserved_disk_mib <= limit_disk_mib
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(runtime_id, deployment_mode, protocol),
    CHECK (
        deployment_mode = 'dedicated'
        OR protocol IN ('postgres', 'mariadb', 'mysql', 'mongodb', 'clickhouse')
    ),
    CHECK (deployment_mode <> 'dedicated' OR max_tenants = 1),
    CHECK (
        (
            compatibility_container_id IS NULL
            AND compatibility_image_id IS NULL
            AND compatibility_probe_revision IS NULL
        )
        OR
        (
            compatibility_container_id IS NOT NULL
            AND compatibility_container_id <> ''
            AND compatibility_image_id IS NOT NULL
            AND compatibility_image_id <> ''
            AND compatibility_probe_revision > 0
        )
    ),
    CHECK (
        deployment_mode <> 'shared'
        OR (database_version IS NULL) = (compatibility_container_id IS NULL)
    ),
    CHECK (
        (backend_kind = 'unix_socket' AND backend_socket_path IS NOT NULL
            AND backend_host IS NULL AND backend_port IS NULL)
        OR
        (backend_kind = 'docker_tcp' AND backend_socket_path IS NULL
            AND backend_host IS NOT NULL AND backend_port IS NOT NULL)
    )
);

CREATE UNIQUE INDEX uq_engine_runtimes_shared_compatibility
    ON engine_runtimes(protocol, compatibility_key, runtime_id)
    WHERE deployment_mode = 'shared';

CREATE TABLE engine_runtime_auth (
    runtime_id TEXT PRIMARY KEY NOT NULL,
    admin_secret TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (runtime_id) REFERENCES engine_runtimes(runtime_id) ON DELETE CASCADE
);

CREATE TABLE engine_runtime_reservations (
    instance_id TEXT PRIMARY KEY NOT NULL,
    runtime_id TEXT NOT NULL,
    database_name TEXT NOT NULL CHECK (
        database_name = trim(database_name) AND database_name <> ''
    ),
    database_username TEXT NOT NULL CHECK (
        database_username = trim(database_username) AND database_username <> ''
    ),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'provisioned')),
    cpu_cores REAL NOT NULL CHECK (cpu_cores > 0),
    memory_mib INTEGER NOT NULL CHECK (memory_mib > 0),
    disk_mib INTEGER NOT NULL CHECK (disk_mib > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (runtime_id) REFERENCES engine_runtimes(runtime_id) ON DELETE RESTRICT
);

CREATE INDEX idx_engine_runtime_reservations_runtime
    ON engine_runtime_reservations(runtime_id, instance_id);

CREATE UNIQUE INDEX uq_engine_runtime_reservations_database
    ON engine_runtime_reservations(runtime_id, database_name);

CREATE UNIQUE INDEX uq_engine_runtime_reservations_username
    ON engine_runtime_reservations(runtime_id, database_username);

CREATE TRIGGER trg_runtime_reservation_shared_insert
BEFORE INSERT ON engine_runtime_reservations
WHEN NOT EXISTS (
    SELECT 1 FROM engine_runtimes
    WHERE runtime_id = NEW.runtime_id AND deployment_mode = 'shared'
)
BEGIN
    SELECT RAISE(ABORT, 'runtime reservations require a shared runtime');
END;

CREATE TRIGGER trg_runtime_reservation_shared_update
BEFORE UPDATE OF runtime_id ON engine_runtime_reservations
WHEN NOT EXISTS (
    SELECT 1 FROM engine_runtimes
    WHERE runtime_id = NEW.runtime_id AND deployment_mode = 'shared'
)
BEGIN
    SELECT RAISE(ABORT, 'runtime reservations require a shared runtime');
END;

-- Every historical instance already owns exactly one container. Model that
-- container as a dedicated runtime without changing any existing runtime,
-- backend, route, credential, status, or limit column.
INSERT INTO engine_runtimes (
    runtime_id, schema_version, protocol, deployment_mode, status,
    backend_kind, backend_socket_path, backend_host, backend_port,
    runtime_kind, container_name, network, limits_json,
    limit_cpu_cores, limit_memory_mib, limit_disk_mib,
    image, database_version, compatibility_key, max_tenants,
    created_at, updated_at
)
SELECT
    instance_id, 1, protocol, 'dedicated', status,
    backend_kind, backend_socket_path, backend_host, backend_port,
    runtime_kind, container_name, network, limits_json,
    COALESCE(json_extract(limits_json, '$.cpu_cores'), 1.0),
    COALESCE(json_extract(limits_json, '$.memory_mib'), 1024),
    COALESCE(json_extract(limits_json, '$.disk_mib'), 10240),
    COALESCE(json_extract(metadata_json, '$.image.configured'), ''),
    json_extract(metadata_json, '$.database_version.current'),
    'dedicated:' || protocol || ':' || instance_id,
    1,
    created_at, updated_at
FROM instance_metadata;

ALTER TABLE instance_metadata
    ADD COLUMN deployment_mode TEXT NOT NULL DEFAULT 'dedicated'
    CHECK (
        deployment_mode = 'dedicated'
        OR (
            deployment_mode = 'shared'
            AND protocol IN ('postgres', 'mariadb', 'mysql', 'mongodb', 'clickhouse')
        )
    );

ALTER TABLE instance_metadata
    ADD COLUMN runtime_id TEXT REFERENCES engine_runtimes(runtime_id) ON DELETE RESTRICT;

UPDATE instance_metadata
SET runtime_id = instance_id,
    metadata_json = json_set(
        metadata_json,
        '$.deployment_mode', 'dedicated',
        '$.runtime_id', instance_id
    );

CREATE UNIQUE INDEX uq_instance_metadata_dedicated_runtime
    ON instance_metadata(runtime_id)
    WHERE deployment_mode = 'dedicated';

CREATE UNIQUE INDEX uq_instance_metadata_shared_database
    ON instance_metadata(runtime_id, database_name)
    WHERE deployment_mode = 'shared';

CREATE UNIQUE INDEX uq_instance_metadata_shared_username
    ON instance_metadata(runtime_id, database_username)
    WHERE deployment_mode = 'shared';

-- A provisioned reservation is the immutable placement identity for an
-- attached shared tenant. Resource values may be resized transactionally, but
-- moving the reservation to another pool or changing its database/login would
-- detach the metadata row from the engine object it describes.
CREATE TRIGGER trg_runtime_reservation_identity_update
BEFORE UPDATE OF instance_id, runtime_id, database_name, database_username
ON engine_runtime_reservations
WHEN EXISTS (
    SELECT 1 FROM instance_metadata AS instance
    WHERE instance.instance_id = OLD.instance_id
      AND instance.deployment_mode = 'shared'
)
BEGIN
    SELECT CASE
        WHEN NEW.instance_id <> OLD.instance_id
          OR NEW.runtime_id <> OLD.runtime_id
          OR NEW.database_name <> OLD.database_name
          OR NEW.database_username <> OLD.database_username
        THEN RAISE(ABORT, 'attached shared reservation identity is immutable')
    END;
END;

-- The canonical instance delete trigger below releases the reservation after
-- the metadata row is gone. Refuse every other deletion order so a raw storage
-- call cannot leave a routable tenant without reserved pool capacity.
CREATE TRIGGER trg_runtime_reservation_attached_delete
BEFORE DELETE ON engine_runtime_reservations
WHEN EXISTS (
    SELECT 1 FROM instance_metadata AS instance
    WHERE instance.instance_id = OLD.instance_id
      AND instance.deployment_mode = 'shared'
)
BEGIN
    SELECT RAISE(ABORT, 'attached shared reservation cannot be deleted directly');
END;

CREATE TRIGGER trg_instance_runtime_insert
BEFORE INSERT ON instance_metadata
BEGIN
    SELECT CASE
        WHEN NEW.runtime_id IS NULL OR NEW.runtime_id = ''
        THEN RAISE(ABORT, 'instance runtime_id is required')
    END;
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM engine_runtimes AS runtime
            WHERE runtime.runtime_id = NEW.runtime_id
              AND runtime.protocol = NEW.protocol
              AND runtime.deployment_mode = NEW.deployment_mode
        )
        THEN RAISE(ABORT, 'instance placement does not match its engine runtime')
    END;
    SELECT CASE
        WHEN NEW.deployment_mode = 'dedicated' AND NEW.runtime_id <> NEW.instance_id
        THEN RAISE(ABORT, 'dedicated instance must own its runtime')
    END;
    SELECT CASE
        WHEN NEW.deployment_mode = 'shared' AND NOT EXISTS (
            SELECT 1 FROM engine_runtime_reservations AS reservation
            WHERE reservation.instance_id = NEW.instance_id
              AND reservation.runtime_id = NEW.runtime_id
              AND reservation.database_name = NEW.database_name
              AND reservation.database_username = NEW.database_username
              AND reservation.state = 'provisioned'
              AND reservation.cpu_cores = json_extract(NEW.limits_json, '$.cpu_cores')
              AND reservation.memory_mib = json_extract(NEW.limits_json, '$.memory_mib')
              AND reservation.disk_mib = json_extract(NEW.limits_json, '$.disk_mib')
        )
        THEN RAISE(ABORT, 'shared instance requires an exact runtime reservation')
    END;
END;

CREATE TRIGGER trg_instance_runtime_update
BEFORE UPDATE OF instance_id, runtime_id, deployment_mode, protocol, database_name, database_username, limits_json
ON instance_metadata
BEGIN
    SELECT CASE
        WHEN NEW.runtime_id IS NULL OR NEW.runtime_id = ''
        THEN RAISE(ABORT, 'instance runtime_id is required')
    END;
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM engine_runtimes AS runtime
            WHERE runtime.runtime_id = NEW.runtime_id
              AND runtime.protocol = NEW.protocol
              AND runtime.deployment_mode = NEW.deployment_mode
        )
        THEN RAISE(ABORT, 'instance placement does not match its engine runtime')
    END;
    SELECT CASE
        WHEN NEW.deployment_mode = 'dedicated' AND NEW.runtime_id <> NEW.instance_id
        THEN RAISE(ABORT, 'dedicated instance must own its runtime')
    END;
    SELECT CASE
        WHEN NEW.deployment_mode = 'shared' AND NOT EXISTS (
            SELECT 1 FROM engine_runtime_reservations AS reservation
            WHERE reservation.instance_id = NEW.instance_id
              AND reservation.runtime_id = NEW.runtime_id
              AND reservation.database_name = NEW.database_name
              AND reservation.database_username = NEW.database_username
              AND reservation.state = 'provisioned'
              AND reservation.cpu_cores = json_extract(NEW.limits_json, '$.cpu_cores')
              AND reservation.memory_mib = json_extract(NEW.limits_json, '$.memory_mib')
              AND reservation.disk_mib = json_extract(NEW.limits_json, '$.disk_mib')
        )
        THEN RAISE(ABORT, 'shared instance requires an exact runtime reservation')
    END;
END;

CREATE TRIGGER trg_engine_runtime_identity_update
BEFORE UPDATE OF protocol, deployment_mode ON engine_runtimes
WHEN EXISTS (
        SELECT 1 FROM instance_metadata AS instance
        WHERE instance.runtime_id = OLD.runtime_id
          AND (
              instance.protocol <> NEW.protocol
              OR instance.deployment_mode <> NEW.deployment_mode
          )
    )
    OR EXISTS (
        SELECT 1 FROM engine_runtime_reservations AS reservation
        WHERE reservation.runtime_id = OLD.runtime_id
          AND (
              NEW.protocol <> OLD.protocol
              OR NEW.deployment_mode <> 'shared'
          )
    )
BEGIN
    SELECT RAISE(ABORT, 'engine runtime identity is in use');
END;

-- Deleting a shared tenant through the canonical instance repository cannot
-- leak a reservation or leave aggregate capacity inflated.
-- Disk capacity also retains ceil(5%) pooled headroom (capped at 8192 MiB)
-- for WAL, redo/undo, and other tenant-induced engine-global files.
CREATE TRIGGER trg_instance_release_runtime_reservation
AFTER DELETE ON instance_metadata
WHEN OLD.deployment_mode = 'shared'
BEGIN
    UPDATE engine_runtimes
        SET tenant_count = (
            SELECT COUNT(*) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ),
        reserved_cpu_cores = COALESCE((
            SELECT SUM(cpu_cores) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0.0),
        reserved_memory_mib = COALESCE((
            SELECT SUM(memory_mib) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0),
        reserved_disk_mib = COALESCE((
            SELECT SUM(disk_mib) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0),
        limit_cpu_cores = CASE protocol
            WHEN 'clickhouse' THEN 0.5 ELSE 0.25
        END + COALESCE((
            SELECT SUM(cpu_cores) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0.0),
        limit_memory_mib = CASE protocol
            WHEN 'postgres' THEN 256
            WHEN 'mysql' THEN 384
            WHEN 'mariadb' THEN 384
            WHEN 'mongodb' THEN 512
            WHEN 'clickhouse' THEN 768
        END + COALESCE((
            SELECT SUM(memory_mib) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0),
        limit_disk_mib = CASE protocol
            WHEN 'postgres' THEN 2048
            WHEN 'clickhouse' THEN 1024
            ELSE 512
        END + COALESCE((
            SELECT SUM(disk_mib) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0) + MIN((COALESCE((
            SELECT SUM(disk_mib) FROM engine_runtime_reservations
            WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
        ), 0) + 19) / 20, 8192),
        limits_json = json_set(
            limits_json,
            '$.cpu_cores', CASE protocol
                WHEN 'clickhouse' THEN 0.5 ELSE 0.25
            END + COALESCE((
                SELECT SUM(cpu_cores) FROM engine_runtime_reservations
                WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
            ), 0.0),
            '$.memory_mib', CASE protocol
                WHEN 'postgres' THEN 256
                WHEN 'mysql' THEN 384
                WHEN 'mariadb' THEN 384
                WHEN 'mongodb' THEN 512
                WHEN 'clickhouse' THEN 768
            END + COALESCE((
                SELECT SUM(memory_mib) FROM engine_runtime_reservations
                WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
            ), 0),
            '$.disk_mib', CASE protocol
                WHEN 'postgres' THEN 2048
                WHEN 'clickhouse' THEN 1024
                ELSE 512
            END + COALESCE((
                SELECT SUM(disk_mib) FROM engine_runtime_reservations
                WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
            ), 0) + MIN((COALESCE((
                SELECT SUM(disk_mib) FROM engine_runtime_reservations
                WHERE runtime_id = OLD.runtime_id AND instance_id <> OLD.instance_id
            ), 0) + 19) / 20, 8192)
        )
    WHERE runtime_id = OLD.runtime_id
      AND EXISTS (
          SELECT 1 FROM engine_runtime_reservations
          WHERE instance_id = OLD.instance_id AND runtime_id = OLD.runtime_id
      );

    DELETE FROM engine_runtime_reservations WHERE instance_id = OLD.instance_id;
END;

CREATE TRIGGER trg_instance_delete_dedicated_runtime
AFTER DELETE ON instance_metadata
WHEN OLD.deployment_mode = 'dedicated'
BEGIN
    DELETE FROM engine_runtimes WHERE runtime_id = OLD.runtime_id;
END;
