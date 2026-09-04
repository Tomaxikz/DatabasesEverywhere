-- Deployment migration is deliberately modeled separately from import/export.
-- A migration owns placement cutover and source retirement, while the existing
-- import/export jobs own only bounded logical data movement.
CREATE TABLE deployment_migrations (
    migration_id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN (
        'postgres', 'mariadb', 'mysql', 'mongodb', 'clickhouse'
    )),
    source_mode TEXT NOT NULL CHECK (source_mode IN ('dedicated', 'shared')),
    target_mode TEXT NOT NULL CHECK (target_mode IN ('dedicated', 'shared')),
    source_runtime_id TEXT NOT NULL,
    target_runtime_id TEXT,
    stage TEXT NOT NULL CHECK (stage IN (
        'requested', 'preflight', 'target_preparing', 'target_prepared',
        'source_fencing', 'source_fenced', 'exporting', 'exported',
        'importing', 'imported', 'validating', 'cutover_pending',
        'cutover_committed', 'verifying_cutover', 'cleaning_source',
        'rolling_back', 'cleanup_pending', 'manual_intervention',
        'completed', 'failed', 'cancelled'
    )),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    source_fenced INTEGER NOT NULL DEFAULT 0 CHECK (source_fenced IN (0, 1)),
    cutover_committed INTEGER NOT NULL DEFAULT 0 CHECK (cutover_committed IN (0, 1)),
    failure_code TEXT,
    failure_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (source_mode <> target_mode),
    CHECK (source_runtime_id <> ''),
    CHECK (target_runtime_id IS NULL OR target_runtime_id <> ''),
    CHECK ((failure_code IS NULL) = (failure_message IS NULL)),
    CHECK (cutover_committed = 0 OR (
        source_fenced = 1
        AND target_runtime_id IS NOT NULL
        AND stage IN (
            'cutover_committed', 'verifying_cutover', 'cleaning_source',
            'cleanup_pending', 'manual_intervention', 'completed'
        )
    ))
);

-- Exactly one workflow may own an instance's placement at a time. Recovery
-- stages intentionally remain active so an operator cannot start over on top
-- of an unresolved target or source.
CREATE UNIQUE INDEX uq_deployment_migrations_active_instance
    ON deployment_migrations(instance_id)
    WHERE stage NOT IN ('completed', 'failed', 'cancelled');

CREATE INDEX idx_deployment_migrations_instance_history
    ON deployment_migrations(instance_id, created_at DESC, migration_id);

CREATE INDEX idx_deployment_migrations_recovery
    ON deployment_migrations(stage, updated_at)
    WHERE stage NOT IN ('completed', 'failed', 'cancelled');
