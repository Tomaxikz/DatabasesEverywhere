CREATE TABLE tenant_activity_buckets (
    instance_id TEXT NOT NULL,
    instance_generation TEXT NOT NULL CHECK (
        instance_generation = trim(instance_generation) AND instance_generation <> ''
    ),
    bucket_start_unix INTEGER NOT NULL CHECK (bucket_start_unix >= 0),
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds >= 60),
    stats_epoch TEXT NOT NULL CHECK (
        stats_epoch = trim(stats_epoch) AND stats_epoch <> ''
    ),
    gap INTEGER NOT NULL CHECK (gap IN (0, 1)),
    operations_observed INTEGER NOT NULL CHECK (operations_observed IN (0, 1)),
    accepted_read INTEGER NOT NULL CHECK (accepted_read >= 0),
    accepted_write INTEGER NOT NULL CHECK (accepted_write >= 0),
    accepted_ddl INTEGER NOT NULL CHECK (accepted_ddl >= 0),
    accepted_other INTEGER NOT NULL CHECK (accepted_other >= 0),
    rejected_read INTEGER NOT NULL CHECK (rejected_read >= 0),
    rejected_write INTEGER NOT NULL CHECK (rejected_write >= 0),
    rejected_ddl INTEGER NOT NULL CHECK (rejected_ddl >= 0),
    rejected_other INTEGER NOT NULL CHECK (rejected_other >= 0),
    active_connections INTEGER NOT NULL CHECK (active_connections >= 0),
    opened_connections INTEGER NOT NULL CHECK (opened_connections >= 0),
    rx_bytes INTEGER NOT NULL CHECK (rx_bytes >= 0),
    tx_bytes INTEGER NOT NULL CHECK (tx_bytes >= 0),
    cpu_time_micros INTEGER CHECK (cpu_time_micros >= 0),
    peak_query_memory_bytes INTEGER CHECK (peak_query_memory_bytes >= 0),
    PRIMARY KEY (instance_id, instance_generation, bucket_start_unix),
    FOREIGN KEY (instance_id) REFERENCES instance_metadata(instance_id) ON DELETE CASCADE
);

-- Keep at most 24 hours and 1,440 sampler intervals, even if a caller bypasses
-- ActivityRepository and writes to SQLite directly. Delayed intervals may be
-- wider than the target 60-second cadence.
CREATE TRIGGER trg_tenant_activity_retention
AFTER INSERT ON tenant_activity_buckets
BEGIN
    DELETE FROM tenant_activity_buckets
    WHERE instance_id = NEW.instance_id
      AND instance_generation = NEW.instance_generation
      AND (
          bucket_start_unix < (
              SELECT MAX(bucket_start_unix) - 86400
              FROM tenant_activity_buckets
              WHERE instance_id = NEW.instance_id
                AND instance_generation = NEW.instance_generation
          )
          OR bucket_start_unix NOT IN (
              SELECT bucket_start_unix
              FROM tenant_activity_buckets
              WHERE instance_id = NEW.instance_id
                AND instance_generation = NEW.instance_generation
              ORDER BY bucket_start_unix DESC
              LIMIT 1440
          )
      );
END;
