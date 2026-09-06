ALTER TABLE engine_runtimes ADD COLUMN desired_state TEXT NOT NULL DEFAULT 'running'
    CHECK(desired_state IN ('running', 'stopped'));

ALTER TABLE deployment_migrations ADD COLUMN target_pool_id TEXT;
UPDATE deployment_migrations SET target_pool_id = target_runtime_id
    WHERE target_mode = 'shared';
ALTER TABLE deployment_migrations DROP COLUMN pool_limits_json;

ALTER TABLE engine_runtimes ADD COLUMN pending_image TEXT;

DROP INDEX IF EXISTS uq_engine_runtimes_shared_compatibility;
ALTER TABLE engine_runtimes DROP COLUMN compatibility_key;

-- Capacity is reserved by tenant count and disk only. Engine CPU/RAM is fixed.
DROP TRIGGER trg_instance_release_runtime_reservation;
CREATE TRIGGER trg_instance_release_runtime_reservation
AFTER DELETE ON instance_metadata WHEN OLD.deployment_mode = 'shared'
BEGIN
    DELETE FROM engine_runtime_reservations WHERE instance_id = OLD.instance_id;
    UPDATE engine_runtimes SET
        tenant_count = (SELECT COUNT(*) FROM engine_runtime_reservations WHERE runtime_id = OLD.runtime_id),
        reserved_disk_mib = COALESCE((SELECT SUM(disk_mib) FROM engine_runtime_reservations WHERE runtime_id = OLD.runtime_id), 0)
    WHERE runtime_id = OLD.runtime_id;
END;
ALTER TABLE engine_runtimes DROP COLUMN reserved_cpu_cores;
ALTER TABLE engine_runtimes DROP COLUMN reserved_memory_mib;
