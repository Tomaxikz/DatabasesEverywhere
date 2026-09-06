ALTER TABLE engine_runtimes ADD COLUMN owner_panel TEXT;
ALTER TABLE engine_runtimes ADD COLUMN owner_server TEXT;
ALTER TABLE engine_runtime_reservations ADD COLUMN owner_panel TEXT;
ALTER TABLE engine_runtime_reservations ADD COLUMN owner_server TEXT;

-- Unowned cross-server pools are not eligible for the new placement model.
-- Preserve data for operator export/removal; never guess or reassign an owner.
UPDATE engine_runtimes SET status = 'quarantined' WHERE deployment_mode = 'shared';
UPDATE instance_metadata SET status = 'quarantined',
    metadata_json = json_set(metadata_json, '$.status', 'quarantined')
WHERE deployment_mode = 'shared';

DROP INDEX uq_engine_runtimes_shared_compatibility;
CREATE UNIQUE INDEX uq_server_pool ON engine_runtimes(owner_panel, owner_server, protocol)
WHERE deployment_mode = 'shared';

CREATE TRIGGER owned_pool_insert BEFORE INSERT ON engine_runtimes
WHEN NEW.deployment_mode = 'shared'
 AND (NEW.owner_panel IS NULL OR NEW.owner_server IS NULL OR NEW.owner_panel = '' OR NEW.owner_server = '')
 AND NOT (NEW.status IN ('quarantined', 'deleting') AND EXISTS (
   SELECT 1 FROM engine_runtimes WHERE runtime_id = NEW.runtime_id
   AND owner_panel IS NULL AND owner_server IS NULL AND status IN ('quarantined', 'deleting')))
BEGIN SELECT RAISE(ABORT, 'shared pool requires a verified owner'); END;

CREATE TRIGGER pool_owner_immutable BEFORE UPDATE OF owner_panel, owner_server, protocol, deployment_mode ON engine_runtimes
WHEN (OLD.owner_panel IS NOT NEW.owner_panel OR OLD.owner_server IS NOT NEW.owner_server
 OR OLD.protocol <> NEW.protocol OR OLD.deployment_mode <> NEW.deployment_mode)
 AND NOT (OLD.deployment_mode = 'dedicated' AND NEW.deployment_mode = 'dedicated'
   AND OLD.protocol = NEW.protocol AND OLD.owner_panel IS NULL AND OLD.owner_server IS NULL
   AND NEW.owner_panel IS NOT NULL AND NEW.owner_server IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'runtime ownership and protocol are immutable'); END;

CREATE TRIGGER owned_reservation_insert BEFORE INSERT ON engine_runtime_reservations
WHEN NOT EXISTS (SELECT 1 FROM engine_runtimes
 WHERE runtime_id = NEW.runtime_id AND owner_panel = NEW.owner_panel AND owner_server = NEW.owner_server)
BEGIN SELECT RAISE(ABORT, 'reservation owner must match pool owner'); END;

CREATE TRIGGER owned_reservation_update BEFORE UPDATE OF runtime_id, owner_panel, owner_server ON engine_runtime_reservations
WHEN NOT EXISTS (SELECT 1 FROM engine_runtimes
 WHERE runtime_id = NEW.runtime_id AND owner_panel = NEW.owner_panel AND owner_server = NEW.owner_server)
BEGIN SELECT RAISE(ABORT, 'reservation owner must match pool owner'); END;

CREATE TRIGGER owned_tenant_insert BEFORE INSERT ON instance_metadata
WHEN NEW.deployment_mode = 'shared' AND NOT EXISTS (
 SELECT 1 FROM engine_runtimes WHERE runtime_id = NEW.runtime_id
 AND owner_panel = json_extract(NEW.metadata_json, '$.owner.panel_id')
 AND owner_server = json_extract(NEW.metadata_json, '$.owner.server_id'))
 AND NOT (NEW.status IN ('quarantined', 'deleting') AND EXISTS (
   SELECT 1 FROM instance_metadata WHERE instance_id = NEW.instance_id
   AND runtime_id = NEW.runtime_id AND status IN ('quarantined', 'deleting')
   AND json_extract(metadata_json, '$.owner') IS NULL))
BEGIN SELECT RAISE(ABORT, 'tenant owner must match pool owner'); END;

CREATE TRIGGER tenant_owner_immutable BEFORE UPDATE OF metadata_json ON instance_metadata
WHEN json_extract(OLD.metadata_json, '$.owner.panel_id') IS NOT NULL
 AND (json_extract(OLD.metadata_json, '$.owner.panel_id') IS NOT json_extract(NEW.metadata_json, '$.owner.panel_id')
   OR json_extract(OLD.metadata_json, '$.owner.server_id') IS NOT json_extract(NEW.metadata_json, '$.owner.server_id'))
BEGIN SELECT RAISE(ABORT, 'tenant ownership is immutable'); END;

CREATE TRIGGER owned_tenant_update BEFORE UPDATE OF runtime_id, deployment_mode, metadata_json, status ON instance_metadata
WHEN NEW.deployment_mode = 'shared' AND NEW.status NOT IN ('quarantined', 'deleting') AND NOT EXISTS (
 SELECT 1 FROM engine_runtimes WHERE runtime_id = NEW.runtime_id
 AND owner_panel = json_extract(NEW.metadata_json, '$.owner.panel_id')
 AND owner_server = json_extract(NEW.metadata_json, '$.owner.server_id'))
BEGIN SELECT RAISE(ABORT, 'tenant owner must match pool owner'); END;

ALTER TABLE deployment_migrations ADD COLUMN pool_limits_json TEXT;
ALTER TABLE deployment_migrations ADD COLUMN target_limits_json TEXT;

-- Releasing a tenant must not resize the physical server-owned engine.
DROP TRIGGER trg_instance_release_runtime_reservation;
CREATE TRIGGER trg_instance_release_runtime_reservation
AFTER DELETE ON instance_metadata WHEN OLD.deployment_mode = 'shared'
BEGIN
    DELETE FROM engine_runtime_reservations WHERE instance_id = OLD.instance_id;
    UPDATE engine_runtimes SET
        tenant_count = (SELECT COUNT(*) FROM engine_runtime_reservations WHERE runtime_id = OLD.runtime_id),
        reserved_cpu_cores = 0.0,
        reserved_memory_mib = 0,
        reserved_disk_mib = COALESCE((SELECT SUM(disk_mib) FROM engine_runtime_reservations WHERE runtime_id = OLD.runtime_id), 0)
    WHERE runtime_id = OLD.runtime_id;
END;

CREATE TRIGGER unowned_pool_state BEFORE UPDATE OF status ON engine_runtimes
WHEN NEW.deployment_mode = 'shared' AND NEW.status NOT IN ('quarantined', 'deleting')
 AND (NEW.owner_panel IS NULL OR NEW.owner_server IS NULL)
BEGIN SELECT RAISE(ABORT, 'unowned shared pool must remain quarantined'); END;
