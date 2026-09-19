-- Quarantine history intentionally survives entity deletion. No secret values or
-- raw engine stderr belong here. Generations prevent ID reuse inheriting incidents.
CREATE TABLE quarantine_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('pool', 'instance')),
    entity_id TEXT NOT NULL,
    generation TEXT NOT NULL,
    code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 64),
    recovery_class TEXT NOT NULL CHECK (recovery_class IN ('validated_retry', 'repair_required', 'manual_review')),
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 96),
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    occurrences INTEGER NOT NULL DEFAULT 1,
    closed_at TEXT,
    final_status TEXT
);
CREATE UNIQUE INDEX quarantine_active_cause
    ON quarantine_events(entity_kind, entity_id, generation, code) WHERE closed_at IS NULL;
CREATE INDEX quarantine_history_lookup ON quarantine_events(entity_kind, entity_id, event_id);

CREATE TRIGGER engine_runtimes_quarantine_insert AFTER INSERT ON engine_runtimes
WHEN NEW.deployment_mode = 'shared' AND NEW.status = 'quarantined'
BEGIN
    INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'pool', NEW.runtime_id, NEW.created_at, CASE WHEN NEW.owner_panel IS NULL OR NEW.owner_server IS NULL THEN 'ownership_mismatch' ELSE 'unknown' END, 'manual_review', 'status_transition'
    WHERE ((NEW.owner_panel IS NULL OR NEW.owner_server IS NULL) OR NOT EXISTS(
        SELECT 1 FROM quarantine_events WHERE entity_kind='pool' AND entity_id=NEW.runtime_id
            AND generation=NEW.created_at AND closed_at IS NULL))
      AND NOT EXISTS(SELECT 1 FROM quarantine_events
          WHERE entity_kind='pool' AND entity_id=NEW.runtime_id AND generation=NEW.created_at
            AND code=(CASE WHEN NEW.owner_panel IS NULL OR NEW.owner_server IS NULL THEN 'ownership_mismatch' ELSE 'unknown' END) AND closed_at IS NULL);
END;

CREATE TRIGGER engine_runtimes_quarantine_update AFTER UPDATE ON engine_runtimes
WHEN NEW.deployment_mode = 'shared' AND NEW.status = 'quarantined'
BEGIN
    INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'pool', NEW.runtime_id, NEW.created_at, CASE WHEN NEW.owner_panel IS NULL OR NEW.owner_server IS NULL THEN 'ownership_mismatch' ELSE 'unknown' END, 'manual_review', 'status_transition'
    WHERE ((NEW.owner_panel IS NULL OR NEW.owner_server IS NULL) OR NOT EXISTS(
        SELECT 1 FROM quarantine_events WHERE entity_kind='pool' AND entity_id=NEW.runtime_id
            AND generation=NEW.created_at AND closed_at IS NULL))
      AND NOT EXISTS(SELECT 1 FROM quarantine_events
          WHERE entity_kind='pool' AND entity_id=NEW.runtime_id AND generation=NEW.created_at
            AND code=(CASE WHEN NEW.owner_panel IS NULL OR NEW.owner_server IS NULL THEN 'ownership_mismatch' ELSE 'unknown' END) AND closed_at IS NULL);
END;

CREATE TRIGGER engine_runtimes_quarantine_close AFTER UPDATE ON engine_runtimes
WHEN (OLD.status = 'quarantined' AND NEW.status <> 'quarantined') OR NEW.created_at <> OLD.created_at
BEGIN
    UPDATE quarantine_events SET closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
        final_status=CASE WHEN NEW.created_at <> OLD.created_at THEN 'replaced' ELSE NEW.status END
    WHERE entity_kind='pool' AND entity_id=OLD.runtime_id AND generation=OLD.created_at AND closed_at IS NULL;
END;
CREATE TRIGGER engine_runtimes_quarantine_delete AFTER DELETE ON engine_runtimes
BEGIN
    UPDATE quarantine_events SET closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), final_status='deleted'
    WHERE entity_kind='pool' AND entity_id=OLD.runtime_id AND generation=OLD.created_at AND closed_at IS NULL;
END;
INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'pool', runtime_id, created_at, 'legacy_unknown', 'manual_review', 'migration_backfill'
    FROM engine_runtimes WHERE status='quarantined' AND deployment_mode='shared';

CREATE TRIGGER instance_metadata_quarantine_insert AFTER INSERT ON instance_metadata
WHEN NEW.status = 'quarantined'
BEGIN
    INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'instance', NEW.instance_id, NEW.created_at, CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'credential_integrity' ELSE 'unknown' END, CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'repair_required' ELSE 'manual_review' END, 'status_transition'
    WHERE ((NEW.protected_secret_recovery_required = 1) OR NOT EXISTS(
        SELECT 1 FROM quarantine_events WHERE entity_kind='instance' AND entity_id=NEW.instance_id
            AND generation=NEW.created_at AND closed_at IS NULL))
      AND NOT EXISTS(SELECT 1 FROM quarantine_events
          WHERE entity_kind='instance' AND entity_id=NEW.instance_id AND generation=NEW.created_at
            AND code=(CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'credential_integrity' ELSE 'unknown' END) AND closed_at IS NULL);
END;

CREATE TRIGGER instance_metadata_quarantine_update AFTER UPDATE ON instance_metadata
WHEN NEW.status = 'quarantined'
BEGIN
    INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'instance', NEW.instance_id, NEW.created_at, CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'credential_integrity' ELSE 'unknown' END, CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'repair_required' ELSE 'manual_review' END, 'status_transition'
    WHERE ((NEW.protected_secret_recovery_required = 1) OR NOT EXISTS(
        SELECT 1 FROM quarantine_events WHERE entity_kind='instance' AND entity_id=NEW.instance_id
            AND generation=NEW.created_at AND closed_at IS NULL))
      AND NOT EXISTS(SELECT 1 FROM quarantine_events
          WHERE entity_kind='instance' AND entity_id=NEW.instance_id AND generation=NEW.created_at
            AND code=(CASE WHEN NEW.protected_secret_recovery_required = 1 THEN 'credential_integrity' ELSE 'unknown' END) AND closed_at IS NULL);
END;

CREATE TRIGGER instance_metadata_quarantine_close AFTER UPDATE ON instance_metadata
WHEN (OLD.status = 'quarantined' AND NEW.status <> 'quarantined') OR NEW.created_at <> OLD.created_at
BEGIN
    UPDATE quarantine_events SET closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
        final_status=CASE WHEN NEW.created_at <> OLD.created_at THEN 'replaced' ELSE NEW.status END
    WHERE entity_kind='instance' AND entity_id=OLD.instance_id AND generation=OLD.created_at AND closed_at IS NULL;
END;
CREATE TRIGGER instance_metadata_quarantine_delete AFTER DELETE ON instance_metadata
BEGIN
    UPDATE quarantine_events SET closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), final_status='deleted'
    WHERE entity_kind='instance' AND entity_id=OLD.instance_id AND generation=OLD.created_at AND closed_at IS NULL;
END;
INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
    SELECT 'instance', instance_id, created_at, 'legacy_unknown', 'manual_review', 'migration_backfill'
    FROM instance_metadata WHERE status='quarantined';
