ALTER TABLE instance_metadata
    ADD COLUMN desired_state TEXT NOT NULL DEFAULT 'running'
    CHECK (desired_state IN ('running', 'stopped'));

-- Before this migration DBEV used the last observed status as implicit intent.
-- Preserve explicit stops and fail-closed states. Failed instances retain the
-- historical retry-on-boot behavior, while creating/booting/running instances
-- remain desired-running.
UPDATE instance_metadata
SET desired_state = CASE
    WHEN status IN ('stopped', 'quarantined', 'deleting') THEN 'stopped'
    ELSE 'running'
END;
