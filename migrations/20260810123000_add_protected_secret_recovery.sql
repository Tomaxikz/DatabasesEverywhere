ALTER TABLE instance_metadata
ADD COLUMN protected_secret_recovery_required INTEGER NOT NULL DEFAULT 0
CHECK (protected_secret_recovery_required IN (0, 1));
