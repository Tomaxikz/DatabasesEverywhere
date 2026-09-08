-- Runtime-owned, not tenant-owned: all members of a pool share one budget.
-- Kept out of metadata JSON so ordinary status/upsert operations cannot reset it.
ALTER TABLE engine_runtimes ADD COLUMN startup_attempts INTEGER NOT NULL DEFAULT 0
    CHECK (startup_attempts BETWEEN 0 AND 2);
