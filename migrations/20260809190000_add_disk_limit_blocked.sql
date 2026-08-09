ALTER TABLE instance_metadata
    ADD COLUMN disk_limit_blocked INTEGER NOT NULL DEFAULT 0
    CHECK (disk_limit_blocked IN (0, 1));

-- Historical instances were never stopped by the predictive scanner. Keep
-- the flag false rather than conflating ordinary operator stops or failures
-- with limiter-owned hysteresis.
UPDATE instance_metadata SET disk_limit_blocked = 0;
