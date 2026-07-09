-- Preserve legacy rows while making any pre-existing ambiguous active routes
-- fail closed. The lexicographically first instance remains active; every
-- other active claimant is retained as quarantined so an operator can inspect and
-- delete or repair it after the daemon starts.
UPDATE instance_metadata AS candidate
SET status = 'quarantined',
    metadata_json = json_set(candidate.metadata_json, '$.status', 'quarantined')
WHERE candidate.status <> 'quarantined'
  AND candidate.protocol NOT IN ('redis', 'qdrant')
  AND EXISTS (
      SELECT 1
      FROM instance_metadata AS winner
      WHERE winner.status <> 'quarantined'
        AND winner.protocol = candidate.protocol
        AND winner.database_username = candidate.database_username
        AND winner.database_name = candidate.database_name
        AND winner.instance_id < candidate.instance_id
  );

UPDATE instance_metadata AS candidate
SET status = 'quarantined',
    metadata_json = json_set(candidate.metadata_json, '$.status', 'quarantined')
WHERE candidate.status <> 'quarantined'
  AND candidate.protocol = 'redis'
  AND EXISTS (
      SELECT 1
      FROM instance_metadata AS winner
      WHERE winner.status <> 'quarantined'
        AND winner.protocol = 'redis'
        AND winner.database_username = candidate.database_username
        AND winner.instance_id < candidate.instance_id
  );

UPDATE instance_metadata AS candidate
SET status = 'quarantined',
    metadata_json = json_set(candidate.metadata_json, '$.status', 'quarantined')
WHERE candidate.status <> 'quarantined'
  AND candidate.protocol = 'qdrant'
  AND json_extract(candidate.metadata_json, '$.route_key_sha256') IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM instance_metadata AS winner
      WHERE winner.status <> 'quarantined'
        AND winner.protocol = 'qdrant'
        AND json_extract(winner.metadata_json, '$.route_key_sha256') =
            json_extract(candidate.metadata_json, '$.route_key_sha256')
        AND winner.instance_id < candidate.instance_id
  );

-- Route identity must be unique in durable storage as well as in the in-memory
-- resolver. Every ordinary lifecycle state reserves its route. Quarantined
-- legacy duplicates remain inspectable but cannot be started.
CREATE UNIQUE INDEX uq_instance_metadata_protocol_database
    ON instance_metadata(protocol, database_username, database_name)
    WHERE protocol NOT IN ('redis', 'qdrant')
      AND status <> 'quarantined';

CREATE UNIQUE INDEX uq_instance_metadata_redis_username
    ON instance_metadata(protocol, database_username)
    WHERE protocol = 'redis'
      AND status <> 'quarantined';

CREATE UNIQUE INDEX uq_instance_metadata_qdrant_route_key
    ON instance_metadata(
        protocol,
        json_extract(metadata_json, '$.route_key_sha256')
    )
    WHERE protocol = 'qdrant'
      AND status <> 'quarantined'
      AND json_extract(metadata_json, '$.route_key_sha256') IS NOT NULL;
