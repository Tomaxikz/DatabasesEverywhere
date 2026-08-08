-- Valkey routes, like Redis routes, are selected by ACL username alone.
-- Quarantine any legacy ambiguous routes before changing the durable index.
UPDATE instance_metadata AS candidate
SET status = 'quarantined',
    metadata_json = json_set(candidate.metadata_json, '$.status', 'quarantined')
WHERE candidate.status <> 'quarantined'
  AND candidate.protocol = 'valkey'
  AND EXISTS (
      SELECT 1
      FROM instance_metadata AS winner
      WHERE winner.status <> 'quarantined'
        AND winner.protocol = 'valkey'
        AND winner.database_username = candidate.database_username
        AND winner.instance_id < candidate.instance_id
  );

DROP INDEX uq_instance_metadata_protocol_database;

CREATE UNIQUE INDEX uq_instance_metadata_protocol_database
    ON instance_metadata(protocol, database_username, database_name)
    WHERE protocol NOT IN ('redis', 'valkey', 'qdrant')
      AND status <> 'quarantined';

CREATE UNIQUE INDEX uq_instance_metadata_valkey_username
    ON instance_metadata(protocol, database_username)
    WHERE protocol = 'valkey'
      AND status <> 'quarantined';
