DROP TRIGGER trg_tenant_activity_retention;

CREATE TRIGGER trg_tenant_activity_retention
AFTER INSERT ON tenant_activity_buckets
BEGIN
    DELETE FROM tenant_activity_buckets
    WHERE instance_id = NEW.instance_id
      AND instance_generation = NEW.instance_generation
      AND bucket_start_unix < (
          SELECT MAX(bucket_start_unix) - 86400
          FROM tenant_activity_buckets
          WHERE instance_id = NEW.instance_id AND instance_generation = NEW.instance_generation
      );

    -- A missing 1,440th row gives a NULL cutoff, so shorter histories stay intact.
    DELETE FROM tenant_activity_buckets
    WHERE instance_id = NEW.instance_id
      AND instance_generation = NEW.instance_generation
      AND bucket_start_unix < (
          SELECT bucket_start_unix
          FROM tenant_activity_buckets
          WHERE instance_id = NEW.instance_id AND instance_generation = NEW.instance_generation
          ORDER BY bucket_start_unix DESC LIMIT 1 OFFSET 1439
      );
END;
