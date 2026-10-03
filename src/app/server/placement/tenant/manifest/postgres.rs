use super::{
    ManifestError,
    model::{
        CollectedManifest, DataRecord, MultisetAccumulator, MultisetDigest, SchemaRecord,
        object_key,
    },
    query::{ManifestContext, decode_base64, decode_utf8, validate_identifier},
};
use crate::databases::postgres::provision::quote_ident as quote_postgres;

const PAGE_SIZE: usize = 128;

#[derive(Debug)]
struct Relation {
    schema: String,
    name: String,
    kind: char,
    data_bearing: bool,
}

pub(super) async fn collect(
    context: &ManifestContext<'_>,
) -> Result<CollectedManifest, ManifestError> {
    context.check_scan_bytes(data_size_sql()).await?;
    let mut collected = CollectedManifest::default();
    let relations = collect_relations(context, &mut collected).await?;
    collect_routines(context, &mut collected).await?;
    collect_types(context, &mut collected).await?;

    for relation in relations {
        match relation.kind {
            'r' | 'p' | 'm' if relation.data_bearing => {
                let digest = table_digest(context, &relation).await?;
                collected.push_data(DataRecord::new(
                    object_key("relation-data", &[&relation.schema, &relation.name]),
                    digest,
                )?)?;
            }
            'S' => {
                let digest = sequence_digest(context, &relation).await?;
                collected.push_data(DataRecord::new(
                    object_key("sequence-state", &[&relation.schema, &relation.name]),
                    digest,
                )?)?;
            }
            'r' | 'p' | 'v' | 'm' => {}
            'f' => {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "PostgreSQL foreign table {}.{} is not part of a portable logical migration",
                    relation.schema, relation.name
                )));
            }
            kind => {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "PostgreSQL relation kind {kind} is not covered"
                )));
            }
        }
    }
    Ok(collected)
}

fn data_size_sql() -> &'static str {
    r#"SELECT coalesce(sum(pg_total_relation_size(c.oid)::numeric), 0)::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  AND c.relkind IN ('r', 'm', 'S');"#
}

async fn collect_relations(
    context: &ManifestContext<'_>,
    collected: &mut CollectedManifest,
) -> Result<Vec<Relation>, ManifestError> {
    let mut relations = Vec::new();
    let mut offset = 0;
    loop {
        let output = context.query(&relation_catalog_sql(offset)).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 5 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid PostgreSQL relation catalog row",
                ));
            }
            let schema = decode_utf8(fields[0])?;
            let name = decode_utf8(fields[1])?;
            validate_identifier(&schema)?;
            validate_identifier(&name)?;
            let kind = parse_kind(fields[2])?;
            let definition = decode_base64(fields[3])?;
            let data_bearing = match fields[4] {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(ManifestError::InvalidCatalog(
                        "invalid PostgreSQL relation data marker",
                    ));
                }
            };
            collected.push_schema(SchemaRecord::new(
                object_key("relation", &[&schema, &name, fields[2]]),
                definition,
            )?)?;
            relations.push(Relation {
                schema,
                name,
                kind,
                data_bearing,
            });
        }
        if rows < PAGE_SIZE {
            break;
        }
        offset += PAGE_SIZE;
    }
    Ok(relations)
}

async fn collect_routines(
    context: &ManifestContext<'_>,
    collected: &mut CollectedManifest,
) -> Result<(), ManifestError> {
    let mut offset = 0;
    loop {
        let output = context.query(&routine_catalog_sql(offset)).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid PostgreSQL routine catalog row",
                ));
            }
            let schema = decode_utf8(fields[0])?;
            let name = decode_utf8(fields[1])?;
            let kind = fields[2];
            let definition = decode_base64(fields[3])?;
            validate_identifier(&schema)?;
            validate_identifier(&name)?;
            if !matches!(kind, "f" | "p") {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "PostgreSQL routine kind {kind} is not covered"
                )));
            }
            collected.push_schema(SchemaRecord::new(
                object_key("routine", &[&schema, &name, kind]),
                definition,
            )?)?;
        }
        if rows < PAGE_SIZE {
            return Ok(());
        }
        offset += PAGE_SIZE;
    }
}

async fn collect_types(
    context: &ManifestContext<'_>,
    collected: &mut CollectedManifest,
) -> Result<(), ManifestError> {
    let mut offset = 0;
    loop {
        let output = context.query(&type_catalog_sql(offset)).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid PostgreSQL type catalog row",
                ));
            }
            let schema = decode_utf8(fields[0])?;
            let name = decode_utf8(fields[1])?;
            let kind = fields[2];
            validate_identifier(&schema)?;
            validate_identifier(&name)?;
            if !matches!(kind, "e" | "d") {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "PostgreSQL custom type {schema}.{name} has unsupported kind {kind}"
                )));
            }
            collected.push_schema(SchemaRecord::new(
                object_key("type", &[&schema, &name, kind]),
                decode_base64(fields[3])?,
            )?)?;
        }
        if rows < PAGE_SIZE {
            return Ok(());
        }
        offset += PAGE_SIZE;
    }
}

async fn table_digest(
    context: &ManifestContext<'_>,
    relation: &Relation,
) -> Result<MultisetDigest, ManifestError> {
    let timeout_ms = context.engine_timeout()?.as_millis();
    let sql = format!(
        r#"BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = {timeout_ms};
SET LOCAL TimeZone = 'UTC';
SET LOCAL DateStyle = 'ISO, YMD';
SET LOCAL IntervalStyle = 'iso_8601';
SET LOCAL extra_float_digits = 3;
SET LOCAL bytea_output = 'hex';
WITH row_hash AS MATERIALIZED (
  SELECT encode(
    pg_catalog.sha256(
      decode('{challenge}', 'hex') ||
      convert_to(pg_catalog.to_jsonb(t)::text, 'UTF8')
    ),
    'hex'
  ) AS hash
  FROM {schema}.{table} AS t
), words AS MATERIALIZED (
  SELECT
    (('x' || substr(hash, 1, 16))::bit(64)::bigint) AS w0,
    (('x' || substr(hash, 17, 16))::bit(64)::bigint) AS w1,
    (('x' || substr(hash, 33, 16))::bit(64)::bigint) AS w2,
    (('x' || substr(hash, 49, 16))::bit(64)::bigint) AS w3
  FROM row_hash
)
SELECT count(*)::text,
  mod(mod(coalesce(sum(w0::numeric), 0), 18446744073709551616) + 18446744073709551616, 18446744073709551616)::text,
  mod(mod(coalesce(sum(w1::numeric), 0), 18446744073709551616) + 18446744073709551616, 18446744073709551616)::text,
  mod(mod(coalesce(sum(w2::numeric), 0), 18446744073709551616) + 18446744073709551616, 18446744073709551616)::text,
  mod(mod(coalesce(sum(w3::numeric), 0), 18446744073709551616) + 18446744073709551616, 18446744073709551616)::text,
  coalesce(bit_xor(w0), 0)::text,
  coalesce(bit_xor(w1), 0)::text,
  coalesce(bit_xor(w2), 0)::text,
  coalesce(bit_xor(w3), 0)::text
FROM words;
COMMIT;"#,
        challenge = context.challenge.hex(),
        schema = quote_postgres(&relation.schema),
        table = quote_postgres(&relation.name),
    );
    MultisetDigest::parse_tsv(&context.query(&sql).await?)
}

async fn sequence_digest(
    context: &ManifestContext<'_>,
    relation: &Relation,
) -> Result<MultisetDigest, ManifestError> {
    let sql = format!(
        "SELECT last_value::text || E'\\t' || is_called::text FROM {}.{};",
        quote_postgres(&relation.schema),
        quote_postgres(&relation.name),
    );
    let output = context.query(&sql).await?;
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let value = lines.next().ok_or(ManifestError::InvalidCatalog(
        "missing PostgreSQL sequence state",
    ))?;
    if lines.next().is_some() {
        return Err(ManifestError::InvalidCatalog(
            "multiple PostgreSQL sequence states returned",
        ));
    }
    let key = object_key("sequence-state", &[&relation.schema, &relation.name]);
    let mut digest = MultisetAccumulator::new();
    digest.add(context.challenge, &key, value.as_bytes())?;
    Ok(digest.finish())
}

fn parse_kind(value: &str) -> Result<char, ManifestError> {
    let mut chars = value.chars();
    let kind = chars.next().ok_or(ManifestError::InvalidCatalog(
        "missing PostgreSQL relation kind",
    ))?;
    if chars.next().is_some() {
        return Err(ManifestError::InvalidCatalog(
            "invalid PostgreSQL relation kind",
        ));
    }
    Ok(kind)
}

fn relation_catalog_sql(offset: usize) -> String {
    format!(
        r#"SELECT
  replace(encode(convert_to(n.nspname, 'UTF8'), 'base64'), E'\n', ''),
  replace(encode(convert_to(c.relname, 'UTF8'), 'base64'), E'\n', ''),
  c.relkind::text,
  replace(encode(convert_to(jsonb_build_object(
    'kind', c.relkind,
    'persistence', c.relpersistence,
    'access_method', am.amname,
    'replica_identity', c.relreplident,
    'row_security', c.relrowsecurity,
    'force_row_security', c.relforcerowsecurity,
    'partition_key', CASE WHEN c.relkind = 'p' THEN pg_get_partkeydef(c.oid) END,
    'partition_bound', pg_get_expr(c.relpartbound, c.oid, false),
    'view_definition', CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid, false) END,
    'options', coalesce((SELECT jsonb_agg(option ORDER BY option) FROM unnest(c.reloptions) option), '[]'::jsonb),
    'comment', obj_description(c.oid, 'pg_class'),
    'sequence', CASE WHEN c.relkind = 'S' THEN (
      SELECT jsonb_build_object(
        'type', format_type(s.seqtypid, NULL), 'start', s.seqstart,
        'increment', s.seqincrement, 'max', s.seqmax, 'min', s.seqmin,
        'cache', s.seqcache, 'cycle', s.seqcycle
      ) FROM pg_sequence s WHERE s.seqrelid = c.oid
    ) END,
    'columns', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'position', a.attnum, 'name', a.attname,
        'type', format_type(a.atttypid, a.atttypmod),
        'not_null', a.attnotnull, 'identity', a.attidentity,
        'generated', a.attgenerated, 'storage', a.attstorage,
        'compression', a.attcompression,
        'default', pg_get_expr(d.adbin, d.adrelid, false),
        'collation', CASE WHEN coll.oid IS NULL THEN NULL ELSE quote_ident(colln.nspname) || '.' || quote_ident(coll.collname) END,
        'options', a.attoptions, 'comment', col_description(c.oid, a.attnum)
      ) ORDER BY a.attnum)
      FROM pg_attribute a
      LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
      LEFT JOIN pg_collation coll ON coll.oid = a.attcollation AND a.attcollation <> 0
      LEFT JOIN pg_namespace colln ON colln.oid = coll.collnamespace
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    ), '[]'::jsonb),
    'constraints', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'name', con.conname, 'kind', con.contype,
        'definition', pg_get_constraintdef(con.oid, false),
        'deferrable', con.condeferrable, 'deferred', con.condeferred,
        'validated', con.convalidated
      ) ORDER BY con.conname, con.oid)
      FROM pg_constraint con WHERE con.conrelid = c.oid
    ), '[]'::jsonb),
    'indexes', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'name', idx.relname, 'definition', pg_get_indexdef(i.indexrelid, 0, false),
        'unique', i.indisunique, 'primary', i.indisprimary,
        'exclusion', i.indisexclusion, 'immediate', i.indimmediate,
        'valid', i.indisvalid, 'clustered', i.indisclustered,
        'replica_identity', i.indisreplident
      ) ORDER BY idx.relname)
      FROM pg_index i JOIN pg_class idx ON idx.oid = i.indexrelid
      WHERE i.indrelid = c.oid
    ), '[]'::jsonb),
    'triggers', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'name', t.tgname, 'enabled', t.tgenabled,
        'definition', pg_get_triggerdef(t.oid, false)
      ) ORDER BY t.tgname)
      FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
    ), '[]'::jsonb),
    'rules', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'name', r.rulename, 'enabled', r.ev_enabled,
        'definition', pg_get_ruledef(r.oid, false)
      ) ORDER BY r.rulename)
      FROM pg_rewrite r WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN'
    ), '[]'::jsonb),
    'policies', coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'name', p.polname, 'command', p.polcmd, 'permissive', p.polpermissive,
        'using', pg_get_expr(p.polqual, p.polrelid, false),
        'check', pg_get_expr(p.polwithcheck, p.polrelid, false),
        'roles', coalesce((
          SELECT jsonb_agg(CASE WHEN role.rolname = current_user THEN '$tenant' ELSE role.rolname END ORDER BY role.rolname)
          FROM unnest(p.polroles) AS policy_role(oid)
          JOIN pg_roles role ON role.oid = policy_role.oid
        ), '[]'::jsonb)
      ) ORDER BY p.polname)
      FROM pg_policy p WHERE p.polrelid = c.oid
    ), '[]'::jsonb)
  )::text, 'UTF8'), 'base64'), E'\n', ''),
  CASE WHEN c.relkind = 'p' OR c.relkind = 'm' OR (c.relkind = 'r' AND NOT c.relispartition) THEN '1' ELSE '0' END
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_am am ON am.oid = c.relam
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
ORDER BY n.nspname, c.relname, c.relkind
LIMIT {PAGE_SIZE} OFFSET {offset};"#,
    )
}

fn routine_catalog_sql(offset: usize) -> String {
    format!(
        r#"SELECT
  replace(encode(convert_to(n.nspname, 'UTF8'), 'base64'), E'\n', ''),
  replace(encode(convert_to(p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', 'UTF8'), 'base64'), E'\n', ''),
  p.prokind::text,
  replace(encode(convert_to(jsonb_build_object(
    'definition', CASE WHEN p.prokind IN ('f', 'p') THEN pg_get_functiondef(p.oid) END,
    'identity_arguments', pg_get_function_identity_arguments(p.oid),
    'result', CASE WHEN p.prokind IN ('f', 'p') THEN pg_get_function_result(p.oid) END,
    'language', l.lanname,
    'kind', p.prokind,
    'volatility', p.provolatile,
    'parallel', p.proparallel,
    'strict', p.proisstrict,
    'security_definer', p.prosecdef,
    'leakproof', p.proleakproof,
    'configuration', p.proconfig
  )::text, 'UTF8'), 'base64'), E'\n', '')
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)
LIMIT {PAGE_SIZE} OFFSET {offset};"#,
    )
}

fn type_catalog_sql(offset: usize) -> String {
    format!(
        r#"SELECT
  replace(encode(convert_to(n.nspname, 'UTF8'), 'base64'), E'\n', ''),
  replace(encode(convert_to(t.typname, 'UTF8'), 'base64'), E'\n', ''),
  t.typtype::text,
  replace(encode(convert_to(jsonb_build_object(
    'kind', t.typtype,
    'category', t.typcategory,
    'not_null', t.typnotnull,
    'default', t.typdefault,
    'base_type', CASE WHEN t.typbasetype <> 0 THEN format_type(t.typbasetype, t.typtypmod) END,
    'collation', CASE WHEN coll.oid IS NULL THEN NULL ELSE quote_ident(colln.nspname) || '.' || quote_ident(coll.collname) END,
    'enum_values', coalesce((
      SELECT jsonb_agg(jsonb_build_object('label', e.enumlabel, 'order', e.enumsortorder) ORDER BY e.enumsortorder)
      FROM pg_enum e WHERE e.enumtypid = t.oid
    ), '[]'::jsonb),
    'domain_constraints', coalesce((
      SELECT jsonb_agg(jsonb_build_object('name', con.conname, 'definition', pg_get_constraintdef(con.oid, false)) ORDER BY con.conname)
      FROM pg_constraint con WHERE con.contypid = t.oid
    ), '[]'::jsonb)
  )::text, 'UTF8'), 'base64'), E'\n', '')
FROM pg_type t
JOIN pg_namespace n ON n.oid = t.typnamespace
LEFT JOIN pg_class type_relation ON type_relation.oid = t.typrelid
LEFT JOIN pg_collation coll ON coll.oid = t.typcollation AND t.typcollation <> 0
LEFT JOIN pg_namespace colln ON colln.oid = coll.collnamespace
WHERE n.nspname <> 'information_schema'
  AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
  AND (
    t.typtype IN ('e', 'd', 'r', 'm')
    OR (t.typtype = 'c' AND type_relation.relkind = 'c')
    OR (t.typtype = 'b' AND t.typelem = 0 AND t.typisdefined)
  )
ORDER BY n.nspname, t.typname
LIMIT {PAGE_SIZE} OFFSET {offset};"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_query_uses_core_sha256_and_order_independent_accumulators() {
        let relation = Relation {
            schema: "public".to_string(),
            name: "events".to_string(),
            kind: 'r',
            data_bearing: true,
        };
        let query = format!(
            "{} {}",
            quote_postgres(&relation.schema),
            quote_postgres(&relation.name)
        );
        assert_eq!(query, "\"public\" \"events\"");
        let catalog = relation_catalog_sql(0);
        assert!(catalog.contains("pg_get_indexdef"));
        assert!(catalog.contains("pg_get_constraintdef"));
        assert!(catalog.contains("pg_get_triggerdef"));
        assert!(catalog.contains("'columns'"));
        assert!(data_size_sql().contains("pg_total_relation_size"));
    }
}
