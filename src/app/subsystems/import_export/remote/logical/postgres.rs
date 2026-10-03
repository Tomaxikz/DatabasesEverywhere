use super::*;

pub(super) async fn prepare_postgres(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    let username = required(source.username.as_deref(), "source.username")?;
    let password = required_secret(source.password.as_ref(), "source.password")?;
    let ssl_mode = if source.endpoint.tls {
        "verify-full"
    } else {
        "disable"
    };
    let service = format!(
        "[remote]\nhost={}\nport={}\ndbname={}\nuser={}\nsslmode={ssl_mode}\nconnect_timeout={connect_timeout_seconds}\n",
        pg_service_value(&source.endpoint.host)?,
        source.endpoint.port,
        pg_service_value(database)?,
        pg_service_value(username)?,
    );
    let passfile = format!(
        "{}:{}:{}:{}:{}\n",
        pgpass_value(&source.endpoint.host)?,
        source.endpoint.port,
        pgpass_value(database)?,
        pgpass_value(username)?,
        pgpass_value(password)?,
    );
    write_private_file(&work_dir.join("pg_service.conf"), service.as_bytes()).await?;
    write_private_file(&work_dir.join("pgpass"), passfile.as_bytes()).await?;

    let filters = postgres_selection_args(selection);
    let tls_root_setup = if source.endpoint.tls {
        r#"if [ -r /etc/ssl/certs/ca-certificates.crt ]; then
  printf '%s\n' 'sslrootcert=/etc/ssl/certs/ca-certificates.crt' >> /work/pg_service.conf
elif [ -r /etc/pki/tls/certs/ca-bundle.crt ]; then
  printf '%s\n' 'sslrootcert=/etc/pki/tls/certs/ca-bundle.crt' >> /work/pg_service.conf
elif [ -r /etc/ssl/cert.pem ]; then
  printf '%s\n' 'sslrootcert=/etc/ssl/cert.pem' >> /work/pg_service.conf
else
  echo 'trusted system CA bundle is unavailable' >&2
  exit 78
fi
"#
    } else {
        ""
    };
    let schema_query = sh_quote(&postgres_schema_query(selection));
    let toc_filter = sh_quote(POSTGRES_TOC_FILTER_PROGRAM);
    Ok(format!(
        r#"set -eu
umask 077
export PGSERVICEFILE=/work/pg_service.conf
export PGPASSFILE=/work/pgpass
{tls_root_setup}psql service=remote -X -v ON_ERROR_STOP=1 -Atc 'SHOW server_version_num' >/work/source-version
pg_dump service=remote --no-owner --no-privileges --format=custom{filters} --file=/work/source.postgres.archive
pg_restore --list /work/source.postgres.archive > /work/source.postgres.toc
awk {toc_filter} /work/source.postgres.toc > /work/source.postgres.filtered.toc
psql service=remote -X -v ON_ERROR_STOP=1 -Atc {schema_query} > /work/source.postgres.schemas.sql
cat /work/source.postgres.schemas.sql > /work/source.postgres.sql
pg_restore --exit-on-error --clean --if-exists --no-owner --no-privileges \
  --use-list=/work/source.postgres.filtered.toc --file=- \
  /work/source.postgres.archive >> /work/source.postgres.sql
rm -f /work/source.postgres.archive /work/source.postgres.toc \
  /work/source.postgres.filtered.toc /work/source.postgres.schemas.sql
"#
    ))
}

pub(super) fn postgres_selection_args(selection: &ImportExportSelection) -> String {
    if selection.mode == SelectionMode::Full {
        return String::new();
    }
    // Without --strict-names, a typoed include can produce a successful empty
    // dump. That is particularly dangerous when the requested mode is wipe.
    let mut args = String::from(" --strict-names");
    for item in &selection.include {
        args.push_str(" --table=");
        args.push_str(&sh_quote(item));
    }
    for item in &selection.exclude {
        args.push_str(" --exclude-table=");
        args.push_str(&sh_quote(item));
    }
    args
}

// Archive TOC entries are structural metadata emitted by pg_restore. Removing
// only SCHEMA entries here prevents --clean from dropping a whole target
// schema while leaving SQL bodies and COPY data completely untouched.
pub(super) const POSTGRES_TOC_FILTER_PROGRAM: &str =
    r#"!($0 ~ /^[0-9]+;/ && $0 ~ / SCHEMA - /) { print }"#;

pub(super) fn postgres_schema_query(selection: &ImportExportSelection) -> String {
    let scope = if selection.mode == SelectionMode::Full {
        String::new()
    } else {
        let predicates = selection
            .include
            .iter()
            .map(|item| postgres_include_predicate(item))
            .collect::<Vec<_>>()
            .join(" OR ");
        format!(" AND ({predicates})")
    };
    format!(
        "SELECT format('CREATE SCHEMA IF NOT EXISTS %I;', n.nspname) \
         FROM pg_catalog.pg_namespace n \
         WHERE n.nspname <> 'information_schema' \
           AND left(n.nspname, 3) <> 'pg_'{scope} \
         ORDER BY n.nspname"
    )
}

pub(super) fn postgres_include_predicate(item: &str) -> String {
    let (schema, table) = match item.rsplit_once('.') {
        Some((schema, table)) => (Some(schema), table),
        None => (None, item),
    };
    let table = postgres_string_literal(table);
    let relation = format!(
        "EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace = n.oid AND c.relname = {table})"
    );
    match schema {
        Some(schema) => format!(
            "(n.nspname = {} AND {relation})",
            postgres_string_literal(schema)
        ),
        None => relation,
    }
}

pub(super) fn postgres_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(super) fn pg_service_value(value: &str) -> Result<String, ApiError> {
    if contains_nul_or_line_break(value) {
        return Err(ApiError::BadRequest(
            "postgres source fields must not contain line breaks".to_string(),
        ));
    }
    Ok(value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace(' ', "\\ "))
}

pub(super) fn pgpass_value(value: &str) -> Result<String, ApiError> {
    if contains_nul_or_line_break(value) {
        return Err(ApiError::BadRequest(
            "postgres pgpass fields must not contain NUL or line breaks".to_string(),
        ));
    }
    Ok(value.replace('\\', "\\\\").replace(':', "\\:"))
}
