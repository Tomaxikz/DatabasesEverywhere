use std::{path::Path, time::Duration};

use secrecy::ExposeSecret;
use serde::Serialize;

use crate::{
    api::{
        api_response::ApiError,
        import_export::{CLICKHOUSE_ENGINE_AWK_PROGRAM, ImportExportSelection, SelectionMode},
    },
    runtime::docker::{DockerError, RemoteImportHelperSpec},
    shared::{protocol::Protocol, shell::sh_quote},
};

use super::{RemoteImportSource, write_private_file};

pub(super) async fn run_helper(
    state: &crate::api::routes::AppState,
    protocol: Protocol,
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    target_username: &str,
    work_dir: &Path,
    output_names: &[String],
) -> Result<(), ApiError> {
    let connect_timeout_seconds = state.config.security.remote_import.connect_timeout_seconds;
    let image = state
        .config
        .images
        .configured_for_protocol(protocol)
        .to_string();
    if let Err(error) = state.docker.ensure_remote_import_image(&image).await {
        return Err(remote_helper_error(protocol, &error));
    }

    let script = match protocol {
        Protocol::Postgres => {
            prepare_postgres(source, selection, work_dir, connect_timeout_seconds).await?
        }
        Protocol::Mariadb => {
            prepare_mariadb(source, selection, work_dir, connect_timeout_seconds).await?
        }
        Protocol::Mysql => {
            prepare_mysql(
                source,
                selection,
                target_username,
                work_dir,
                connect_timeout_seconds,
            )
            .await?
        }
        Protocol::Mongodb => {
            prepare_mongodb(
                source,
                selection,
                work_dir,
                output_names,
                connect_timeout_seconds,
            )
            .await?
        }
        Protocol::Clickhouse => {
            prepare_clickhouse(source, selection, work_dir, connect_timeout_seconds).await?
        }
        Protocol::Redis | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} cannot be acquired as a logical dump",
                protocol.as_str()
            )));
        }
    };
    debug_assert!(
        output_names
            .iter()
            .all(|output_name| script.contains(output_name))
    );

    let spec = RemoteImportHelperSpec {
        image,
        work_dir: work_dir.to_path_buf(),
        script,
        extra_hosts: source.endpoint.helper_extra_hosts(),
        timeout: Duration::from_secs(
            state
                .config
                .security
                .remote_import
                .operation_timeout_seconds,
        ),
        max_output_bytes: state.config.security.remote_import.max_staged_bytes,
    };
    match state.docker.run_remote_import_helper(&spec).await {
        Ok(_) => Ok(()),
        Err(error) => Err(remote_helper_error(protocol, &error)),
    }
}

pub(super) fn output_names(
    protocol: Protocol,
    selection: &ImportExportSelection,
) -> Result<Vec<String>, ApiError> {
    let names = match protocol {
        Protocol::Postgres => vec!["source.postgres.sql".to_string()],
        Protocol::Mariadb => vec!["source.mariadb.sql".to_string()],
        Protocol::Mysql => vec!["source.mysql.sql".to_string()],
        Protocol::Clickhouse => vec!["source.clickhouse.sql".to_string()],
        Protocol::Mongodb => {
            let collection_count = mongodb_selected_collections(selection)?.len();
            if collection_count == 1 {
                vec!["source.mongodb.archive.gz".to_string()]
            } else {
                (0..collection_count)
                    .map(|index| format!("source.mongodb.{index:04}.archive.gz"))
                    .collect()
            }
        }
        Protocol::Redis | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} cannot be acquired as a logical dump",
                protocol.as_str()
            )));
        }
    };
    Ok(names)
}

fn remote_helper_error(protocol: Protocol, error: &DockerError) -> ApiError {
    tracing::warn!(
        protocol = protocol.as_str(),
        error_kind = ?std::mem::discriminant(error),
        "remote database dump helper failed"
    );
    ApiError::BadRequest(format!(
        "remote {} source acquisition failed; verify endpoint, TLS, credentials, permissions, and version compatibility",
        protocol.as_str()
    ))
}

async fn prepare_postgres(
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
    let schema_query = sh_quote(&postgres_schema_creation_query(selection));
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

async fn prepare_mariadb(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    write_mysql_option_file(
        source,
        work_dir,
        MysqlFlavor::Mariadb,
        connect_timeout_seconds,
    )
    .await?;
    let (filters, tables) = mysql_selection_args(selection, database, "--ignore-table")?;
    let database_objects = mysql_database_object_args(selection);
    let definer_filter =
        mysql_definer_filter_script("/work/source.mariadb.raw.sql", "/work/source.mariadb.sql");
    Ok(format!(
        r#"set -eu
umask 077
mariadb --defaults-extra-file=/work/client.cnf --batch --skip-column-names -e 'SELECT VERSION()' >/work/source-version
mariadb-dump --defaults-extra-file=/work/client.cnf \
  --single-transaction --quick{database_objects} --triggers \
  --hex-blob --add-drop-table --skip-comments{filters} \
  -- {}{tables} > /work/source.mariadb.raw.sql
{definer_filter}
rm -f /work/source.mariadb.raw.sql
"#,
        sh_quote(database)
    ))
}

async fn prepare_mysql(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    target_username: &str,
    work_dir: &Path,
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    write_mysql_option_file(
        source,
        work_dir,
        MysqlFlavor::Mysql,
        connect_timeout_seconds,
    )
    .await?;
    let (filters, tables) = mysql_selection_args(selection, database, "--ignore-table")?;
    let database_objects = mysql_database_object_args(selection);
    let definer_filter = mysql_target_definer_filter_script(
        "/work/source.mysql.raw.sql",
        "/work/source.mysql.sql",
        target_username,
    )?;
    Ok(format!(
        r#"set -eu
umask 077
mysql --defaults-extra-file=/work/client.cnf --batch --skip-column-names -e 'SELECT VERSION()' >/work/source-version
mysqldump --defaults-extra-file=/work/client.cnf \
  --single-transaction --quick{database_objects} --triggers \
  --hex-blob --add-drop-table --skip-comments --no-tablespaces --set-gtid-purged=OFF{filters} \
  -- {}{tables} > /work/source.mysql.raw.sql
{definer_filter}
rm -f /work/source.mysql.raw.sql
"#,
        sh_quote(database)
    ))
}

#[derive(Clone, Copy)]
enum MysqlFlavor {
    Mariadb,
    Mysql,
}

async fn write_mysql_option_file(
    source: &RemoteImportSource,
    work_dir: &Path,
    flavor: MysqlFlavor,
    connect_timeout_seconds: u64,
) -> Result<(), ApiError> {
    let username = required(source.username.as_deref(), "source.username")?;
    let password = required_secret(source.password.as_ref(), "source.password")?;
    let mut config = format!(
        "[client]\nhost={}\nport={}\nprotocol=tcp\nuser={}\npassword={}\nconnect-timeout={connect_timeout_seconds}\n",
        mysql_option_value(&source.endpoint.host)?,
        source.endpoint.port,
        mysql_option_value(username)?,
        mysql_option_value(password)?,
    );
    match (flavor, source.endpoint.tls) {
        (MysqlFlavor::Mariadb, true) => {
            config.push_str("ssl=1\nssl-verify-server-cert=1\n");
        }
        (MysqlFlavor::Mariadb, false) => config.push_str("ssl=0\n"),
        (MysqlFlavor::Mysql, true) => config.push_str("ssl-mode=VERIFY_IDENTITY\n"),
        (MysqlFlavor::Mysql, false) => config.push_str("ssl-mode=DISABLED\n"),
    }
    write_private_file(&work_dir.join("client.cnf"), config.as_bytes()).await
}

async fn prepare_mongodb(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    output_names: &[String],
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    let collections = mongodb_selected_collections(selection)?;
    if collections.len() != output_names.len() {
        return Err(ApiError::Runtime(
            "mongodb remote import output plan did not match its collection selection".to_string(),
        ));
    }
    let host = if source.endpoint.host.contains(':') {
        format!("[{}]", source.endpoint.host)
    } else {
        source.endpoint.host.clone()
    };
    let tls = if source.endpoint.tls { "&tls=true" } else { "" };
    let connect_timeout_milliseconds = connect_timeout_seconds.saturating_mul(1_000);
    let config = MongoDumpConfig {
        uri: format!(
            "mongodb://{host}:{}/?directConnection=true&connectTimeoutMS={connect_timeout_milliseconds}&serverSelectionTimeoutMS={connect_timeout_milliseconds}{tls}",
            source.endpoint.port,
        ),
        password: source.password.as_ref().map(ExposeSecret::expose_secret),
    };
    let config = serde_yaml::to_string(&config).map_err(|error| {
        ApiError::Runtime(format!("failed to encode mongodb credentials: {error}"))
    })?;
    write_private_file(&work_dir.join("mongodump.yml"), config.as_bytes()).await?;

    let mut authentication = String::new();
    if let Some(username) = source.username.as_deref() {
        authentication.push_str(" --username ");
        authentication.push_str(&sh_quote(username));
        authentication.push_str(" --authenticationDatabase ");
        authentication.push_str(&sh_quote(
            source
                .authentication_database
                .as_deref()
                .unwrap_or(database),
        ));
    }
    let mut script = format!(
        "set -eu\numask 077\ndump_collection() {{\n  mongodump --config /work/mongodump.yml --db {}{authentication} \"$@\" --gzip\n}}\n",
        sh_quote(database),
    );
    for (collection, output_name) in collections.into_iter().zip(output_names) {
        let collection = collection
            .map(|collection| format!(" --collection={}", sh_quote(collection)))
            .unwrap_or_default();
        script.push_str(&format!(
            "dump_collection{collection} --archive={}\n",
            sh_quote(&format!("/work/{output_name}")),
        ));
    }
    Ok(script)
}

#[derive(Serialize)]
struct MongoDumpConfig<'a> {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

async fn prepare_clickhouse(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    let username = required(source.username.as_deref(), "source.username")?;
    let password = required_secret(source.password.as_ref(), "source.password")?;
    if !portable_identifier(database) {
        return Err(ApiError::BadRequest(
            "clickhouse source.database must use ascii letters, digits, underscore, or dash"
                .to_string(),
        ));
    }
    let secure = if source.endpoint.tls { "true" } else { "false" };
    let tls_validation = if source.endpoint.tls {
        r#"<openSSL><client><loadDefaultCAFile>true</loadDefaultCAFile><verificationMode>strict</verificationMode><invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler></client></openSSL>"#
    } else {
        ""
    };
    let config = format!(
        "<clickhouse><host>{}</host><port>{}</port><user>{}</user><password>{}</password><database>{}</database><secure>{secure}</secure><connect_timeout>{connect_timeout_seconds}</connect_timeout>{tls_validation}</clickhouse>\n",
        xml_escape(&source.endpoint.host),
        source.endpoint.port,
        xml_escape(username),
        xml_escape(password),
        xml_escape(database),
    );
    write_private_file(&work_dir.join("clickhouse-client.xml"), config.as_bytes()).await?;

    let (table_source, exclude_case) = clickhouse_table_selection(selection);
    let column_case = clickhouse_column_selection(selection);
    let database_shell = sh_quote(database);
    let rebase_create = CLICKHOUSE_REBASE_CREATE_SCRIPT;
    let engine_parser = sh_quote(CLICKHOUSE_ENGINE_AWK_PROGRAM);
    Ok(format!(
        r#"set -eu
umask 077
client='clickhouse-client --config-file=/work/clickhouse-client.xml'
database={database_shell}
$client --query 'SELECT version()' >/work/source-version
printf '%s\n' '-- DatabasesEverywhere ClickHouse logical dump' > /work/source.clickhouse.sql
{table_source} | while IFS= read -r table; do
  [ -n "$table" ] || continue
  case "$table" in *[!A-Za-z0-9_-]*)
    echo 'remote clickhouse contains a non-portable table name' >&2
    exit 40
  ;; esac
  {exclude_case}
  create=$($client --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw")
  engine=$(printf '%s\n' "$create" | awk {engine_parser}) || {{
    echo 'remote clickhouse SHOW CREATE must contain exactly one valid ENGINE clause' >&2
    exit 41
  }}
  case "$engine" in
    MergeTree|ReplacingMergeTree|SummingMergeTree|AggregatingMergeTree|CollapsingMergeTree|VersionedCollapsingMergeTree|GraphiteMergeTree|CoalescingMergeTree|Log|TinyLog|StripeLog|Memory) ;;
    *)
      echo 'remote clickhouse table uses an unsupported or non-portable table engine' >&2
      exit 41
    ;;
  esac
  columns=$({column_case})
  printf 'DROP TABLE IF EXISTS `%s`;\n' "$table" >> /work/source.clickhouse.sql
  {rebase_create} >> /work/source.clickhouse.sql
  printf ';\n' >> /work/source.clickhouse.sql
  $client \
    --output_format_sql_insert_table_name="$table" \
    --query "SELECT $columns FROM \`$table\` FORMAT SQLInsert" >> /work/source.clickhouse.sql
  printf '\n' >> /work/source.clickhouse.sql
done
"#
    ))
}

const CLICKHOUSE_REBASE_CREATE_SCRIPT: &str = r#"quoted_qualified="CREATE TABLE \`$database\`.\`$table\`"
plain_qualified="CREATE TABLE $database.$table"
quoted_local="CREATE TABLE \`$table\`"
plain_local="CREATE TABLE $table"
case "$create" in
  "$quoted_qualified"*) suffix=${create#"$quoted_qualified"} ;;
  "$plain_qualified"*)  suffix=${create#"$plain_qualified"} ;;
  "$quoted_local"*)     suffix=${create#"$quoted_local"} ;;
  "$plain_local"*)      suffix=${create#"$plain_local"} ;;
  *)
    echo 'remote clickhouse SHOW CREATE returned an unexpected table identifier' >&2
    exit 42
  ;;
esac
case "$suffix" in
  ''|[[:space:]]*|'('*) ;;
  *)
    echo 'remote clickhouse SHOW CREATE table identifier was ambiguous' >&2
    exit 43
  ;;
esac
printf 'CREATE TABLE `%s`%s\n' "$table" "$suffix""#;

fn postgres_selection_args(selection: &ImportExportSelection) -> String {
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

fn mysql_selection_args(
    selection: &ImportExportSelection,
    database: &str,
    ignore_flag: &str,
) -> Result<(String, String), ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok((String::new(), String::new()));
    }
    let mut filters = String::new();
    for item in &selection.exclude {
        let table = mysql_selection_table(item, database)?;
        filters.push(' ');
        filters.push_str(ignore_flag);
        filters.push('=');
        filters.push_str(&sh_quote(&format!("{database}.{table}")));
    }
    let mut tables = String::new();
    for item in &selection.include {
        let table = mysql_selection_table(item, database)?;
        tables.push(' ');
        tables.push_str(&sh_quote(table));
    }
    Ok((filters, tables))
}

fn mysql_selection_table<'a>(item: &'a str, database: &str) -> Result<&'a str, ApiError> {
    let Some((qualified_database, table)) = item.rsplit_once('.') else {
        return Ok(item);
    };
    if qualified_database != database {
        return Err(ApiError::BadRequest(format!(
            "mysql/mariadb selection item {item} targets database {qualified_database}; expected {database}"
        )));
    }
    Ok(table)
}

fn mysql_database_object_args(selection: &ImportExportSelection) -> &'static str {
    if selection.mode == SelectionMode::Full {
        " --routines --events"
    } else {
        ""
    }
}

const MYSQL_DEFINER_SED_PROGRAM: &str = r#"/^[[:space:]]*\/\*(M)?!/ {
s#(/\*(M)?![0-9]*[[:space:]]+)DEFINER=`([^`]|``)*`@`([^`]|``)*`[[:space:]]*#\1#
}
/^[[:space:]]*(CREATE|ALTER)[[:space:]]/ {
s#^([[:space:]]*(CREATE|ALTER)[[:space:]]+((OR[[:space:]]+REPLACE|ALGORITHM=[^[:space:]]+)[[:space:]]+)*)DEFINER=`([^`]|``)*`@`([^`]|``)*`[[:space:]]*#\1#
}"#;

const MYSQL_TARGET_DEFINER_AWK_PROGRAM: &str = r#"
function plain_object(value) {
  return value ~ /^[[:space:]]*(CREATE|ALTER)[[:space:]]+((OR[[:space:]]+REPLACE|ALGORITHM=[^[:space:]]+|DEFINER=[^[:space:]]+|SQL[[:space:]]+SECURITY[[:space:]]+(DEFINER|INVOKER))[[:space:]]+)*(EVENT|FUNCTION|PROCEDURE|TRIGGER|VIEW)([[:space:]`(]|$)/
}
function version_object(value) {
  return value ~ /\/\*![0-9]+[[:space:]]+(EVENT|FUNCTION|PROCEDURE|TRIGGER|VIEW)([[:space:]`(]|$)/
}
{
  if (pending && $0 ~ /^[[:space:]]*$/) {
    next
  }

  is_plain_object = plain_object($0)
  is_version_object = version_object($0)
  is_object = is_plain_object || is_version_object
  version_definer = $0 ~ /^[[:space:]]*\/\*!/ && $0 ~ /\/\*![0-9]+[[:space:]]+DEFINER=/
  plain_definer = is_plain_object && $0 ~ /DEFINER=/
  version_target = $0 ~ ("/[*]![0-9]+[[:space:]]+" expected "([[:space:]]|[*]/)")
  plain_target = is_plain_object && $0 ~ ("^[[:space:]]*(CREATE|ALTER)[[:space:]]+((OR[[:space:]]+REPLACE|ALGORITHM=[^[:space:]]+)[[:space:]]+)*" expected "[[:space:]]+")

  if (pending) {
    if (is_object && !version_definer && !plain_definer) {
      pending = 0
      next
    }
    unsafe = 1
    pending = 0
  }

  if ((version_definer && !version_target) || (plain_definer && !plain_target)) {
    unsafe = 1
  }
  if (is_object) {
    if (!version_target && !plain_target) {
      unsafe = 1
    }
  } else if (version_target) {
    pending = 1
  }
}
END {
  if (unsafe || pending) {
    print "mysqldump emitted an unsupported or unsafe DEFINER form" > "/dev/stderr"
    exit 65
  }
}
"#;

fn mysql_definer_filter_script(input: &str, output: &str) -> String {
    format!(
        "sed -E {} -- {} > {}\n",
        sh_quote(MYSQL_DEFINER_SED_PROGRAM),
        sh_quote(input),
        sh_quote(output)
    )
}

fn mysql_target_definer_filter_script(
    input: &str,
    output: &str,
    target_username: &str,
) -> Result<String, ApiError> {
    if target_username.is_empty()
        || target_username.len() > 63
        || !target_username
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !target_username
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::BadRequest(
            "target mysql username cannot be represented safely in imported object definers"
                .to_string(),
        ));
    }

    let target_definer = format!("DEFINER=`{target_username}`@`%`");
    let rewrite_program = format!(
        r#"/^[[:space:]]*\/\*!/ {{
s#(/\*![0-9]+[[:space:]]+)DEFINER=`([^`]|``)*`@`([^`]|``)*`#\1{target_definer}#
}}
/^[[:space:]]*(CREATE|ALTER)[[:space:]]/ {{
s#^([[:space:]]*(CREATE|ALTER)[[:space:]]+((OR[[:space:]]+REPLACE|ALGORITHM=[^[:space:]]+)[[:space:]]+)*)DEFINER=`([^`]|``)*`@`([^`]|``)*`#\1{target_definer}#
}}"#
    );
    Ok(format!(
        "sed -E {} -- {} > {}\nawk -v expected={} {} {}\n",
        sh_quote(&rewrite_program),
        sh_quote(input),
        sh_quote(output),
        sh_quote(&target_definer),
        sh_quote(MYSQL_TARGET_DEFINER_AWK_PROGRAM),
        sh_quote(output),
    ))
}

// Archive TOC entries are structural metadata emitted by pg_restore. Removing
// only SCHEMA entries here prevents --clean from dropping a whole target
// schema while leaving SQL bodies and COPY data completely untouched.
const POSTGRES_TOC_FILTER_PROGRAM: &str = r#"!($0 ~ /^[0-9]+;/ && $0 ~ / SCHEMA - /) { print }"#;

fn postgres_schema_creation_query(selection: &ImportExportSelection) -> String {
    let scope = if selection.mode == SelectionMode::Full {
        String::new()
    } else {
        let predicates = selection
            .include
            .iter()
            .map(|item| {
                let (schema, table) = item
                    .rsplit_once('.')
                    .map_or((None, item.as_str()), |(schema, table)| {
                        (Some(schema), table)
                    });
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
            })
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

fn postgres_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn mongodb_selected_collections(
    selection: &ImportExportSelection,
) -> Result<Vec<Option<&str>>, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(vec![None]);
    }
    if selection.include.is_empty() {
        return Err(ApiError::BadRequest(
            "mongodb remote selective import requires at least one included collection".to_string(),
        ));
    }
    if let Some(overlap) = selection
        .include
        .iter()
        .find(|collection| selection.exclude.contains(*collection))
    {
        return Err(ApiError::BadRequest(format!(
            "mongodb remote selection cannot include and exclude the same collection: {overlap}"
        )));
    }
    Ok(selection
        .include
        .iter()
        .map(|collection| Some(collection.as_str()))
        .collect())
}

fn clickhouse_table_selection(selection: &ImportExportSelection) -> (String, String) {
    let source = if selection.mode == SelectionMode::Full {
        "$client --query 'SHOW TABLES FORMAT TSVRaw'".to_string()
    } else {
        format!("printf '%s\\n' {}", sh_quote(&selection.include.join("\n")))
    };
    if selection.exclude.is_empty() {
        return (source, ":".to_string());
    }
    let patterns = selection
        .exclude
        .iter()
        .map(|table| sh_quote(table))
        .collect::<Vec<_>>()
        .join("|");
    (
        source,
        format!("case \"$table\" in {patterns}) continue ;; esac"),
    )
}

fn clickhouse_column_selection(selection: &ImportExportSelection) -> String {
    if selection.fields.is_empty() {
        return "printf '*'".to_string();
    }
    let mut cases = String::from("case \"$table\" in ");
    for (table, fields) in &selection.fields {
        let fields = fields
            .iter()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>()
            .join(", ");
        cases.push_str(&format!(
            "{}) printf '%s' {} ;; ",
            sh_quote(table),
            sh_quote(&fields)
        ));
    }
    cases.push_str("*) printf '*' ;; esac");
    cases
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, ApiError> {
    value.ok_or_else(|| ApiError::BadRequest(format!("remote import requires {field}")))
}

fn required_secret<'a>(
    value: Option<&'a secrecy::SecretString>,
    field: &str,
) -> Result<&'a str, ApiError> {
    value
        .map(ExposeSecret::expose_secret)
        .ok_or_else(|| ApiError::BadRequest(format!("remote import requires {field}")))
}

fn pg_service_value(value: &str) -> Result<String, ApiError> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(ApiError::BadRequest(
            "postgres source fields must not contain line breaks".to_string(),
        ));
    }
    Ok(value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace(' ', "\\ "))
}

fn pgpass_value(value: &str) -> Result<String, ApiError> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(ApiError::BadRequest(
            "postgres pgpass fields must not contain NUL or line breaks".to_string(),
        ));
    }
    Ok(value.replace('\\', "\\\\").replace(':', "\\:"))
}

fn mysql_option_value(value: &str) -> Result<String, ApiError> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(ApiError::BadRequest(
            "mysql source fields must not contain line breaks".to_string(),
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn portable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_file_escapes_quotes_and_backslashes() {
        assert_eq!(mysql_option_value("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn pgpass_escapes_field_separators() {
        assert_eq!(pgpass_value(r"a:b\c").unwrap(), r"a\:b\\c");
    }

    #[test]
    fn pgpass_rejects_line_and_nul_injection() {
        for value in ["secret\nother", "secret\rother", "secret\0other"] {
            assert!(matches!(pgpass_value(value), Err(ApiError::BadRequest(_))));
        }
    }

    #[test]
    fn generated_scripts_do_not_contain_passwords() {
        let source = RemoteImportSource {
            endpoint: super::super::security::ResolvedRemoteEndpoint {
                host: "db.example.com".to_string(),
                port: 5432,
                addresses: vec!["203.0.113.5:5432".parse().unwrap()],
                tls: true,
            },
            database: Some("app".to_string()),
            username: Some("operator".to_string()),
            password: Some(secrecy::SecretString::from("do-not-leak")),
            authentication_database: None,
            database_index: 0,
            api_key: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let script = runtime
            .block_on(prepare_postgres(
                &source,
                &ImportExportSelection::default(),
                dir.path(),
                37,
            ))
            .unwrap();
        assert!(!script.contains("do-not-leak"));
        assert!(script.contains("sslrootcert=/etc/ssl/certs/ca-certificates.crt"));
        assert!(script.contains("--format=custom"));
        assert!(script.contains("pg_restore --list"));
        assert!(script.contains("--clean --if-exists"));
        assert!(script.contains(&sh_quote(POSTGRES_TOC_FILTER_PROGRAM)));
        assert!(script.contains("CREATE SCHEMA IF NOT EXISTS"));
        let service = std::fs::read_to_string(dir.path().join("pg_service.conf")).unwrap();
        assert!(service.contains("connect_timeout=37"));
    }

    #[test]
    fn mysql_dump_scripts_end_options_before_database_and_tables() {
        let source = RemoteImportSource {
            endpoint: super::super::security::ResolvedRemoteEndpoint {
                host: "db.example.com".to_string(),
                port: 3306,
                addresses: vec!["203.0.113.5:3306".parse().unwrap()],
                tls: false,
            },
            database: Some("-app".to_string()),
            username: Some("operator".to_string()),
            password: Some(secrecy::SecretString::from("secret")),
            authentication_database: None,
            database_index: 0,
            api_key: None,
        };
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["-events".to_string()],
            exclude: vec!["legacy".to_string()],
            ..ImportExportSelection::default()
        };
        let mysql_dir = tempfile::tempdir().unwrap();
        let mariadb_dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mysql = runtime
            .block_on(prepare_mysql(
                &source,
                &selection,
                "target_user",
                mysql_dir.path(),
                23,
            ))
            .unwrap();
        let mariadb = runtime
            .block_on(prepare_mariadb(&source, &selection, mariadb_dir.path(), 23))
            .unwrap();

        for script in [&mysql, &mariadb] {
            let ignore = script.find("--ignore-table='-app.legacy'").unwrap();
            let positionals = script.find("-- '-app' '-events'").unwrap();
            assert!(ignore < positionals);
            assert!(script.contains("--triggers"));
            assert!(!script.contains("--routines"));
            assert!(!script.contains("--events --triggers"));
            assert!(
                !script.contains("sed -E 's/DEFINER="),
                "a global DEFINER replacement can corrupt ordinary INSERT values"
            );
        }
        assert!(mysql.contains("DEFINER=`target_user`@`%`"));
        assert!(mysql.contains(&sh_quote(MYSQL_TARGET_DEFINER_AWK_PROGRAM)));
        assert!(
            mariadb.contains(&sh_quote(MYSQL_DEFINER_SED_PROGRAM)),
            "mariadb restores as its tenant and strips source definers"
        );
        for directory in [&mysql_dir, &mariadb_dir] {
            let config = std::fs::read_to_string(directory.path().join("client.cnf")).unwrap();
            assert!(config.contains("connect-timeout=23"));
        }
    }

    #[test]
    fn full_mysql_dumps_include_database_wide_objects_but_selective_dumps_do_not() {
        let full = ImportExportSelection::default();
        let selective = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string()],
            ..ImportExportSelection::default()
        };

        assert_eq!(mysql_database_object_args(&full), " --routines --events");
        assert_eq!(mysql_database_object_args(&selective), "");
    }

    #[test]
    fn mysql_selection_rejects_a_different_database_qualifier() {
        let mismatched = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["other.orders".to_string()],
            ..ImportExportSelection::default()
        };
        assert!(matches!(
            mysql_selection_args(&mismatched, "app", "--ignore-table"),
            Err(ApiError::BadRequest(_))
        ));

        let matched = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["app.orders".to_string()],
            exclude: vec!["app.audit".to_string()],
            ..ImportExportSelection::default()
        };
        let (filters, tables) = mysql_selection_args(&matched, "app", "--ignore-table").unwrap();
        assert!(filters.contains("--ignore-table='app.audit'"));
        assert_eq!(tables, " 'orders'");
    }

    #[cfg(unix)]
    #[test]
    fn mariadb_definer_filter_preserves_insert_values() {
        let fixture = concat!(
            "INSERT INTO `payloads` VALUES ('DEFINER=`x`@`y` ',",
            "'/*!50017 DEFINER=`x`@`y`*/');\n",
            "/*!50003 CREATE*/ /*!50017 DEFINER=`admin`@`%`*/ ",
            "/*!50003 TRIGGER `audit` BEFORE INSERT ON `items` FOR EACH ROW ",
            "SET @x='/*!50017 DEFINER=`literal`@`value`*/' */;;\n",
            "/*M!100301 CREATE*/ /*M!100301 DEFINER=`maria_admin`@`localhost`*/ ",
            "/*M!100301 TRIGGER `maria_audit` BEFORE UPDATE ON `items` FOR EACH ROW ",
            "SET @x='/*M!100301 DEFINER=`literal`@`value`*/' */;;\n",
            "CREATE DEFINER=`admin`@`%` VIEW `items_view` AS SELECT 1;\n",
            "ALTER ALGORITHM=UNDEFINED DEFINER=`admin`@`%` VIEW `other_view` AS SELECT 2;\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("dump.sql");
        std::fs::write(&input, fixture).unwrap();
        let output = std::process::Command::new("sed")
            .arg("-E")
            .arg(MYSQL_DEFINER_SED_PROGRAM)
            .arg("--")
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "sed failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let filtered = String::from_utf8(output.stdout).unwrap();

        assert!(filtered.contains(
            "INSERT INTO `payloads` VALUES ('DEFINER=`x`@`y` ',\
'/*!50017 DEFINER=`x`@`y`*/');"
        ));
        assert!(filtered.contains("/*!50003 CREATE*/ /*!50017 */"));
        assert!(filtered.contains("'/*!50017 DEFINER=`literal`@`value`*/'"));
        assert!(filtered.contains("/*M!100301 CREATE*/ /*M!100301 */"));
        assert!(filtered.contains("'/*M!100301 DEFINER=`literal`@`value`*/'"));
        assert!(filtered.contains("CREATE VIEW `items_view`"));
        assert!(filtered.contains("ALTER ALGORITHM=UNDEFINED VIEW `other_view`"));
    }

    #[cfg(unix)]
    #[test]
    fn mysql_definer_filter_rewrites_every_supported_object_to_the_target_tenant() {
        let fixture = concat!(
            "INSERT INTO `payloads` VALUES ('DEFINER=`literal`@`value`');\n",
            "/*!50003 CREATE*/ /*!50017 DEFINER=`source`@`localhost`*/ ",
            "/*!50003 TRIGGER `audit` BEFORE INSERT ON `items` FOR EACH ROW SET @x=1 */;;\n",
            "CREATE DEFINER=`source`@`localhost` PROCEDURE `refresh_items`() SELECT 1;\n",
            "CREATE DEFINER=`source`@`localhost` FUNCTION `item_count`() RETURNS INT RETURN 1;\n",
            "/*!50106 CREATE*/ /*!50117 DEFINER=`source`@`localhost`*/ ",
            "/*!50106 EVENT `nightly` ON SCHEDULE EVERY 1 DAY DO SELECT 1 */;;\n",
            "CREATE ALGORITHM=UNDEFINED DEFINER=`source`@`localhost` ",
            "SQL SECURITY DEFINER VIEW `items_view` AS SELECT 1;\n",
            "ALTER ALGORITHM=UNDEFINED DEFINER=`source`@`localhost` ",
            "VIEW `other_view` AS SELECT 2;\n",
            "/*!50001 CREATE ALGORITHM=UNDEFINED */\n",
            "/*!50013 DEFINER=`source`@`localhost` SQL SECURITY DEFINER */\n",
            "/*!50001 VIEW `versioned_view` AS SELECT 3 */;\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("dump.sql");
        let output = directory.path().join("filtered.sql");
        std::fs::write(&input, fixture).unwrap();
        let script = mysql_target_definer_filter_script(
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            "target_user",
        )
        .unwrap();
        let command = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(
            command.status.success(),
            "filter failed: {}",
            String::from_utf8_lossy(&command.stderr)
        );
        let filtered = std::fs::read_to_string(output).unwrap();

        assert!(filtered.contains("INSERT INTO `payloads` VALUES ('DEFINER=`literal`@`value`');"));
        assert_eq!(filtered.matches("DEFINER=`target_user`@`%`").count(), 7);
        assert!(!filtered.contains("DEFINER=`source`@`localhost`"));
    }

    #[cfg(unix)]
    #[test]
    fn mysql_definer_filter_rejects_an_object_without_an_explicit_definer() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("dump.sql");
        let output = directory.path().join("filtered.sql");
        std::fs::write(
            &input,
            "CREATE SQL SECURITY DEFINER VIEW `unsafe_view` AS SELECT 1;\n",
        )
        .unwrap();
        let script = mysql_target_definer_filter_script(
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            "target_user",
        )
        .unwrap();
        let command = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();

        assert!(!command.status.success());
        assert!(
            String::from_utf8_lossy(&command.stderr).contains("unsupported or unsafe DEFINER form")
        );
    }

    #[cfg(unix)]
    #[test]
    fn postgres_toc_filter_removes_only_structural_schema_entries() {
        let fixture = concat!(
            ";\n",
            "; Archive created at 2026-01-01\n",
            "5; 2615 2200 SCHEMA - app operator\n",
            "125; 1259 12345 TABLE app events operator\n",
            "126; 0 0 TABLE DATA app events operator\n",
            "127; 1255 456 FUNCTION app dangerous() operator\n",
        );
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("dump.toc");
        std::fs::write(&input, fixture).unwrap();
        let output = std::process::Command::new("awk")
            .arg(POSTGRES_TOC_FILTER_PROGRAM)
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "awk failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let filtered = String::from_utf8(output.stdout).unwrap();

        assert!(!filtered.contains("SCHEMA - app"));
        assert!(filtered.contains("TABLE app events"));
        assert!(filtered.contains("TABLE DATA app events"));
        assert!(filtered.contains("FUNCTION app dangerous()"));
    }

    #[test]
    fn postgres_schema_query_scopes_selective_imports_without_sql_injection() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["reporting.orders".to_string(), "events".to_string()],
            ..ImportExportSelection::default()
        };

        let query = postgres_schema_creation_query(&selection);

        assert!(query.contains("n.nspname = 'reporting'"));
        assert!(query.contains("c.relname = 'orders'"));
        assert!(query.contains("c.relname = 'events'"));
        assert!(query.contains("CREATE SCHEMA IF NOT EXISTS %I"));
        assert_eq!(postgres_string_literal("x'y"), "'x''y'");
    }

    #[test]
    fn selective_postgres_dump_requires_every_pattern_to_match() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["public.orders".to_string()],
            ..ImportExportSelection::default()
        };

        let args = postgres_selection_args(&selection);

        assert!(args.contains("--strict-names"));
        assert!(args.contains("--table='public.orders'"));
    }

    #[test]
    fn mongodb_output_plan_supports_multiple_collections() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string(), "customers".to_string()],
            exclude: vec!["audit".to_string()],
            ..ImportExportSelection::default()
        };

        let collections = mongodb_selected_collections(&selection).unwrap();
        let names = output_names(Protocol::Mongodb, &selection).unwrap();

        assert_eq!(collections, vec![Some("orders"), Some("customers")]);
        assert_eq!(
            names,
            vec![
                "source.mongodb.0000.archive.gz",
                "source.mongodb.0001.archive.gz"
            ]
        );
    }

    #[test]
    fn mongodb_output_plan_keeps_the_single_archive_name() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string()],
            ..ImportExportSelection::default()
        };

        assert_eq!(
            output_names(Protocol::Mongodb, &selection).unwrap(),
            vec!["source.mongodb.archive.gz"]
        );
        assert_eq!(
            output_names(Protocol::Mongodb, &ImportExportSelection::default()).unwrap(),
            vec!["source.mongodb.archive.gz"]
        );
    }

    #[test]
    fn mongodb_config_uses_the_configured_connection_deadline() {
        let source = RemoteImportSource {
            endpoint: super::super::security::ResolvedRemoteEndpoint {
                host: "mongodb.example.com".to_string(),
                port: 27017,
                addresses: vec!["203.0.113.5:27017".parse().unwrap()],
                tls: true,
            },
            database: Some("app".to_string()),
            username: Some("operator".to_string()),
            password: Some(secrecy::SecretString::from("secret")),
            authentication_database: Some("admin".to_string()),
            database_index: 0,
            api_key: None,
        };
        let directory = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string(), "customers".to_string()],
            ..ImportExportSelection::default()
        };
        let planned_output_names = output_names(Protocol::Mongodb, &selection).unwrap();

        let script = runtime
            .block_on(prepare_mongodb(
                &source,
                &selection,
                directory.path(),
                &planned_output_names,
                37,
            ))
            .unwrap();

        let client_config =
            std::fs::read_to_string(directory.path().join("mongodump.yml")).unwrap();
        assert!(client_config.contains("directConnection=true"));
        assert!(client_config.contains("connectTimeoutMS=37000"));
        assert!(client_config.contains("serverSelectionTimeoutMS=37000"));
        assert!(client_config.contains("tls=true"));
        assert!(!script.contains("secret"));
        assert_eq!(script.matches("mongodump ").count(), 1);
        assert_eq!(script.matches("dump_collection --collection=").count(), 2);
        assert!(script.contains("--collection='orders'"));
        assert!(script.contains("--collection='customers'"));
        assert!(script.contains("/work/source.mongodb.0000.archive.gz"));
        assert!(script.contains("/work/source.mongodb.0001.archive.gz"));

        let maximum_selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: (0..512)
                .map(|index| format!("collection_{index:04}_{}", "x".repeat(110)))
                .collect(),
            ..ImportExportSelection::default()
        };
        let maximum_output_names = output_names(Protocol::Mongodb, &maximum_selection).unwrap();
        let maximum_script = runtime
            .block_on(prepare_mongodb(
                &source,
                &maximum_selection,
                directory.path(),
                &maximum_output_names,
                37,
            ))
            .unwrap();
        assert_eq!(
            maximum_script
                .matches("dump_collection --collection=")
                .count(),
            512
        );
        assert!(maximum_script.len() < 256 * 1024);
    }

    #[test]
    fn clickhouse_script_uses_a_portable_engine_allowlist() {
        let source = RemoteImportSource {
            endpoint: super::super::security::ResolvedRemoteEndpoint {
                host: "clickhouse.example.com".to_string(),
                port: 9440,
                addresses: vec!["203.0.113.5:9440".parse().unwrap()],
                tls: true,
            },
            database: Some("app".to_string()),
            username: Some("operator".to_string()),
            password: Some(secrecy::SecretString::from("secret")),
            authentication_database: None,
            database_index: 0,
            api_key: None,
        };
        let directory = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let script = runtime
            .block_on(prepare_clickhouse(
                &source,
                &ImportExportSelection::default(),
                directory.path(),
                37,
            ))
            .unwrap();

        assert!(script.contains("MergeTree|ReplacingMergeTree|SummingMergeTree"));
        assert!(script.contains("|Log|TinyLog|StripeLog|Memory)"));
        assert!(script.contains("unsupported or non-portable table engine"));
        assert!(!script.contains("ENGINE[[:space:]]*=[[:space:]]*(URL|"));
        let client_config =
            std::fs::read_to_string(directory.path().join("clickhouse-client.xml")).unwrap();
        assert!(client_config.contains("<loadDefaultCAFile>true</loadDefaultCAFile>"));
        assert!(client_config.contains("<verificationMode>strict</verificationMode>"));
        assert!(client_config.contains("<name>RejectCertificateHandler</name>"));
        assert!(client_config.contains("<connect_timeout>37</connect_timeout>"));
    }

    #[cfg(unix)]
    #[test]
    fn clickhouse_engine_parser_accepts_exactly_one_line_anchored_clause() {
        let parse = |show_create: &str| {
            std::process::Command::new("awk")
                .arg(CLICKHOUSE_ENGINE_AWK_PROGRAM)
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write as _;

                    child
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(show_create.as_bytes())?;
                    child.wait_with_output()
                })
                .unwrap()
        };

        let allowed =
            parse("CREATE TABLE `events`\n(\n  `id` UInt64\n)\nENGINE = MergeTree\nORDER BY id\n");
        assert!(allowed.status.success());
        assert_eq!(
            String::from_utf8(allowed.stdout).unwrap().trim(),
            "MergeTree"
        );

        let deceptive = parse(
            "CREATE TABLE `events`\n(\n  `payload` String DEFAULT 'ENGINE = MergeTree'\n)\nCOMMENT 'ENGINE = MergeTree'\nENGINE = URL('https://example.invalid')\n",
        );
        assert!(deceptive.status.success());
        assert_eq!(String::from_utf8(deceptive.stdout).unwrap().trim(), "URL");

        assert!(
            !parse("CREATE TABLE `events` (`id` UInt64)\n")
                .status
                .success()
        );
        assert!(
            !parse("CREATE TABLE `events` (`id` UInt64)\nENGINE = MergeTree\nENGINE = Memory\n")
                .status
                .success()
        );
    }

    #[cfg(unix)]
    #[test]
    fn clickhouse_show_create_rebases_quoted_and_unquoted_database_names() {
        for fixture in [
            "CREATE TABLE app.orders\n(\n    `id` UInt64\n)\nENGINE = MergeTree ORDER BY id",
            "CREATE TABLE `app`.`orders`\n(\n    `id` UInt64\n)\nENGINE = MergeTree ORDER BY id",
        ] {
            let command = format!(
                "set -eu\ndatabase=app\ntable=orders\ncreate=\"$CREATE_FIXTURE\"\n{}",
                CLICKHOUSE_REBASE_CREATE_SCRIPT
            );
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .env("CREATE_FIXTURE", fixture)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "rebase failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = String::from_utf8(output.stdout).unwrap();
            assert!(output.starts_with("CREATE TABLE `orders`\n("));
            assert!(!output.contains("CREATE TABLE app.orders"));
            assert!(!output.contains("CREATE TABLE `app`.`orders`"));
        }
    }
}
