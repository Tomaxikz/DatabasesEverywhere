use std::path::Path;

use crate::{
    routes::http::response::ApiError,
    subsystems::import_export::{ImportExportSelection, SelectionMode},
    utils::shell::sh_quote,
};

use super::{
    super::{RemoteImportSource, write_private_file},
    contains_nul_or_line_break, required, required_secret,
};

pub(super) async fn prepare_mariadb(
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
    let database_objects = mysql_extra_args(selection);
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

pub(super) async fn prepare_mysql(
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
    let database_objects = mysql_extra_args(selection);
    let definer_filter = mysql_definer_filter(
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
pub(super) enum MysqlFlavor {
    Mariadb,
    Mysql,
}

pub(super) async fn write_mysql_option_file(
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

pub(super) fn mysql_selection_args(
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

pub(super) fn mysql_selection_table<'a>(
    item: &'a str,
    database: &str,
) -> Result<&'a str, ApiError> {
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

pub(super) fn mysql_extra_args(selection: &ImportExportSelection) -> &'static str {
    if selection.mode == SelectionMode::Full {
        " --routines --events"
    } else {
        ""
    }
}

pub(super) const MYSQL_DEFINER_SED_PROGRAM: &str = r#"/^[[:space:]]*\/\*(M)?!/ {
s#(/\*(M)?![0-9]*[[:space:]]+)DEFINER=`([^`]|``)*`@`([^`]|``)*`[[:space:]]*#\1#
}
/^[[:space:]]*(CREATE|ALTER)[[:space:]]/ {
s#^([[:space:]]*(CREATE|ALTER)[[:space:]]+((OR[[:space:]]+REPLACE|ALGORITHM=[^[:space:]]+)[[:space:]]+)*)DEFINER=`([^`]|``)*`@`([^`]|``)*`[[:space:]]*#\1#
}"#;

pub(super) const MYSQL_TARGET_DEFINER_AWK_PROGRAM: &str = r#"
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

pub(super) fn mysql_definer_filter_script(input: &str, output: &str) -> String {
    format!(
        "sed -E {} -- {} > {}\n",
        sh_quote(MYSQL_DEFINER_SED_PROGRAM),
        sh_quote(input),
        sh_quote(output)
    )
}

pub(super) fn is_safe_definer_username(username: &str) -> bool {
    let mut bytes = username.bytes();
    let starts_with_letter = bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic());
    let rest_is_portable =
        bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    username.len() <= MAX_DEFINER_USERNAME_BYTES && starts_with_letter && rest_is_portable
}

pub(super) const MAX_DEFINER_USERNAME_BYTES: usize = 63;

pub(super) fn mysql_definer_filter(
    input: &str,
    output: &str,
    target_username: &str,
) -> Result<String, ApiError> {
    if !is_safe_definer_username(target_username) {
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

pub(super) fn mysql_option_value(value: &str) -> Result<String, ApiError> {
    if contains_nul_or_line_break(value) {
        return Err(ApiError::BadRequest(
            "mysql source fields must not contain line breaks".to_string(),
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
