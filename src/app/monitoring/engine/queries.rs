use std::collections::{HashMap, HashSet};

use super::{Capabilities, CollectError, EngineTotals};
use crate::monitoring::OperationCounts;

pub(crate) fn mysql_prepare_sql() -> &'static str {
    r#"SET SESSION max_execution_time = 3000;
UPDATE performance_schema.setup_consumers
SET ENABLED = 'YES'
WHERE NAME = 'events_statements_cpu';
SELECT '__DBE_CAPS__',
       EXISTS(
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'performance_schema'
             AND table_name = 'events_statements_summary_by_user_by_event_name'
             AND column_name = 'SUM_CPU_TIME'
       ),
       EXISTS(
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'performance_schema'
             AND table_name = 'events_statements_summary_by_user_by_event_name'
             AND column_name = 'MAX_TOTAL_MEMORY'
       );"#
}

pub(crate) fn mysql_collect_sql(capabilities: Capabilities) -> &'static str {
    match (capabilities.cpu, capabilities.memory) {
        (true, true) => {
            "SET SESSION max_execution_time = 3000; SELECT '__DBE_READY__', EXISTS(SELECT 1 FROM performance_schema.setup_consumers WHERE NAME = 'events_statements_cpu' AND ENABLED = 'YES'); SELECT USER, COALESCE(SUM(SUM_CPU_TIME), 0), COALESCE(MAX(MAX_TOTAL_MEMORY), 0) FROM performance_schema.events_statements_summary_by_user_by_event_name WHERE USER IS NOT NULL GROUP BY USER ORDER BY USER;"
        }
        (true, false) => {
            "SET SESSION max_execution_time = 3000; SELECT '__DBE_READY__', EXISTS(SELECT 1 FROM performance_schema.setup_consumers WHERE NAME = 'events_statements_cpu' AND ENABLED = 'YES'); SELECT USER, COALESCE(SUM(SUM_CPU_TIME), 0), NULL FROM performance_schema.events_statements_summary_by_user_by_event_name WHERE USER IS NOT NULL GROUP BY USER ORDER BY USER;"
        }
        (false, true) => {
            "SET SESSION max_execution_time = 3000; SELECT '__DBE_READY__', 1; SELECT USER, NULL, COALESCE(MAX(MAX_TOTAL_MEMORY), 0) FROM performance_schema.events_statements_summary_by_user_by_event_name WHERE USER IS NOT NULL GROUP BY USER ORDER BY USER;"
        }
        (false, false) => "SET SESSION max_execution_time = 3000; SELECT '__DBE_READY__', 1;",
    }
}

pub(crate) fn mariadb_prepare_sql() -> &'static str {
    "SET SESSION max_statement_time = 3; SET GLOBAL userstat = 1; SELECT '__DBE_READY__';"
}

pub(crate) fn mariadb_collect_sql() -> &'static str {
    "SET SESSION max_statement_time = 3; SELECT '__DBE_READY__', @@GLOBAL.userstat; SELECT USER, CPU_TIME FROM information_schema.USER_STATISTICS WHERE USER IS NOT NULL ORDER BY USER;"
}

pub(crate) fn clickhouse_collect_sql() -> &'static str {
    r#"SELECT
    user,
    sum(ProfileEvents['OSCPUVirtualTimeMicroseconds']),
    max(memory_usage),
    countIf(query_kind IN ('Select', 'Show', 'Describe', 'Exists', 'Explain')),
    countIf(query_kind IN ('Insert', 'Update', 'Delete')),
    countIf(query_kind IN ('Create', 'Alter', 'Drop', 'Rename', 'Truncate', 'Attach', 'Detach')),
    countIf(query_kind NOT IN (
        'Select', 'Show', 'Describe', 'Exists', 'Explain',
        'Insert', 'Update', 'Delete',
        'Create', 'Alter', 'Drop', 'Rename', 'Truncate', 'Attach', 'Detach'
    ))
FROM system.query_log
WHERE type = 'QueryFinish'
  AND is_initial_query = 1
  AND user != 'dbe_admin'
  AND toUnixTimestamp64Micro(event_time_microseconds) > {dbe_previous:Int64}
  AND toUnixTimestamp64Micro(event_time_microseconds) <= {dbe_cutoff:Int64}
GROUP BY user
ORDER BY user
FORMAT TabSeparatedRaw;"#
}

pub(crate) fn parse_mysql_capabilities(output: &str) -> Result<Capabilities, CollectError> {
    let fields = output
        .lines()
        .map(str::trim_end)
        .find_map(|line| line.strip_prefix("__DBE_CAPS__\t"))
        .ok_or(CollectError::InvalidOutput)?
        .split('\t')
        .collect::<Vec<_>>();
    if fields.len() != 2 {
        return Err(CollectError::InvalidOutput);
    }
    Ok(Capabilities {
        cpu: parse_flag(fields[0])?,
        memory: parse_flag(fields[1])?,
        operations: false,
    })
}

pub(crate) fn parse_mariadb_ready(output: &str) -> Result<Capabilities, CollectError> {
    if !output.lines().any(|line| line.trim() == "__DBE_READY__") {
        return Err(CollectError::InvalidOutput);
    }
    Ok(Capabilities {
        cpu: true,
        memory: false,
        operations: false,
    })
}

pub(crate) fn parse_mysql_rows(
    output: &str,
    capabilities: Capabilities,
) -> Result<HashMap<String, EngineTotals>, CollectError> {
    parse_rows(ready_rows(output)?, 3, |fields| {
        let cpu_time_micros = if capabilities.cpu {
            parse_picoseconds_micros(fields[1])?
        } else {
            0
        };
        let peak_query_memory_bytes = if capabilities.memory {
            parse_u64(fields[2])?
        } else {
            0
        };
        Ok(EngineTotals {
            cpu_time_micros,
            peak_query_memory_bytes,
            operations: OperationCounts::default(),
        })
    })
}

pub(crate) fn parse_mariadb_rows(
    output: &str,
) -> Result<HashMap<String, EngineTotals>, CollectError> {
    parse_rows(ready_rows(output)?, 2, |fields| {
        Ok(EngineTotals {
            cpu_time_micros: parse_seconds_micros(fields[1])?,
            peak_query_memory_bytes: 0,
            operations: OperationCounts::default(),
        })
    })
}

pub(crate) fn keep_tenant_rows<'a>(
    rows: &mut HashMap<String, EngineTotals>,
    usernames: impl IntoIterator<Item = &'a str>,
) {
    let usernames = usernames.into_iter().collect::<HashSet<_>>();
    rows.retain(|username, _| usernames.contains(username.as_str()));
}

fn parse_clickhouse_rows(output: &str) -> Result<HashMap<String, EngineTotals>, CollectError> {
    parse_rows(output, 7, |fields| {
        Ok(EngineTotals {
            cpu_time_micros: parse_u64(fields[1])?,
            peak_query_memory_bytes: parse_u64(fields[2])?,
            operations: OperationCounts {
                read: parse_u64(fields[3])?,
                write: parse_u64(fields[4])?,
                ddl: parse_u64(fields[5])?,
                other: parse_u64(fields[6])?,
            },
        })
    })
}

pub(super) fn parse_clickhouse_window(
    output: &str,
) -> Result<(u64, HashMap<String, EngineTotals>), CollectError> {
    let (marker, rows) = output.split_once('\n').unwrap_or((output, ""));
    let checkpoint = marker
        .trim_end()
        .strip_prefix("__DBE_CUTOFF__\t")
        .ok_or(CollectError::InvalidOutput)
        .and_then(parse_u64)?;
    Ok((checkpoint, parse_clickhouse_rows(rows)?))
}

fn ready_rows(output: &str) -> Result<&str, CollectError> {
    let (marker, rows) = output.split_once('\n').unwrap_or((output, ""));
    let mut fields = marker.trim_end().split('\t');
    if fields.next() != Some("__DBE_READY__") {
        return Err(CollectError::InvalidOutput);
    }
    let ready = fields
        .next()
        .ok_or(CollectError::InvalidOutput)
        .and_then(parse_flag)?;
    if fields.next().is_some() {
        return Err(CollectError::InvalidOutput);
    }
    ready.then_some(rows).ok_or(CollectError::NotReady)
}

fn parse_rows<F>(
    output: &str,
    expected_fields: usize,
    mut parse: F,
) -> Result<HashMap<String, EngineTotals>, CollectError>
where
    F: FnMut(&[&str]) -> Result<EngineTotals, CollectError>,
{
    let mut rows = HashMap::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.trim_end().split('\t').collect::<Vec<_>>();
        if fields.len() != expected_fields || fields[0].is_empty() {
            return Err(CollectError::InvalidOutput);
        }
        let totals = parse(&fields)?;
        if rows.insert(fields[0].to_string(), totals).is_some() {
            return Err(CollectError::InvalidOutput);
        }
    }
    Ok(rows)
}

fn parse_flag(value: &str) -> Result<bool, CollectError> {
    match value {
        "0" | "NO" | "OFF" => Ok(false),
        "1" | "YES" | "ON" => Ok(true),
        _ => Err(CollectError::InvalidOutput),
    }
}

fn parse_u64(value: &str) -> Result<u64, CollectError> {
    value
        .parse::<u128>()
        .map(|value| value.min(u64::MAX as u128) as u64)
        .map_err(|_| CollectError::InvalidOutput)
}

fn parse_picoseconds_micros(value: &str) -> Result<u64, CollectError> {
    value
        .parse::<u128>()
        .map(|value| (value / 1_000_000).min(u64::MAX as u128) as u64)
        .map_err(|_| CollectError::InvalidOutput)
}

fn parse_seconds_micros(value: &str) -> Result<u64, CollectError> {
    if value.starts_with('-') || value.is_empty() {
        return Err(CollectError::InvalidOutput);
    }
    if value.contains(['e', 'E']) {
        let seconds = value
            .parse::<f64>()
            .map_err(|_| CollectError::InvalidOutput)?;
        if !seconds.is_finite() || seconds < 0.0 {
            return Err(CollectError::InvalidOutput);
        }
        return Ok((seconds * 1_000_000.0).min(u64::MAX as f64) as u64);
    }

    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole = whole
        .parse::<u128>()
        .map_err(|_| CollectError::InvalidOutput)?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CollectError::InvalidOutput);
    }
    let mut micros = 0_u128;
    for byte in fraction.bytes().take(6) {
        micros = micros * 10 + u128::from(byte - b'0');
    }
    for _ in fraction.len().min(6)..6 {
        micros *= 10;
    }
    Ok(whole
        .saturating_mul(1_000_000)
        .saturating_add(micros)
        .min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_preparation_detects_version_specific_columns() {
        assert_eq!(
            parse_mysql_capabilities("__DBE_CAPS__\t1\t0\n").unwrap(),
            Capabilities {
                cpu: true,
                memory: false,
                operations: false,
            }
        );
        assert_eq!(
            parse_mysql_capabilities("notice\n__DBE_CAPS__\t1\t1\n").unwrap(),
            Capabilities {
                cpu: true,
                memory: true,
                operations: false,
            }
        );
        assert!(parse_mysql_capabilities("__DBE_CAPS__\tmaybe\t1").is_err());
        assert!(parse_mysql_capabilities("1\t1").is_err());
    }

    #[test]
    fn mysql_parser_converts_picoseconds_without_float_rounding() {
        let rows = parse_mysql_rows(
            "__DBE_READY__\t1\ntenant_a\t1234567890123\t987654\n",
            Capabilities {
                cpu: true,
                memory: true,
                operations: false,
            },
        )
        .unwrap();
        assert_eq!(rows["tenant_a"].cpu_time_micros, 1_234_567);
        assert_eq!(rows["tenant_a"].peak_query_memory_bytes, 987_654);
    }

    #[test]
    fn mysql_parser_accepts_capability_specific_null_placeholders() {
        let cpu_only = parse_mysql_rows(
            "__DBE_READY__\t1\ntenant_a\t6000000\tNULL\n",
            Capabilities {
                cpu: true,
                memory: false,
                operations: false,
            },
        )
        .unwrap();
        assert_eq!(cpu_only["tenant_a"].cpu_time_micros, 6);
        assert_eq!(cpu_only["tenant_a"].peak_query_memory_bytes, 0);

        let memory_only = parse_mysql_rows(
            "__DBE_READY__\t1\ntenant_a\tNULL\t1024\n",
            Capabilities {
                cpu: false,
                memory: true,
                operations: false,
            },
        )
        .unwrap();
        assert_eq!(memory_only["tenant_a"].cpu_time_micros, 0);
        assert_eq!(memory_only["tenant_a"].peak_query_memory_bytes, 1024);
    }

    #[test]
    fn mariadb_seconds_are_converted_safely() {
        assert_eq!(parse_seconds_micros("12").unwrap(), 12_000_000);
        assert_eq!(
            parse_seconds_micros("0.017637000000000003").unwrap(),
            17_637
        );
        assert_eq!(parse_seconds_micros("1.2").unwrap(), 1_200_000);
        assert_eq!(parse_seconds_micros("1e-6").unwrap(), 1);
        assert!(parse_seconds_micros("-1").is_err());
        assert!(parse_seconds_micros("NaN").is_err());
    }

    #[test]
    fn collection_rejects_a_runtime_that_lost_its_dynamic_accounting_switch() {
        let capabilities = Capabilities {
            cpu: true,
            memory: true,
            operations: false,
        };
        assert!(matches!(
            parse_mysql_rows("__DBE_READY__\t0\n", capabilities),
            Err(CollectError::NotReady)
        ));
        assert!(matches!(
            parse_mariadb_rows("__DBE_READY__\t0\n"),
            Err(CollectError::NotReady)
        ));
        assert!(parse_mariadb_rows("__DBE_READY__\t1\n").is_ok());
    }

    #[test]
    fn clickhouse_parser_keeps_only_aggregate_resource_and_kind_counts() {
        let (checkpoint, rows) = parse_clickhouse_window(
            "__DBE_CUTOFF__\t1777777777777777\ntenant_a\t1500\t4096\t3\t2\t1\t4\n",
        )
        .unwrap();
        assert_eq!(checkpoint, 1_777_777_777_777_777);
        assert_eq!(
            rows["tenant_a"],
            EngineTotals {
                cpu_time_micros: 1500,
                peak_query_memory_bytes: 4096,
                operations: OperationCounts {
                    read: 3,
                    write: 2,
                    ddl: 1,
                    other: 4,
                },
            }
        );
        assert!(parse_clickhouse_rows("tenant_a\tbad\t4096\t3\t2\t1\t4").is_err());
        assert!(
            parse_clickhouse_rows("tenant_a\t1\t2\t3\t4\t5\t6\ntenant_a\t1\t2\t3\t4\t5\t6")
                .is_err()
        );
        assert!(parse_clickhouse_window("tenant_a\t1\t2\t3\t4\t5\t6").is_err());
        assert!(parse_clickhouse_window("__DBE_CUTOFF__\tbad\n").is_err());
    }

    #[test]
    fn sql_collectors_never_select_raw_query_text() {
        for sql in [
            mysql_prepare_sql(),
            mysql_collect_sql(Capabilities {
                cpu: true,
                memory: true,
                operations: false,
            }),
            mariadb_collect_sql(),
            clickhouse_collect_sql(),
        ] {
            let normalized = sql.to_ascii_lowercase();
            assert!(!normalized.contains("digest_text"));
            assert!(!normalized.contains("query_text"));
            assert!(!normalized.contains("client_ip"));
            assert!(!normalized.contains("exception"));
        }
        assert!(!clickhouse_collect_sql().contains("    query,"));
        assert!(mysql_prepare_sql().contains("max_execution_time = 3000"));
        assert!(mariadb_collect_sql().contains("max_statement_time = 3"));
        assert!(clickhouse_collect_sql().contains("event_time_microseconds) >"));
        assert!(clickhouse_collect_sql().contains("{dbe_previous:Int64}"));
        assert!(clickhouse_collect_sql().contains("{dbe_cutoff:Int64}"));
    }
}
