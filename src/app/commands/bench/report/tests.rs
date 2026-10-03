use super::{
    csv::csv_field,
    format::human_bytes,
    markdown::write_recommendation_row,
    reserve_report_directory,
    terminal::{
        TerminalColor, TerminalColors, final_recommendation_row, format_elapsed, grouped_usize,
        truncate,
    },
    write_private,
};

#[test]
fn csv_fields_escape_delimiters_and_quotes() {
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
}

#[test]
fn byte_format_uses_binary_units() {
    assert_eq!(human_bytes(1024), "1.00 KiB");
    assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
}

#[test]
fn terminal_helpers_keep_counts_and_elapsed_time_readable() {
    assert_eq!(grouped_usize(12_345_678), "12,345,678");
    assert_eq!(format_elapsed(90_250.0), "1m 30.2s");
    assert!(
        !TerminalColors { enabled: false }
            .paint(TerminalColor::Green, "ok")
            .contains('\u{1b}')
    );
    assert!(
        TerminalColors { enabled: true }
            .paint(TerminalColor::Green, "ok")
            .contains("\u{1b}[32m")
    );
    assert_eq!(truncate("a-very-long-instance-name", 12), "a-very-lo...");
    assert!(truncate("a-very-long-instance-name", 12).is_ascii());
}

#[test]
fn manual_active_job_recommendation_rows_expose_model_inputs_and_result() {
    let workload = crate::commands::bench::metrics::ManualActiveJobsWorkloadReport {
        workload: "configured maximum upload".to_string(),
        protocol: "mongodb".to_string(),
        mode: "wipe".to_string(),
        compressed: true,
        estimate: crate::commands::bench::metrics::SchedulerJobCostReport {
            input_size_bytes: 4 * 1024 * 1024 * 1024,
            memory_mib: 1024,
            io_mib: 4096,
            cpu_units: 2,
        },
        memory_ceiling_jobs: 8,
        io_ceiling_jobs: 4,
        cpu_ceiling_jobs: 6,
        configured_active_ceiling_jobs: 12,
        recommended_manual_max_active_jobs: 4,
    };

    let mut terminal = String::new();
    final_recommendation_row(&mut terminal, &workload);
    assert!(terminal.contains("configured maximum upload"));
    assert!(terminal.contains("4.00 GiB"));
    assert!(terminal.trim_end().ends_with('4'));

    let mut markdown = String::new();
    write_recommendation_row(&mut markdown, &workload);
    assert!(markdown.contains("| `configured maximum upload` | mongodb | wipe | true |"));
    assert!(markdown.contains("| 1024 | 4096 | 2 | 8 | 4 | 6 | 12 | **4** |"));
}

#[tokio::test]
async fn report_directory_and_files_refuse_reuse() {
    let directory =
        std::env::temp_dir().join(format!("dbev-bench-report-test-{}", uuid::Uuid::new_v4()));
    reserve_report_directory(&directory).unwrap();
    assert!(reserve_report_directory(&directory).is_err());

    let report = directory.join("report.json");
    write_private(&report, b"first").await.unwrap();
    assert!(write_private(&report, b"second").await.is_err());
    assert_eq!(tokio::fs::read(&report).await.unwrap(), b"first");

    tokio::fs::remove_file(report).await.unwrap();
    tokio::fs::remove_dir(directory).await.unwrap();
}
