use super::{
    csv::{request_samples_csv, resource_samples_csv},
    markdown::write_recommendation_row,
    reserve_report_directory,
    terminal::{
        TerminalColor, TerminalColors, final_recommendation_row, format_elapsed, grouped_usize,
        truncate,
    },
    write_private,
};

#[test]
fn request_csv_preserves_quoting_precision_and_empty_fields() {
    let sample = crate::commands::bench::metrics::RequestSample {
        phase: "test".into(),
        target: "a,b".into(),
        index: 7,
        duration_micros: 1234,
        status_code: None,
        success: false,
        error: Some("a\"b\r\nc".into()),
    };
    let header = "phase,target,index,duration_micros,duration_ms,status_code,success,error\n";
    assert_eq!(request_samples_csv(&[]).unwrap(), header.as_bytes());
    assert_eq!(
        request_samples_csv(&[sample]).unwrap(),
        format!("{header}test,\"a,b\",7,1234,1.234,,false,\"a\"\"b\r\nc\"\n").as_bytes()
    );
}

#[test]
fn resource_csv_preserves_decimal_precision_and_optional_columns() {
    let sample = crate::commands::bench::metrics::ResourceSample {
        elapsed_ms: 17,
        phase: "steady".into(),
        daemon_cpu_percent: Some(1.25),
        daemon_rss_bytes: Some(4096),
        benchmark_cpu_percent: None,
        benchmark_rss_bytes: None,
        instance_id: Some("db,1".into()),
        instance_protocol: Some("mysql".into()),
        instance_sample_failed: false,
        instance_cpu_percent: Some(0.0),
        instance_memory_bytes: None,
    };
    let header = "elapsed_ms,phase,daemon_cpu_percent,daemon_rss_bytes,benchmark_cpu_percent,benchmark_rss_bytes,instance_id,instance_protocol,instance_sample_failed,instance_cpu_percent,instance_memory_bytes\n";
    assert_eq!(resource_samples_csv(&[]).unwrap(), header.as_bytes());
    assert_eq!(
        resource_samples_csv(&[sample]).unwrap(),
        format!("{header}17,steady,1.250000,4096,,,\"db,1\",mysql,false,0.000000,\n").as_bytes()
    );
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
