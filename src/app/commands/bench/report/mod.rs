use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use anyhow::Context;
use tokio::io::AsyncWriteExt;

use super::metrics::{BenchmarkReport, RequestSample, ResourceSample};

mod csv;
mod format;
mod markdown;
mod terminal;
#[cfg(test)]
mod tests;

pub(super) use self::terminal::print_terminal_report;
use self::{
    csv::{request_samples_csv, resource_samples_csv},
    markdown::markdown_report,
};

pub(super) struct ReportPaths {
    pub directory: PathBuf,
    pub json: PathBuf,
    pub markdown: PathBuf,
    pub request_samples: PathBuf,
    pub resource_samples: PathBuf,
    pub diagnostics: PathBuf,
}

pub(super) fn reserve_report_directory(output_dir: &Path) -> anyhow::Result<()> {
    if let Some(parent) = output_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create benchmark report parent {}",
                parent.display()
            )
        })?;
    }
    match std::fs::create_dir(output_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "benchmark refuses to reuse report directory {}",
                output_dir.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to create benchmark report directory {}",
                    output_dir.display()
                )
            });
        }
    }
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to secure benchmark report directory {}",
                    output_dir.display()
                )
            },
        )?;
    }
    Ok(())
}

pub(super) async fn write_reports(
    output_dir: &Path,
    report: &BenchmarkReport,
    request_samples: &[RequestSample],
    resource_samples: &[ResourceSample],
) -> anyhow::Result<ReportPaths> {
    let metadata = tokio::fs::symlink_metadata(output_dir)
        .await
        .with_context(|| {
            format!(
                "failed to inspect benchmark report directory {}",
                output_dir.display()
            )
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "benchmark report path is not a real directory: {}",
            output_dir.display()
        );
    }
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| {
                format!(
                    "failed to secure benchmark report directory {}",
                    output_dir.display()
                )
            })?;
    }

    let paths = ReportPaths {
        directory: output_dir.to_path_buf(),
        json: output_dir.join("report.json"),
        markdown: output_dir.join("report.md"),
        request_samples: output_dir.join("request-samples.csv"),
        resource_samples: output_dir.join("resource-samples.csv"),
        diagnostics: output_dir.join("diagnostics.log"),
    };
    let json = serde_json::to_vec_pretty(report).context("failed to serialize benchmark report")?;
    let markdown = markdown_report(report);
    let request_csv = request_samples_csv(request_samples);
    let resource_csv = resource_samples_csv(resource_samples);
    let diagnostics = diagnostics_log(report);

    write_private(&paths.json, &json).await?;
    write_private(&paths.markdown, markdown.as_bytes()).await?;
    write_private(&paths.request_samples, request_csv.as_bytes()).await?;
    write_private(&paths.resource_samples, resource_csv.as_bytes()).await?;
    write_private(&paths.diagnostics, diagnostics.as_bytes()).await?;
    Ok(paths)
}

async fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .with_context(|| format!("refused to overwrite {}", path.display()))?;
    file.write_all(contents)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.flush()
        .await
        .with_context(|| format!("failed to flush {}", path.display()))?;
    drop(file);
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .with_context(|| format!("failed to secure {}", path.display()))?;
    }
    Ok(())
}

fn diagnostics_log(report: &BenchmarkReport) -> String {
    let mut output = String::new();
    for warning in &report.warnings {
        let _ = writeln!(output, "WARN {warning}");
    }
    for error in &report.errors {
        let _ = writeln!(output, "ERROR {error}");
    }
    if output.is_empty() {
        output.push_str("No benchmark warnings or errors.\n");
    }
    output
}
