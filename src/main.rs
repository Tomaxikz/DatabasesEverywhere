#[cfg(not(target_os = "linux"))]
compile_error!(
    "dbev supports Linux targets only; cross-compile it for Linux instead of building a Windows executable"
);

#[cfg(target_os = "linux")]
const RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    databases_everywhere::cli::harden_process_file_creation();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(databases_everywhere::cli::run());
    // Tokio otherwise waits indefinitely for detached blocking work while the runtime drops.
    // Durable jobs are reconciled on the next boot, so the process exit itself must stay bounded.
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}
