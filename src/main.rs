#[cfg(not(target_os = "linux"))]
compile_error!(
    "dbev supports Linux targets only; cross-compile it for Linux instead of building a Windows executable"
);

#[cfg(target_os = "linux")]
const RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use databases_everywhere::commands;

    commands::set_safe_umask();

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| {
            let result = runtime.block_on(commands::run());
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
            result
        });
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            commands::report_error(&error);
            std::process::ExitCode::FAILURE
        }
    }
}
