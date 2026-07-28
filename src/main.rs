#[cfg(not(target_os = "linux"))]
compile_error!(
    "dbev supports Linux targets only; cross-compile it for Linux instead of building a Windows executable"
);

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    databases_everywhere::cli::harden_process_file_creation();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(databases_everywhere::cli::run())
}
