fn main() -> anyhow::Result<()> {
    databases_everywhere::cli::harden_process_file_creation();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(databases_everywhere::cli::run())
}
