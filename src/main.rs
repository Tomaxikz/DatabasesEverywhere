#[tokio::main]
async fn main() -> anyhow::Result<()> {
    databases_everywhere::cli::run().await
}
