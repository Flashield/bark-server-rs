use bark_server_rs::config::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse_args();
    let config = cli.to_config();
    bark_server_rs::run_server(config, bark_server_rs::shutdown_signal()).await
}
