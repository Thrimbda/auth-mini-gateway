use auth_mini_gateway::auth_mini::AuthMiniClient;
use auth_mini_gateway::config::Config;
use auth_mini_gateway::db::Store;
use auth_mini_gateway::server::run_server;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let config = Config::from_env()?;
    Store::initialize(&config.database_path)?;
    let auth_mini = Arc::new(AuthMiniClient::new(config.auth_mini_issuer.clone()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(run_server(config, auth_mini))
}
