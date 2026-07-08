use auth_mini_gateway::auth_mini::AuthMiniClient;
use auth_mini_gateway::config::Config;
use auth_mini_gateway::db::Store;
use auth_mini_gateway::server::run_server;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    Store::initialize(&config.database_path)?;
    let auth_mini = AuthMiniClient::new(config.auth_mini_issuer.clone());

    run_server(config, auth_mini)
}
