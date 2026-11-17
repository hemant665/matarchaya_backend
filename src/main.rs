use std::{error::Error, sync::Arc};

use actix_web::HttpServer;
use app::{config::AppConfig, container::Container, create_app::create_app};

async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = AppConfig::from_env()?;
    let container = Arc::new(Container::new(&config).await?);

    let bind = (config.server.address.clone(), config.server.port);
    let origins: Arc<[String]> = config.cors_allowed_origins.clone().into();
    log::info!("Listening on http://{}:{}", bind.0, bind.1);

    HttpServer::new(move || create_app(container.clone(), origins.clone()))
        .bind(bind)?
        .run()
        .await?;
    Ok(())
}

#[actix_web::main]
async fn main() {
    dotenvy::dotenv().ok();
    base::log_config::config_logger();

    // Print a readable message instead of `Error: Custom { .. }`.
    if let Err(err) = run().await {
        log::error!("{err}");
        std::process::exit(1);
    }
}
