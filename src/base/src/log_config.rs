use actix_web::middleware::Logger;

/// Initializes `env_logger`. Honors `RUST_LOG`, defaulting to `info`.
pub fn config_logger() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();
}

/// Access-log middleware. `/health` is excluded so probes don't flood the log.
pub fn log_format_config() -> Logger {
    Logger::new("%a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T")
        .exclude("/health")
}
