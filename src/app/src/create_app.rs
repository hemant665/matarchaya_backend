use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{
    App, Error,
    body::MessageBody,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    web,
};
use base::{error::json_error_handler, log_config::log_format_config};

use crate::container::Container;
use crate::routers::{auth, health};

fn cors_config(allowed_origins: &[String]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        .allowed_headers(["Authorization", "Accept", "Content-Type"])
        // Needed for the refresh-token cookie to travel cross-origin.
        .supports_credentials()
        .max_age(3600);

    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

pub fn create_app(
    container: Arc<Container>,
    cors_allowed_origins: Arc<[String]>,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Response = ServiceResponse<impl MessageBody>,
        Config = (),
        InitError = (),
        Error = Error,
    >,
> {
    App::new()
        .service(health::health)
        // Auth services
        .app_data(web::Data::from(container.auth_service.clone()))
        .app_data(web::Data::new(container.auth_config.clone()))
        // Shared
        .app_data(web::Data::new(container.sqlx_pool.clone()))
        .app_data(web::JsonConfig::default().error_handler(json_error_handler))
        .wrap(cors_config(&cors_allowed_origins))
        .wrap(log_format_config())
        .configure(auth::auth_routes)
}
