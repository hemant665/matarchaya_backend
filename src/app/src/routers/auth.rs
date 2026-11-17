use actix_web::{
    middleware::from_fn,
    web::{self, ServiceConfig},
};
use auth::api::{
    controllers::auth_handler::{
        login_handler, logout_handler, me_handler, refresh_handler,
    },
    middlewares::jwt_extractor::check_permission_middleware,
};
use base::error::json_error_handler;

/// Auth routes:
///
/// * `POST /auth/login`   public: email + password
/// * `POST /auth/refresh` public: authenticated by the refresh-token cookie
/// * `POST /auth/logout`  requires the `user` permission
/// * `GET  /auth/me`      requires the `user` permission
pub fn auth_routes(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(
                web::resource("/login")
                    // A login body is tiny; refuse anything larger early.
                    .app_data(
                        web::JsonConfig::default()
                            .limit(4 * 1024)
                            .error_handler(json_error_handler),
                    )
                    .route(web::post().to(login_handler)),
            )
            .service(
                web::resource("/refresh")
                    .route(web::post().to(refresh_handler)),
            )
            .service(
                web::resource("/logout")
                    .wrap(from_fn(|req, next| async move {
                        check_permission_middleware(req, next, "user").await
                    }))
                    .route(web::post().to(logout_handler)),
            )
            .service(
                web::resource("/me")
                    .wrap(from_fn(|req, next| async move {
                        check_permission_middleware(req, next, "user").await
                    }))
                    .route(web::get().to(me_handler)),
            ),
    );
}
