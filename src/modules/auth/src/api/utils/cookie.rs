use actix_web::cookie::{Cookie, SameSite, time::Duration};

use crate::config::AuthConfig;

/// The refresh-token cookie: unreadable by page scripts (`HttpOnly`) and only
/// sent to the auth routes (`Path`).
///
/// Secure mode uses `SameSite=None` so a frontend on another site can use it
/// over HTTPS. Plain-http dev falls back to `Lax`, because browsers reject
/// `SameSite=None` without `Secure`.
pub fn refresh_cookie(config: &AuthConfig, token: &str) -> Cookie<'static> {
    let same_site = if config.refresh_cookie_secure {
        SameSite::None
    } else {
        SameSite::Lax
    };

    Cookie::build(config.refresh_cookie_name.clone(), token.to_owned())
        .http_only(true)
        .secure(config.refresh_cookie_secure)
        .same_site(same_site)
        .path(config.refresh_cookie_path.clone())
        .max_age(Duration::days(config.refresh_token_ttl_days))
        .finish()
}

/// Expires the cookie. It must carry the same attributes it was set with, or
/// the browser keeps the original.
pub fn removal_cookie(config: &AuthConfig) -> Cookie<'static> {
    let mut cookie = refresh_cookie(config, "");
    cookie.make_removal();
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secure: bool) -> AuthConfig {
        AuthConfig {
            jwt_secret: "x".repeat(32),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 30,
            refresh_cookie_name: "refresh_token".into(),
            refresh_cookie_secure: secure,
            refresh_cookie_path: "/auth".into(),
            bootstrap_admin: None,
        }
    }

    #[test]
    fn secure_cookie_is_http_only_none_samesite_and_scoped() {
        let cookie = refresh_cookie(&config(true), "abc");
        assert_eq!(cookie.name(), "refresh_token");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::None));
        assert_eq!(cookie.path(), Some("/auth"));
        assert_eq!(cookie.max_age(), Some(Duration::days(30)));
    }

    #[test]
    fn insecure_dev_cookie_falls_back_to_lax() {
        let cookie = refresh_cookie(&config(false), "abc");
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn removal_cookie_is_empty_and_expired_with_matching_attributes() {
        let cookie = removal_cookie(&config(true));
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(Duration::ZERO));
        assert_eq!(cookie.path(), Some("/auth"));
        assert_eq!(cookie.http_only(), Some(true));
    }
}
