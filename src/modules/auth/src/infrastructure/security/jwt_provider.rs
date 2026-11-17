use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
    errors::ErrorKind,
};
use uuid::Uuid;

use crate::application::ports::token_provider::AccessTokenProvider;
use crate::domain::errors::auth_error::AuthError;
use base::jwt_claims::JwtClaims;

/// HS256-signed access tokens.
pub struct JwtAccessTokenProvider {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    ttl: Duration,
}

impl JwtAccessTokenProvider {
    pub fn new(secret: &str, ttl_minutes: i64) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 5;
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
            ttl: Duration::minutes(ttl_minutes),
        }
    }
}

impl AccessTokenProvider for JwtAccessTokenProvider {
    fn issue(&self, user_id: Uuid, role: &str) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = JwtClaims {
            sub: user_id,
            role: role.to_string(),
            iat: now.timestamp(),
            exp: (now + self.ttl).timestamp(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| AuthError::Internal(e.to_string()))
    }

    fn verify(&self, token: &str) -> Result<JwtClaims, AuthError> {
        decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidToken,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trips_claims() {
        let provider = JwtAccessTokenProvider::new(SECRET, 15);
        let id = Uuid::new_v4();

        let token = provider.issue(id, "admin").unwrap();
        let claims = provider.verify(&token).unwrap();

        assert_eq!(claims.sub, id);
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.exp - claims.iat, 15 * 60);
    }

    #[test]
    fn rejects_a_token_signed_with_another_secret() {
        let token =
            JwtAccessTokenProvider::new("another-secret-another-secret-00", 15)
                .issue(Uuid::new_v4(), "admin")
                .unwrap();
        let err = JwtAccessTokenProvider::new(SECRET, 15)
            .verify(&token)
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[test]
    fn rejects_garbage_and_tampered_tokens() {
        let provider = JwtAccessTokenProvider::new(SECRET, 15);
        assert!(matches!(
            provider.verify("garbage").unwrap_err(),
            AuthError::InvalidToken
        ));

        let token = provider.issue(Uuid::new_v4(), "user").unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "eyJzdWIiOiJ4In0"; // different payload, same signature
        assert!(matches!(
            provider.verify(&parts.join(".")).unwrap_err(),
            AuthError::InvalidToken
        ));
    }

    #[test]
    fn reports_expiry_distinctly() {
        // Expired well beyond the 5s leeway.
        let provider = JwtAccessTokenProvider::new(SECRET, -10);
        let token = provider.issue(Uuid::new_v4(), "user").unwrap();
        assert!(matches!(
            provider.verify(&token).unwrap_err(),
            AuthError::TokenExpired
        ));
    }
}
