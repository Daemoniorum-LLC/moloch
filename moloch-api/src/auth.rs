//! Authentication and authorization for the API.
//!
//! Supports:
//! - API key authentication
//! - JWT tokens
//! - Rate limiting per key
//! - Permission levels

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use moloch_core::hash;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Authentication configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// JWT secret key.
    pub jwt_secret: String,
    /// JWT token expiration duration.
    pub token_expiration: Duration,
    /// Enable API key authentication.
    pub api_keys_enabled: bool,
    /// Enable JWT authentication.
    pub jwt_enabled: bool,
    /// Rate limit: requests per minute per key.
    pub rate_limit_rpm: u32,
    /// Rate limit window duration.
    pub rate_limit_window: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-me-in-production".to_string(),
            token_expiration: Duration::from_secs(3600), // 1 hour
            api_keys_enabled: true,
            jwt_enabled: true,
            rate_limit_rpm: 1000,
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

/// Permission level for API access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read-only access.
    Read,
    /// Can submit events.
    Write,
    /// Full administrative access.
    Admin,
}

impl Default for Permission {
    fn default() -> Self {
        Permission::Read
    }
}

/// An API key with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// The key ID (not the secret).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Permission level.
    pub permission: Permission,
    /// When the key was created.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    /// When the key expires (None = never).
    #[serde(default, with = "chrono::serde::ts_milliseconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key is active.
    pub active: bool,
}

impl ApiKey {
    /// Create a new API key.
    pub fn new(id: impl Into<String>, name: impl Into<String>, permission: Permission) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            permission,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        }
    }

    /// Set expiration time.
    pub fn expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.expires_at = Some(time);
        self
    }

    /// Check if the key is valid.
    pub fn is_valid(&self) -> bool {
        if !self.active {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if exp < Utc::now() {
                return false;
            }
        }
        true
    }

    /// Check if the key has the required permission.
    pub fn has_permission(&self, required: Permission) -> bool {
        self.permission >= required
    }
}

/// JWT claims for authentication tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user or key ID).
    pub sub: String,
    /// Permission level.
    pub permission: Permission,
    /// Issued at timestamp.
    pub iat: i64,
    /// Expiration timestamp.
    pub exp: i64,
}

impl Claims {
    /// Create new claims.
    pub fn new(subject: impl Into<String>, permission: Permission, expiration: Duration) -> Self {
        let now = Utc::now();
        Self {
            sub: subject.into(),
            permission,
            iat: now.timestamp(),
            exp: (now + expiration).timestamp(),
        }
    }

    /// Check if the claims are expired.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Check if the claims have the required permission.
    pub fn has_permission(&self, required: Permission) -> bool {
        self.permission >= required
    }
}

/// Authentication errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authentication")]
    MissingAuth,

    #[error("invalid API key")]
    InvalidApiKey,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("expired token")]
    ExpiredToken,

    #[error("insufficient permissions")]
    InsufficientPermissions,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("key not found")]
    KeyNotFound,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthError::MissingAuth => StatusCode::UNAUTHORIZED,
            AuthError::InvalidApiKey => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::ExpiredToken => StatusCode::UNAUTHORIZED,
            AuthError::InsufficientPermissions => StatusCode::FORBIDDEN,
            AuthError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            AuthError::KeyNotFound => StatusCode::NOT_FOUND,
        };

        let body = serde_json::json!({
            "error": self.to_string(),
            "code": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}

/// Rate limiter state for a single key.
#[derive(Debug)]
struct RateLimitState {
    /// Request count in current window.
    count: u32,
    /// When the window started.
    window_start: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    fn check(&mut self, limit: u32, window: Duration) -> bool {
        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(self.window_start) >= window {
            self.count = 0;
            self.window_start = now;
        }

        // Check limit
        if self.count >= limit {
            return false;
        }

        self.count += 1;
        true
    }
}

/// Authentication middleware and key management.
pub struct AuthMiddleware {
    config: AuthConfig,
    /// API keys by their hashed secret.
    api_keys: DashMap<String, ApiKey>,
    /// Rate limit state by key ID.
    rate_limits: DashMap<String, RateLimitState>,
    /// JWT encoding key.
    encoding_key: EncodingKey,
    /// JWT decoding key.
    decoding_key: DecodingKey,
}

impl std::fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("config", &self.config)
            .field("api_keys", &self.api_keys.len())
            .field("rate_limits", &self.rate_limits.len())
            .finish_non_exhaustive()
    }
}

impl AuthMiddleware {
    /// Create a new auth middleware.
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            config,
            api_keys: DashMap::new(),
            rate_limits: DashMap::new(),
            encoding_key,
            decoding_key,
        }
    }

    /// Create auth middleware with strict production checks.
    ///
    /// Panics if:
    /// - JWT secret is the default "change-me-in-production"
    /// - JWT secret is shorter than 32 characters
    pub fn new_strict(config: AuthConfig) -> Self {
        if config.jwt_secret == "change-me-in-production" {
            panic!("JWT secret must be changed from default value in production");
        }
        if config.jwt_secret.len() < 32 {
            panic!("JWT secret must be at least 32 characters");
        }
        Self::new(config)
    }

    /// Register an API key.
    pub fn register_key(&self, secret: impl Into<String>, key: ApiKey) {
        let secret = secret.into();
        let hashed = self.hash_key(&secret);
        self.api_keys.insert(hashed, key);
    }

    /// Revoke an API key by its secret.
    pub fn revoke_key(&self, secret: &str) -> Option<ApiKey> {
        let hashed = self.hash_key(secret);
        self.api_keys.remove(&hashed).map(|(_, v)| v)
    }

    /// Get an API key by its secret.
    pub fn get_key(&self, secret: &str) -> Option<ApiKey> {
        let hashed = self.hash_key(secret);
        self.api_keys.get(&hashed).map(|v| v.clone())
    }

    /// Hash an API key for storage using BLAKE3.
    ///
    /// BLAKE3 is cryptographically secure, fast, and produces consistent output.
    /// Returns a 64-character hex string (32 bytes).
    fn hash_key(&self, secret: &str) -> String {
        let h = hash(secret.as_bytes());
        hex::encode(h.as_bytes())
    }

    /// Validate an API key and check rate limits.
    pub fn validate_api_key(&self, secret: &str) -> Result<ApiKey, AuthError> {
        let hashed = self.hash_key(secret);

        // Get the key
        let key = self
            .api_keys
            .get(&hashed)
            .ok_or(AuthError::InvalidApiKey)?
            .clone();

        // Check if valid
        if !key.is_valid() {
            return Err(AuthError::InvalidApiKey);
        }

        // Check rate limit
        let mut rate_limit = self
            .rate_limits
            .entry(key.id.clone())
            .or_insert_with(RateLimitState::new);
        if !rate_limit.check(self.config.rate_limit_rpm, self.config.rate_limit_window) {
            warn!("Rate limit exceeded for key: {}", key.id);
            return Err(AuthError::RateLimitExceeded);
        }

        debug!("API key validated: {}", key.id);
        Ok(key)
    }

    /// Generate a JWT token for a key.
    pub fn generate_token(&self, key: &ApiKey) -> Result<String, AuthError> {
        let claims = Claims::new(&key.id, key.permission, self.config.token_expiration);

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    /// Validate a JWT token.
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let validation = Validation::default();

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let claims = token_data.claims;

        // Check expiration
        if claims.is_expired() {
            return Err(AuthError::ExpiredToken);
        }

        // Check rate limit
        let mut rate_limit = self
            .rate_limits
            .entry(claims.sub.clone())
            .or_insert_with(RateLimitState::new);
        if !rate_limit.check(self.config.rate_limit_rpm, self.config.rate_limit_window) {
            warn!("Rate limit exceeded for token: {}", claims.sub);
            return Err(AuthError::RateLimitExceeded);
        }

        debug!("Token validated for: {}", claims.sub);
        Ok(claims)
    }

    /// Authenticate from an HTTP request.
    pub fn authenticate(&self, authorization: Option<&str>) -> Result<Claims, AuthError> {
        let auth = authorization.ok_or(AuthError::MissingAuth)?;

        if auth.starts_with("Bearer ") {
            // JWT token
            let token = &auth[7..];
            self.validate_token(token)
        } else if auth.starts_with("ApiKey ") {
            // API key
            let key_secret = &auth[7..];
            let key = self.validate_api_key(key_secret)?;
            Ok(Claims::new(
                &key.id,
                key.permission,
                self.config.token_expiration,
            ))
        } else {
            Err(AuthError::MissingAuth)
        }
    }

    /// List all API keys (without secrets).
    pub fn list_keys(&self) -> Vec<ApiKey> {
        self.api_keys
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get rate limit stats for a key.
    pub fn rate_limit_stats(&self, key_id: &str) -> Option<(u32, Duration)> {
        self.rate_limits.get(key_id).map(|state| {
            let remaining = self.config.rate_limit_rpm.saturating_sub(state.count);
            let window_remaining = self
                .config
                .rate_limit_window
                .checked_sub(state.window_start.elapsed())
                .unwrap_or(Duration::ZERO);
            (remaining, window_remaining)
        })
    }
}

/// Authenticated user info extracted from requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// The claims from authentication.
    pub claims: Claims,
}

impl AuthenticatedUser {
    /// Check if the user has read permission.
    pub fn can_read(&self) -> bool {
        self.claims.has_permission(Permission::Read)
    }

    /// Check if the user has write permission.
    pub fn can_write(&self) -> bool {
        self.claims.has_permission(Permission::Write)
    }

    /// Check if the user has admin permission.
    pub fn is_admin(&self) -> bool {
        self.claims.has_permission(Permission::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test-secret-key".to_string(),
            token_expiration: Duration::from_secs(3600),
            api_keys_enabled: true,
            jwt_enabled: true,
            rate_limit_rpm: 10,
            rate_limit_window: Duration::from_secs(60),
        }
    }

    #[test]
    fn test_api_key_creation() {
        let key = ApiKey::new("key-1", "Test Key", Permission::Write);

        assert_eq!(key.id, "key-1");
        assert_eq!(key.name, "Test Key");
        assert_eq!(key.permission, Permission::Write);
        assert!(key.is_valid());
    }

    #[test]
    fn test_api_key_expiration() {
        let expired = ApiKey::new("key-1", "Expired", Permission::Read)
            .expires_at(Utc::now() - chrono::Duration::hours(1));

        assert!(!expired.is_valid());

        let future = ApiKey::new("key-2", "Future", Permission::Read)
            .expires_at(Utc::now() + chrono::Duration::hours(1));

        assert!(future.is_valid());
    }

    #[test]
    fn test_api_key_permissions() {
        let read_key = ApiKey::new("key-1", "Read", Permission::Read);
        let write_key = ApiKey::new("key-2", "Write", Permission::Write);
        let admin_key = ApiKey::new("key-3", "Admin", Permission::Admin);

        // Read key
        assert!(read_key.has_permission(Permission::Read));
        assert!(!read_key.has_permission(Permission::Write));
        assert!(!read_key.has_permission(Permission::Admin));

        // Write key
        assert!(write_key.has_permission(Permission::Read));
        assert!(write_key.has_permission(Permission::Write));
        assert!(!write_key.has_permission(Permission::Admin));

        // Admin key
        assert!(admin_key.has_permission(Permission::Read));
        assert!(admin_key.has_permission(Permission::Write));
        assert!(admin_key.has_permission(Permission::Admin));
    }

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new("user-1", Permission::Write, Duration::from_secs(3600));

        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.permission, Permission::Write);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_auth_middleware_api_key() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Write);
        auth.register_key("secret-123", key);

        // Valid key
        let result = auth.validate_api_key("secret-123");
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.id, "key-1");

        // Invalid key
        let result = auth.validate_api_key("wrong-secret");
        assert!(matches!(result, Err(AuthError::InvalidApiKey)));
    }

    #[test]
    fn test_auth_middleware_jwt() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Write);

        // Generate token
        let token = auth.generate_token(&key).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = auth.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "key-1");
        assert_eq!(claims.permission, Permission::Write);
    }

    #[test]
    fn test_auth_middleware_rate_limit() {
        let mut config = make_config();
        config.rate_limit_rpm = 3;
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Read);
        auth.register_key("secret-123", key);

        // First 3 requests should succeed
        for _ in 0..3 {
            let result = auth.validate_api_key("secret-123");
            assert!(result.is_ok());
        }

        // 4th request should be rate limited
        let result = auth.validate_api_key("secret-123");
        assert!(matches!(result, Err(AuthError::RateLimitExceeded)));
    }

    #[test]
    fn test_auth_middleware_revoke_key() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Write);
        auth.register_key("secret-123", key);

        // Key works
        assert!(auth.validate_api_key("secret-123").is_ok());

        // Revoke
        let revoked = auth.revoke_key("secret-123");
        assert!(revoked.is_some());

        // Key no longer works
        assert!(auth.validate_api_key("secret-123").is_err());
    }

    #[test]
    fn test_authenticate_bearer() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Write);
        let token = auth.generate_token(&key).unwrap();

        let result = auth.authenticate(Some(&format!("Bearer {}", token)));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "key-1");
    }

    #[test]
    fn test_authenticate_api_key() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let key = ApiKey::new("key-1", "Test Key", Permission::Write);
        auth.register_key("secret-123", key);

        let result = auth.authenticate(Some("ApiKey secret-123"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "key-1");
    }

    #[test]
    fn test_authenticate_missing() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let result = auth.authenticate(None);
        assert!(matches!(result, Err(AuthError::MissingAuth)));
    }

    #[test]
    fn test_list_keys() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        auth.register_key("secret-1", ApiKey::new("key-1", "Key 1", Permission::Read));
        auth.register_key("secret-2", ApiKey::new("key-2", "Key 2", Permission::Write));

        let keys = auth.list_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_authenticated_user_permissions() {
        let claims = Claims::new("user-1", Permission::Write, Duration::from_secs(3600));
        let user = AuthenticatedUser { claims };

        assert!(user.can_read());
        assert!(user.can_write());
        assert!(!user.is_admin());
    }

    // ===== TDD Tests for Cryptographic API Key Hashing =====

    #[test]
    fn test_hash_key_is_consistent() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        // Hash should be consistent for same input
        let hash1 = auth.hash_key("my-secret-key");
        let hash2 = auth.hash_key("my-secret-key");
        assert_eq!(hash1, hash2, "same input should produce same hash");
    }

    #[test]
    fn test_hash_key_is_cryptographic_length() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let hash = auth.hash_key("my-secret-key");

        // BLAKE3 hex is 64 chars, Argon2 PHC is ~97+ chars
        // Current SipHash is only 16 chars - this test should FAIL initially
        assert!(
            hash.len() >= 64,
            "hash should be at least 32 bytes (64 hex chars), got {} chars",
            hash.len()
        );
    }

    #[test]
    fn test_hash_key_different_inputs_different_outputs() {
        let config = make_config();
        let auth = AuthMiddleware::new(config);

        let hash1 = auth.hash_key("secret-key-1");
        let hash2 = auth.hash_key("secret-key-2");
        assert_ne!(
            hash1, hash2,
            "different inputs should produce different hashes"
        );
    }

    // ===== TDD Tests for JWT Secret Production Guard =====

    #[test]
    #[should_panic(expected = "JWT secret must be changed")]
    fn test_default_jwt_secret_panics_in_strict_mode() {
        let config = AuthConfig::default();
        let _auth = AuthMiddleware::new_strict(config);
    }

    #[test]
    #[should_panic(expected = "JWT secret must be at least 32 characters")]
    fn test_short_jwt_secret_panics_in_strict_mode() {
        let mut config = AuthConfig::default();
        config.jwt_secret = "too-short".to_string();
        let _auth = AuthMiddleware::new_strict(config);
    }

    #[test]
    fn test_valid_jwt_secret_works_in_strict_mode() {
        let mut config = AuthConfig::default();
        config.jwt_secret = "my-secure-production-secret-at-least-32-characters-long".to_string();
        let auth = AuthMiddleware::new_strict(config);

        // Should not panic, and should work
        let key = ApiKey::new("test", "Test", Permission::Read);
        assert!(auth.generate_token(&key).is_ok());
    }
}
