//! JWT token service implementation for authentication and authorization.
//!
//! This module provides a [`JwtTokenService`] struct that implements the [`TokenService`] trait,
//! allowing for the creation, validation, and refreshing of JWT access and refresh tokens.
//!
//! # Features
//! - Configurable access and refresh token durations
//! - Secure token encoding and decoding using HMAC SHA-256
//! - Custom error handling for token operations
//!
//! # Example
//! ```rust,no_run
//! use authen::core::token::jwt::JwtTokenService;
//! let jwt_service = JwtTokenService::new("mysecret", 3600, 86400);
//! ```

use crate::core::token::claims::{AccessTokenClaims, Claims, RefreshTokenClaims};
use crate::core::token::{TokenPair, TokenService};
use crate::error::AuthError;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

/// Service for generating, validating, and refreshing JWT access and refresh tokens.
///
/// This struct encapsulates the cryptographic keys, algorithm, and token durations
/// required for secure JWT operations.
pub struct JwtTokenService {
    /// Key used for encoding (signing) JWTs.
    encoding_key: EncodingKey,
    /// Key used for decoding (verifying) JWTs.
    decoding_key: DecodingKey,
    /// Algorithm used for signing and verifying JWTs.
    algorithm: Algorithm,
    /// Duration (in seconds) for which an access token is valid.
    access_token_duration: u64,
    /// Duration (in seconds) for which a refresh token is valid.
    refresh_token_duration: u64,
}

impl JwtTokenService {
    /// Creates a new [`JwtTokenService`] with the given secret and token durations.
    ///
    /// # Arguments
    /// * `secret` - The secret key used for signing and verifying tokens.
    /// * `access_token_duration` - Access token validity duration in seconds.
    /// * `refresh_token_duration` - Refresh token validity duration in seconds.
    ///
    /// # Example
    /// ```rust,no_run
    /// use authen::core::token::jwt::JwtTokenService;
    /// let service = JwtTokenService::new("mysecret", 3600, 86400);
    /// ```
    pub fn new(secret: &str, access_token_duration: u64, refresh_token_duration: u64) -> Self {
        let key_bytes = secret.as_bytes();

        Self {
            encoding_key: EncodingKey::from_secret(key_bytes),
            decoding_key: DecodingKey::from_secret(key_bytes),
            algorithm: Algorithm::HS256,
            access_token_duration,
            refresh_token_duration,
        }
    }

    /// Returns the current UNIX timestamp in seconds using chrono.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenGeneration`] if the time conversion fails.
    fn current_timestamp() -> Result<usize, AuthError> {
        let now = Utc::now().naive_utc();
        let timestamp = now.and_utc().timestamp();
        if timestamp < 0 {
            Err(AuthError::TokenGeneration(
                "Failed to get current time".to_string(),
            ))
        } else {
            Ok(timestamp as usize)
        }
    }

    /// Generates a signed JWT access token for the given user ID.
    ///
    /// # Arguments
    /// * `user_id` - The user identifier to embed in the token claims.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenGeneration`] if token creation fails.
    fn generate_access_token(&self, user_id: &str) -> Result<String, AuthError> {
        let now = Self::current_timestamp()?;
        let expiration = now + self.access_token_duration as usize;

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
            token_type: "access".to_string(),
        };

        let header = Header::new(self.algorithm);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGeneration(format!("Failed to encode access token: {e}")))
    }

    /// Generates a signed JWT refresh token for the given user ID.
    ///
    /// # Arguments
    /// * `user_id` - The user identifier to embed in the token claims.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenGeneration`] if token creation fails.
    fn generate_refresh_token(&self, user_id: &str) -> Result<String, AuthError> {
        let now = Self::current_timestamp()?;
        let expiration = now + self.refresh_token_duration as usize;

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
            token_type: "refresh".to_string(),
        };

        let header = Header::new(self.algorithm);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGeneration(format!("Failed to encode refresh token: {e}")))
    }

    /// Validates a JWT and deserializes its claims.
    ///
    /// # Type Parameters
    /// * `T` - The type of claims to deserialize (e.g., [`AccessTokenClaims`], [`RefreshTokenClaims`]).
    ///
    /// # Arguments
    /// * `token` - The JWT string to validate and decode.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenExpired`], [`AuthError::InvalidToken`], or [`AuthError::TokenValidation`] on failure.
    fn validate_token<T>(&self, token: &str) -> Result<T, AuthError>
    where
        T: serde::de::DeserializeOwned,
    {
        let validation = Validation::new(self.algorithm);

        decode::<T>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AuthError::InvalidToken("Invalid token format".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AuthError::InvalidToken("Invalid token signature".to_string())
                }
                _ => AuthError::TokenValidation(format!("Token validation failed: {e}")),
            })
    }
}

#[async_trait::async_trait]
impl TokenService for JwtTokenService {
    /// Generates a new access and refresh token pair for the specified user.
    ///
    /// # Arguments
    /// * `user_id` - The user identifier to embed in the token claims.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenGeneration`] if token creation fails.
    async fn generate_token_pair(&self, user_id: &str) -> Result<TokenPair, AuthError> {
        let access_token = self.generate_access_token(user_id)?;
        let refresh_token = self.generate_refresh_token(user_id)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    /// Validates an access token and returns its claims.
    ///
    /// # Arguments
    /// * `token` - The JWT access token string to validate.
    ///
    /// # Errors
    /// Returns [`AuthError::TokenExpired`], [`AuthError::InvalidToken`], or [`AuthError::TokenValidation`] on failure.
    async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn Claims + Send + Sync>, AuthError> {
        let claims: AccessTokenClaims = self.validate_token(token)?;
        Ok(Box::new(claims))
    }

    /// Validates a refresh token and generates a new token pair if valid.
    ///
    /// # Arguments
    /// * `refresh_token` - The JWT refresh token string to validate.
    ///
    /// # Errors
    /// Returns [`AuthError::InvalidToken`] if the token is not a refresh token, or other token errors.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let refresh_claims: RefreshTokenClaims = self.validate_token(refresh_token)?;

        if refresh_claims.token_type != "refresh" {
            return Err(AuthError::InvalidToken(
                "Expected refresh token".to_string(),
            ));
        }

        self.generate_token_pair(&refresh_claims.sub).await
    }
}
