//! Token management module.
//!
//! This module provides the core abstractions and types for handling authentication tokens,
//! including creation, validation, and refreshing of access and refresh tokens. It defines
//! the `TokenPair` struct, the `TokenService` trait for token operations, and re-exports
//! submodules for claims and JWT handling.
//!
//! # Overview
//!
//! - **TokenPair**: Represents a pair of access and refresh tokens.
//! - **TokenService**: Trait for generating, validating, and refreshing tokens.
//! - **claims**: Submodule for token claims definitions.
//! - **jwt**: Submodule for JWT-specific logic.
//!
//! # Example
//!
//! ```rust,no_run
//! use authen::core::token::{TokenPair, TokenService};
//! use authen::error::AuthError;
//! # struct MyTokenService;
//! # #[async_trait::async_trait]
//! # impl TokenService for MyTokenService {
//! #     async fn generate_token_pair(&self, user_id: &str) -> Result<TokenPair, AuthError> { todo!() }
//! #     async fn validate_access_token(&self, token: &str) -> Result<Box<dyn authen::core::token::claims::Claims + Send + Sync>, AuthError> { todo!() }
//! #     async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> { todo!() }
//! # }
//! # async fn example() {
//! let service = MyTokenService;
//! let tokens = service.generate_token_pair("user123").await.unwrap();
//! let claims = service.validate_access_token(&tokens.access_token).await.unwrap();
//! let refreshed = service.refresh_access_token(&tokens.refresh_token).await.unwrap();
//! # }
//! ```

use crate::error::AuthError;

/// Represents a pair of authentication tokens.
///
/// This struct contains both the access token and the refresh token as strings.
/// The access token is typically used for authenticating API requests, while the
/// refresh token is used to obtain new access tokens when the current one expires.
///
/// # Fields
///
/// - `access_token`: The short-lived token used for authenticating requests.
/// - `refresh_token`: The long-lived token used to refresh the access token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// Trait for token service operations.
///
/// This trait abstracts the main operations required for token-based authentication systems.
/// Implementors are responsible for generating, validating, and refreshing authentication tokens.
///
/// # Safety
///
/// All methods are asynchronous and must be thread-safe (`Send + Sync`).
///
/// # Example
///
/// ```rust,no_run
/// # use authen::core::token::{TokenPair, TokenService};
/// # use authen::error::AuthError;
/// # struct MyTokenService;
/// # #[async_trait::async_trait]
/// # impl TokenService for MyTokenService {
/// #     async fn generate_token_pair(&self, user_id: &str) -> Result<TokenPair, AuthError> { todo!() }
/// #     async fn validate_access_token(&self, token: &str) -> Result<Box<dyn authen::core::token::claims::Claims + Send + Sync>, AuthError> { todo!() }
/// #     async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> { todo!() }
/// # }
/// ```
#[async_trait::async_trait]
pub trait TokenService: Send + Sync {
    /// Generates a new token pair for a given user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier of the user for whom the tokens are generated.
    ///
    /// # Returns
    ///
    /// * `Ok(TokenPair)` containing the access and refresh tokens if successful.
    /// * `Err(AuthError)` if token generation fails.
    async fn generate_token_pair(&self, user_id: &str) -> Result<TokenPair, AuthError>;

    /// Validates an access token and extracts its claims.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token string to validate.
    ///
    /// # Returns
    ///
    /// * `Ok(Box<dyn Claims>)` containing the extracted claims if the token is valid.
    /// * `Err(AuthError)` if validation fails or the token is invalid/expired.
    async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn crate::core::token::claims::Claims + Send + Sync>, AuthError>;

    /// Refreshes an access token using a refresh token.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The refresh token string used to obtain a new token pair.
    ///
    /// # Returns
    ///
    /// * `Ok(TokenPair)` containing the new access and refresh tokens if successful.
    /// * `Err(AuthError)` if the refresh token is invalid or expired.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>;
}

/// Submodule for default claims for JWTs.
///
/// Contains traits and types for representing and validating claims in tokens.
pub mod claims;

/// Submodule for JWT implementation and utilities.
///
/// Contains logic for encoding, decoding, and verifying JWTs.
pub mod jwt;
