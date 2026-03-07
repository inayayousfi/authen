//! # Authentication Service Module
//!
//! This module provides the high-level logic for user authentication, acting as the central point of the crate's interactions.
//! It exposes the [`AuthService`] struct, which aggregates all necessary dependencies and provides methods for user registration,
//! login, token management, and user retrieval. The service is designed to be flexible and extensible, allowing for custom
//! password managers, user repositories, and token services.
//!
//! ## Features
//! - User registration and login
//! - Password verification and management
//! - Token generation, validation, and refresh
//! - User retrieval from tokens
//! - Extensible via dependency injection

use std::sync::Arc;

use crate::{core::user::User, error::AuthError};

/// Represents different authentication methods for login operations.
#[derive(Debug, Clone)]
pub enum LoginMethod {
    /// Login using username/email and password credentials.
    Credentials {
        /// The user identifier (username, email, etc.)
        identifier: String,
        /// The user's plain text password
        password: String,
    },
    /// Login using OAuth2 authorization code flow.
    OAuth2 {
        /// The OAuth2 provider
        provider: crate::core::oauth::store::OAuth2Provider,
        /// The authorization code received from the provider
        code: String,
        /// The state parameter for CSRF protection
        state: String,
    },
}

/// Represents different signup/registration methods.
#[derive(Debug, Clone)]
pub enum SignupMethod {
    /// Register using credentials (username/email and password).
    Credentials {
        /// The user identifier (username, email, etc.)
        identifier: String,
        /// The user's plain text password
        password: String,
    },
    /// Register via OAuth2 (will create account if it doesn't exist).
    OAuth2 {
        /// The OAuth2 provider
        provider: crate::core::oauth::store::OAuth2Provider,
        /// The authorization code received from the provider
        code: String,
        /// The state parameter for CSRF protection
        state: String,
    },
}

/// The main authentication service, aggregating all dependencies and providing high-level authentication logic.
///
/// `AuthService` aggregates the necessary dependencies to perform authentication operations, such as user registration,
/// login, token management, and user retrieval. It is designed to be flexible and allows for custom implementations of
/// password managers, user repositories, and token services.
///
/// # Features
/// - User registration and login
/// - Password verification and management
/// - Token generation, validation, and refresh
/// - User retrieval from tokens
/// - Extensible via dependency injection
///
/// # Examples
/// ```rust
/// use authen::auth_service::AuthService;
/// let service = AuthService::default();
/// ```
///
/// # Errors
/// Most methods return [`AuthError`] on failure.
pub struct AuthService {
    /// Shared configuration and variables for the authentication service.
    pub vars: Arc<crate::core::vars::AuthServiceVariables>,
    /// The password manager responsible for password hashing and verification.
    pub password_manager: Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
    /// The user repository for persistent user management (e.g., database or in-memory store).
    pub persistent_users_manager:
        Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
    /// The token manager responsible for generating and validating authentication tokens.
    pub token_manager: Box<dyn crate::core::token::TokenService + Send + Sync>,
    pub oauth2_manager: Box<dyn crate::core::oauth::OAuth2Service + Send + Sync>,
}

impl Default for AuthService {
    /// Creates a default [`AuthService`] instance using default configuration, Argon2 password manager,
    /// in-memory user repository, JWT token service, and default OAuth2 manager.
    ///
    /// # Returns
    /// Returns a fully initialized [`AuthService`] with default dependencies.
    fn default() -> Self {
        let vars = Arc::new(crate::core::vars::AuthServiceVariables::default());
        Self {
            vars: vars.clone(),
            password_manager: Box::new(crate::core::password::Argon2PasswordManager::default()),
            persistent_users_manager: Box::new(
                crate::core::user::persistence::InMemoryUserRepo::new(),
            ),
            token_manager: Box::new(crate::core::token::jwt::JwtTokenService::new(
                &vars.secret_key,
                vars.token_expiration,
                vars.refresh_token_expiration,
            )),
            oauth2_manager: Box::new(crate::core::oauth::manager::OAuth2Manager::default()),
        }
    }
}

impl AuthService {
    /// Constructs a new [`AuthService`] with the provided dependencies.
    ///
    /// # Arguments
    /// * `vars` - Shared configuration and variables for the authentication service.
    /// * `password_manager` - Optional custom password manager. If `None`, uses Argon2 by default.
    /// * `persistent_users_manager` - Optional custom user repository. If `None`, uses in-memory repository by default.
    /// * `token_manager` - Optional custom token service. If `None`, uses JWT token service by default.
    /// * `oauth2_manager` - Optional custom OAuth2 service. If `None`, uses default OAuth2 manager.
    ///
    /// # Returns
    /// Returns an [`AuthService`] instance on success, or an [`AuthError`] if construction fails.
    pub fn new(
        vars: Arc<crate::core::vars::AuthServiceVariables>,
        password_manager: Option<
            Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
        >,
        persistent_users_manager: Option<
            Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
        >,
        token_manager: Option<Box<dyn crate::core::token::TokenService + Send + Sync>>,
        oauth2_manager: Option<Box<dyn crate::core::oauth::OAuth2Service + Send + Sync>>,
    ) -> Result<Self, AuthError> {
        let pwd_manager = match password_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::password::Argon2PasswordManager::default()),
        };
        let pum = match persistent_users_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::user::persistence::InMemoryUserRepo::new()),
        };
        let tk_manager = match token_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::token::jwt::JwtTokenService::new(
                &vars.secret_key,
                vars.token_expiration,
                vars.refresh_token_expiration,
            )),
        };
        let oauth_manager = match oauth2_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::oauth::manager::OAuth2Manager::default()),
        };

        Ok(AuthService {
            vars,
            password_manager: pwd_manager,
            persistent_users_manager: pum,
            token_manager: tk_manager,
            oauth2_manager: oauth_manager,
        })
    }

    /// Authenticates a user using the specified login method.
    ///
    /// Supports both credentials-based and OAuth2-based login flows.
    ///
    /// # Arguments
    /// * `method` - The authentication method to use for login. See [`LoginMethod`].
    ///
    /// # Returns
    /// Returns a tuple `(User, TokenPair)` if login is successful, or an [`AuthError`] if authentication fails.
    ///
    /// # Errors
    /// Returns [`AuthError::InvalidCredentials`] if credentials are invalid, or other variants for OAuth2 failures.
    pub async fn login(
        &self,
        method: LoginMethod,
    ) -> Result<(User, crate::core::token::TokenPair), AuthError> {
        match method {
            LoginMethod::Credentials {
                identifier,
                password,
            } => {
                // Find user by identifier
                let stored_user = self
                    .persistent_users_manager
                    .get_user_by_identifier(&identifier)
                    .await
                    .ok_or(AuthError::InvalidCredentials)?;

                // Verify the password using the password manager from the service
                let credentials = stored_user
                    .credentials
                    .as_ref()
                    .ok_or(AuthError::InvalidCredentials)?;

                let is_valid = self
                    .password_manager
                    .verify_password(&password, &credentials.password_hash)
                    .await
                    .map_err(|e| {
                        AuthError::PasswordVerificationError(format!(
                            "Password verification failed: {e}"
                        ))
                    })?;

                if !is_valid {
                    return Err(AuthError::InvalidCredentials);
                }

                // Generate tokens
                let tokens = self.get_tokens(stored_user.id.clone()).await?;
                Ok((stored_user, tokens))
            }
            LoginMethod::OAuth2 {
                provider,
                code,
                state,
            } => {
                // Exchange code for token
                let oauth_token = self
                    .exchange_oauth2_code_for_token(provider, &code, &state)
                    .await?;

                // Fetch user info from OAuth provider
                let oauth_user_info = self.fetch_oauth2_user_info(&oauth_token).await?;

                // Try to find existing user by OAuth provider and user ID
                let existing_user = self
                    .persistent_users_manager
                    .get_user_by_oauth_id(provider, &oauth_user_info.provider_user_id)
                    .await;

                let user = if let Some(mut user) = existing_user {
                    // Update OAuth account info
                    user.oauth_accounts.insert(provider, oauth_user_info);
                    user.updated_at = chrono::Utc::now().naive_utc();
                    self.persistent_users_manager.update_user(&user).await?;
                    user
                } else {
                    // Check if user exists by email (if provided)
                    let existing_user_by_email = if let Some(ref email) = oauth_user_info.email {
                        self.persistent_users_manager
                            .get_user_by_identifier(email)
                            .await
                    } else {
                        None
                    };

                    if let Some(mut user) = existing_user_by_email {
                        // Link OAuth account to existing user
                        user.oauth_accounts.insert(provider, oauth_user_info);
                        user.updated_at = chrono::Utc::now().naive_utc();
                        self.persistent_users_manager.update_user(&user).await?;
                        user
                    } else {
                        // Create new user
                        let mut new_user = User {
                            id: uuid::Uuid::new_v4().to_string(),
                            ..User::default()
                        };
                        new_user.oauth_accounts.insert(provider, oauth_user_info);
                        new_user.created_at = chrono::Utc::now().naive_utc();
                        new_user.updated_at = new_user.created_at;

                        self.persistent_users_manager
                            .add_user(new_user.clone())
                            .await?;
                        new_user
                    }
                };

                // Generate tokens for the user
                let tokens = self.get_tokens(user.id.clone()).await?;
                Ok((user, tokens))
            }
        }
    }

    /// Registers a new user using the specified signup method.
    ///
    /// Supports both credentials-based and OAuth2-based registration flows.
    ///
    /// # Arguments
    /// * `method` - The registration method to use for signup. See [`SignupMethod`].
    ///
    /// # Returns
    /// Returns a tuple `(User, TokenPair)` if signup is successful, or an [`AuthError`] if registration fails.
    ///
    /// # Errors
    /// Returns [`AuthError::SignupError`] or other variants for OAuth2 failures.
    pub async fn signup(
        &self,
        method: SignupMethod,
    ) -> Result<(User, crate::core::token::TokenPair), AuthError> {
        match method {
            SignupMethod::Credentials {
                identifier,
                password,
            } => {
                // Create user with credentials
                let user = User::with_plain_password(
                    self.password_manager.as_ref(),
                    uuid::Uuid::new_v4().to_string(),
                    identifier,
                    crate::core::credentials::PlainPassword::new(password),
                )
                .await?;

                // Register the user
                self.persistent_users_manager
                    .add_user(user.clone())
                    .await
                    .map_err(|e| AuthError::SignupError(format!("signup: {e}")))?;

                // Generate tokens
                let tokens = self.get_tokens(user.id.clone()).await?;
                Ok((user, tokens))
            }
            SignupMethod::OAuth2 {
                provider,
                code,
                state,
            } => {
                // Exchange code for token
                let oauth_token = self
                    .exchange_oauth2_code_for_token(provider, &code, &state)
                    .await?;

                // Fetch user info from OAuth provider
                let oauth_user_info = self.fetch_oauth2_user_info(&oauth_token).await?;

                // Try to find existing user by OAuth provider and user ID
                let existing_user = self
                    .persistent_users_manager
                    .get_user_by_oauth_id(provider, &oauth_user_info.provider_user_id)
                    .await;

                let user = if let Some(mut user) = existing_user {
                    // Update OAuth account info
                    user.oauth_accounts.insert(provider, oauth_user_info);
                    user.updated_at = chrono::Utc::now().naive_utc();
                    self.persistent_users_manager.update_user(&user).await?;
                    user
                } else {
                    // Check if user exists by email (if provided)
                    let existing_user_by_email = if let Some(ref email) = oauth_user_info.email {
                        self.persistent_users_manager
                            .get_user_by_identifier(email)
                            .await
                    } else {
                        None
                    };

                    if let Some(mut user) = existing_user_by_email {
                        // Link OAuth account to existing user
                        user.oauth_accounts.insert(provider, oauth_user_info);
                        user.updated_at = chrono::Utc::now().naive_utc();
                        self.persistent_users_manager.update_user(&user).await?;
                        user
                    } else {
                        // Create new user
                        let mut new_user = User {
                            id: uuid::Uuid::new_v4().to_string(),
                            ..User::default()
                        };
                        new_user.oauth_accounts.insert(provider, oauth_user_info);
                        new_user.created_at = chrono::Utc::now().naive_utc();
                        new_user.updated_at = new_user.created_at;

                        self.persistent_users_manager
                            .add_user(new_user.clone())
                            .await?;
                        new_user
                    }
                };

                // Generate tokens for the user
                let tokens = self.get_tokens(user.id.clone()).await?;
                Ok((user, tokens))
            }
        }
    }

    /// Generates a new token pair (access and refresh tokens) for a given user ID.
    ///
    /// # Arguments
    /// * `id` - The user ID for which to generate tokens.
    ///
    /// # Returns
    /// Returns a [`TokenPair`] containing access and refresh tokens, or an [`AuthError`] if generation fails.
    pub async fn get_tokens(&self, id: String) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.generate_token_pair(&id).await
    }

    /// Validates an access token and returns the associated claims.
    ///
    /// # Arguments
    /// * `token` - The access token to validate.
    ///
    /// # Returns
    /// Returns the token claims if valid, or an [`AuthError`] if validation fails.
    pub async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn crate::core::token::claims::Claims + Send + Sync>, AuthError> {
        self.token_manager.validate_access_token(token).await
    }

    /// Refreshes an access token using a valid refresh token.
    ///
    /// # Arguments
    /// * `refresh_token` - The refresh token to use for generating a new access token.
    ///
    /// # Returns
    /// Returns a new [`TokenPair`] if the refresh token is valid, or an [`AuthError`] if refresh fails.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.refresh_access_token(refresh_token).await
    }

    /// Validates a token and extracts the user ID (subject) from it.
    ///
    /// # Arguments
    /// * `token` - The token to validate and extract the user ID from.
    ///
    /// # Returns
    /// Returns the user ID as a `String` if the token is valid, or an [`AuthError`] if validation fails.
    pub async fn get_user_id_from_token(&self, token: &str) -> Result<String, AuthError> {
        let claims = self.validate_access_token(token).await?;
        Ok(claims.get_subject().to_string())
    }

    /// Checks if a token is expired by attempting to validate it.
    ///
    /// # Arguments
    /// * `token` - The token to check for expiration.
    ///
    /// # Returns
    /// Returns `true` if the token is expired or invalid, `false` otherwise.
    pub async fn is_token_expired(&self, token: &str) -> bool {
        self.validate_access_token(token).await.is_err()
    }

    /// Validates a token and retrieves the associated user from the repository.
    ///
    /// # Arguments
    /// * `token` - The token to validate and extract the user from.
    ///
    /// # Returns
    /// Returns the [`User`] if the token is valid and the user exists, or an [`AuthError`] otherwise.
    pub async fn get_user_from_token(&self, token: &str) -> Result<User, AuthError> {
        let user_id = self.get_user_id_from_token(token).await?;
        self.persistent_users_manager
            .get_user_by_id(&user_id)
            .await
            .ok_or(AuthError::UserNotFound)
    }

    // OAuth2 Methods

    /// Generates an OAuth2 authorization URL for the specified provider.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider to generate the URL for.
    /// * `state` - A state parameter for CSRF protection.
    /// * `scopes` - Optional additional scopes beyond the default ones.
    ///
    /// # Returns
    /// Returns the authorization URL as a `String` if successful, or an [`AuthError`] if generation fails.
    pub async fn generate_oauth2_auth_url(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
        state: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<String, AuthError> {
        self.oauth2_manager
            .generate_auth_url(provider, state, scopes)
            .await
    }

    /// Exchanges an OAuth2 authorization code for an access token.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider.
    /// * `code` - The authorization code received from the provider.
    /// * `state` - The state parameter for verification.
    ///
    /// # Returns
    /// Returns an [`OAuth2Token`] if successful, or an [`AuthError`] if the token exchange fails.
    pub async fn exchange_oauth2_code_for_token(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
        code: &str,
        state: &str,
    ) -> Result<crate::core::oauth::store::OAuth2Token, AuthError> {
        self.oauth2_manager
            .exchange_code_for_token(provider, code, state)
            .await
    }

    /// Fetches user information from an OAuth2 provider using an access token.
    ///
    /// # Arguments
    /// * `token` - The OAuth2 token to use for fetching user info.
    ///
    /// # Returns
    /// Returns [`OAuth2UserInfo`] if successful, or an [`AuthError`] if fetching user info fails.
    pub async fn fetch_oauth2_user_info(
        &self,
        token: &crate::core::oauth::store::OAuth2Token,
    ) -> Result<crate::core::oauth::store::OAuth2UserInfo, AuthError> {
        self.oauth2_manager.fetch_user_info(token).await
    }

    /// Refreshes an OAuth2 access token using a refresh token.
    ///
    /// # Arguments
    /// * `token` - The OAuth2 token containing the refresh token.
    ///
    /// # Returns
    /// Returns a new [`OAuth2Token`] if successful, or an [`AuthError`] if refreshing the token fails.
    pub async fn refresh_oauth2_token(
        &self,
        token: &crate::core::oauth::store::OAuth2Token,
    ) -> Result<crate::core::oauth::store::OAuth2Token, AuthError> {
        self.oauth2_manager.refresh_token(token).await
    }

    /// Links an OAuth account to an existing user.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the existing user.
    /// * `provider` - The OAuth2 provider.
    /// * `code` - The authorization code from the OAuth provider.
    /// * `state` - The state parameter for CSRF protection.
    ///
    /// # Returns
    /// Returns the updated [`User`] on success.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if the user doesn't exist, or other variants for OAuth2 failures.
    pub async fn link_oauth_account(
        &self,
        user_id: &str,
        provider: crate::core::oauth::store::OAuth2Provider,
        code: &str,
        state: &str,
    ) -> Result<User, AuthError> {
        // Get the existing user
        let mut user = self
            .persistent_users_manager
            .get_user_by_id(user_id)
            .await
            .ok_or(AuthError::UserNotFound)?;

        // Exchange code for token
        let oauth_token = self
            .exchange_oauth2_code_for_token(provider, code, state)
            .await?;

        // Fetch user info from OAuth provider
        let oauth_user_info = self.fetch_oauth2_user_info(&oauth_token).await?;

        // Link the OAuth account to the user
        user = user.link_oauth_account(oauth_user_info);

        // Update the user in storage
        self.persistent_users_manager.update_user(&user).await?;

        Ok(user)
    }

    /// Unlinks an OAuth account from a user.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    /// * `provider` - The OAuth2 provider to unlink.
    ///
    /// # Returns
    /// Returns the updated [`User`] on success.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if the user doesn't exist, or other variants for update failures.
    pub async fn unlink_oauth_account(
        &self,
        user_id: &str,
        provider: crate::core::oauth::store::OAuth2Provider,
    ) -> Result<User, AuthError> {
        // Get the existing user
        let mut user = self
            .persistent_users_manager
            .get_user_by_id(user_id)
            .await
            .ok_or(AuthError::UserNotFound)?;

        // Unlink the OAuth account
        user.unlink_oauth_account(provider);

        // Update the user in storage
        self.persistent_users_manager.update_user(&user).await?;

        Ok(user)
    }

    /// Retrieves all OAuth providers linked to a user.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    ///
    /// # Returns
    /// Returns a vector of [`OAuth2Provider`]s that are linked to the user.
    ///
    /// # Errors
    /// Returns [`AuthError::UserNotFound`] if the user doesn't exist.
    pub async fn get_linked_oauth_providers(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::core::oauth::store::OAuth2Provider>, AuthError> {
        let user = self
            .persistent_users_manager
            .get_user_by_id(user_id)
            .await
            .ok_or(AuthError::UserNotFound)?;

        Ok(user.oauth_accounts.keys().copied().collect())
    }

    /// Retrieves the frontend redirect URI for the specified OAuth2 provider.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider to get the redirect frontend URI for.
    ///
    /// # Returns
    /// Returns the redirect frontend URI as a `String`, or an [`AuthError`] if the provider configuration is missing.
    pub async fn get_oauth2_redirect_frontend_uri(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
    ) -> Result<String, AuthError> {
        // Since oauth2_manager is a Box<dyn OAuth2Service>, we need to downcast it to OAuth2Manager
        // to access the get_redirect_frontend_uri method. For now, we'll need to modify the trait.
        // Let's assume we add this method to the OAuth2Service trait.
        self.oauth2_manager
            .get_redirect_frontend_uri(provider)
            .await
    }
}
