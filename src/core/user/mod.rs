//! User data structures and persistence traits.
//!
//! This module provides the [`User`] struct, which encapsulates user identity and credentials,
//! as well as methods for user creation with both hashed and plaintext passwords. It also
//! re-exports the [`persistence`] submodule, which defines traits and types for user persistence
//! operations (e.g., repositories).
//!
//! # Examples
//!
//! Creating a user with already hashed credentials:
//! ```rust,no_run
//! use authen::core::user::User;
//! use authen::core::credentials::Credentials;
//! let credentials = Credentials::default();
//! let user = User::new("user-id".to_string(), credentials);
//! ```
//!
//! Creating a user with a plaintext password (async):
//! ```ignore
//! use authen::core::user::User;
//! use authen::core::credentials::PlainPassword;
//! # async fn example(manager: &impl authen::core::password::SecurePasswordManager) {
//! let user = User::with_plain_password(
//!     manager,
//!     "user-id".to_string(),
//!     "username".to_string(),
//!     PlainPassword::from("password123"),
//! ).await.unwrap();
//! # }
//! ```

use crate::core::credentials::{Credentials, PlainPassword};
use crate::core::oauth::store::{OAuth2Provider, OAuth2UserInfo};
use std::collections::HashMap;

/// Represents a user in the authentication system.
///
/// The `User` struct contains a unique identifier and associated credentials.
/// The credentials include the user's identifier (e.g., username or email) and password hash.
#[derive(Debug, Clone)]
pub struct User {
    /// Unique identifier for the user (preferably a UUID).
    pub id: String,
    /// User credentials, including hashed password and identifier.
    pub credentials: Option<Credentials>,
    /// OAuth2 accounts linked to this user
    pub oauth_accounts: HashMap<OAuth2Provider, OAuth2UserInfo>,
    /// Account creation timestamp
    pub created_at: chrono::NaiveDateTime,
    /// Last updated timestamp
    pub updated_at: chrono::NaiveDateTime,
}

impl Default for User {
    fn default() -> Self {
        let now = chrono::Utc::now().naive_utc();
        Self {
            id: String::new(),
            credentials: None,
            oauth_accounts: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl User {
    /// Creates a new user with already hashed credentials.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the user (e.g., UUID).
    /// * `credentials` - User credentials, including hashed password and identifier.
    ///
    /// # Returns
    /// A new [`User`] instance.
    pub fn new(id: String, credentials: Credentials) -> Self {
        let now = chrono::Utc::now().naive_utc();
        Self {
            id,
            credentials: Some(credentials),
            oauth_accounts: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a user from a plaintext password, hashing it using the provided password manager.
    ///
    /// # Arguments
    /// * `manager` - Reference to a type implementing [`SecurePasswordManager`] for hashing passwords.
    /// * `id` - Unique identifier for the user (e.g., UUID).
    /// * `identifier` - User identifier (e.g., username or email).
    /// * `plain_password` - The user's plaintext password.
    ///
    /// # Returns
    /// * `Ok(User)` if the password was hashed and the user was created successfully.
    /// * `Err(AuthError)` if password hashing or credential creation fails.
    ///
    /// # Errors
    /// Returns [`AuthError`] if password hashing or credential creation fails.
    ///
    /// # Examples
    /// ```ignore
    /// # use authen::core::user::User;
    /// # use authen::core::credentials::PlainPassword;
    /// # async fn example(manager: &impl authen::core::password::SecurePasswordManager) {
    /// let user = User::with_plain_password(
    ///     manager,
    ///     "user-id".to_string(),
    ///     "username".to_string(),
    ///     PlainPassword::from("password123"),
    /// ).await.unwrap();
    /// # }
    /// ```
    pub async fn with_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let credentials =
            Credentials::from_plain_password(manager, id.clone(), identifier, plain_password)
                .await?;

        Ok(Self {
            id,
            credentials: Some(credentials),
            oauth_accounts: HashMap::new(),
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        })
    }

    /// Links an OAuth account to this user.
    ///
    /// # Arguments
    /// * `oauth_info` - The OAuth user info to link to this user.
    ///
    /// # Returns
    /// The updated user with the OAuth account linked.
    pub fn link_oauth_account(mut self, mut oauth_info: OAuth2UserInfo) -> Self {
        oauth_info.user_id = self.id.clone();
        self.oauth_accounts.insert(oauth_info.provider, oauth_info);
        self.updated_at = chrono::Utc::now().naive_utc();
        self
    }

    /// Unlinks an OAuth account from this user.
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider to unlink.
    ///
    /// # Returns
    /// True if the account was unlinked, false if it wasn't linked.
    pub fn unlink_oauth_account(&mut self, provider: OAuth2Provider) -> bool {
        let was_linked = self.oauth_accounts.remove(&provider).is_some();
        if was_linked {
            self.updated_at = chrono::Utc::now().naive_utc();
        }
        was_linked
    }

    /// Checks if an OAuth account is linked to this user.
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider to check.
    ///
    /// # Returns
    /// True if the provider is linked, false otherwise.
    pub fn has_oauth_account(&self, provider: OAuth2Provider) -> bool {
        self.oauth_accounts.contains_key(&provider)
    }

    /// Gets the OAuth account info for a specific provider.
    ///
    /// # Arguments
    /// * `provider` - The OAuth provider to get info for.
    ///
    /// # Returns
    /// The OAuth user info if linked, None otherwise.
    pub fn get_oauth_account(&self, provider: OAuth2Provider) -> Option<&OAuth2UserInfo> {
        self.oauth_accounts.get(&provider)
    }

    /// Creates a new user from OAuth account info only (no password credentials).
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the user (e.g., UUID).
    /// * `oauth_info` - The OAuth user info to create the user with.
    ///
    /// # Returns
    /// A new [`User`] instance with the OAuth account linked.
    pub fn from_oauth(id: String, mut oauth_info: OAuth2UserInfo) -> Self {
        oauth_info.user_id = id.clone();
        let now = chrono::Utc::now().naive_utc();
        let mut oauth_accounts = HashMap::new();
        oauth_accounts.insert(oauth_info.provider, oauth_info);

        Self {
            id,
            credentials: None,
            oauth_accounts,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Persistence traits and types for user storage and retrieval.
pub mod persistence;
