//! In-memory implementation of the `UserRepository` trait for testing and development.
//!
//! This module provides a thread-safe, in-memory user repository using `Arc<Mutex<Vec<User>>>`.
//! It is intended for use in tests or non-persistent environments where a database is not required.

use async_trait::async_trait;

use super::traits::UserRepository;
use crate::core::user::User;
use std::sync::{Arc, Mutex};

/// Thread-safe, in-memory implementation of the [`UserRepository`] trait.
///
/// Stores users in a shared, mutable vector protected by a mutex.
/// Suitable for testing or ephemeral use cases where persistence is not required.
#[derive(Default, Debug)]
pub struct InMemoryUserRepo {
    /// Shared, thread-safe vector of users.
    users: Arc<Mutex<Vec<User>>>,
}

impl InMemoryUserRepo {
    /// Creates a new, empty in-memory user repository.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::user::persistence::InMemoryUserRepo;
    /// let repo = InMemoryUserRepo::new();
    /// ```
    pub fn new() -> Self {
        InMemoryUserRepo {
            users: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepo {
    /// Adds a new user to the repository.
    ///
    /// # Arguments
    /// * `user` - The user to add.
    ///
    /// # Returns
    /// * `Ok(User)` if the user was added successfully.
    /// * `Err(AuthError)` if the repository is unavailable.
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        users.push(user.clone());
        Ok(user.clone())
    }

    /// Retrieves a user by their unique ID.
    ///
    /// # Arguments
    /// * `id` - The user's unique identifier.
    ///
    /// # Returns
    /// * `Some(User)` if found, or `None` if not found or on lock error.
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users.iter().find(|u| u.id == id).cloned()
    }

    /// Retrieves a user by their identifier (e.g., username or email).
    ///
    /// # Arguments
    /// * `identifier` - The user's identifier.
    ///
    /// # Returns
    /// * `Some(User)` if found, or `None` if not found or on lock error.
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users
            .iter()
            .find(|u| {
                u.credentials
                    .as_ref()
                    .map(|creds| creds.identifier == identifier)
                    .unwrap_or(false)
            })
            .cloned()
    }

    /// Updates an existing user in the repository.
    ///
    /// # Arguments
    /// * `user` - The user with updated information.
    ///
    /// # Returns
    /// * `Ok(())` if the user was updated.
    /// * `Err(AuthError::UserNotFound)` if the user does not exist.
    /// * `Err(AuthError)` if the repository is unavailable.
    async fn update_user(&self, user: &User) -> Result<(), crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        if let Some(existing) = users.iter_mut().find(|u| u.id == user.id) {
            *existing = user.clone();
            Ok(())
        } else {
            Err(crate::error::AuthError::UserNotFound)
        }
    }

    /// Deletes a user from the repository by their ID.
    ///
    /// # Arguments
    /// * `id` - The user's unique identifier.
    ///
    /// # Returns
    /// * `Ok(())` if the user was deleted.
    /// * `Err(AuthError::UserNotFound)` if the user does not exist.
    /// * `Err(AuthError)` if the repository is unavailable.
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        let len_before = users.len();
        users.retain(|u| u.id != id);
        if users.len() < len_before {
            Ok(())
        } else {
            Err(crate::error::AuthError::UserNotFound)
        }
    }

    /// Retrieves a user by their OAuth provider and provider user ID.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider.
    /// * `provider_user_id` - The user ID from the OAuth provider.
    ///
    /// # Returns
    /// * `Some(User)` if found, or `None` if not found or on lock error.
    async fn get_user_by_oauth_id(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
        provider_user_id: &str,
    ) -> Option<User> {
        let users = self.users.lock().ok()?;
        users
            .iter()
            .find(|u| {
                u.oauth_accounts
                    .get(&provider)
                    .map(|oauth_info| oauth_info.provider_user_id == provider_user_id)
                    .unwrap_or(false)
            })
            .cloned()
    }
}
