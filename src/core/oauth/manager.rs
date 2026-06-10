//! OAuth2 Manager Implementation
//!
//! This module provides the concrete implementation of the [`OAuth2Service`] trait
//! using the [`oauth2`] and [`reqwest`] crates for handling OAuth2 authentication flows.
//!
//! # Overview
//!
//! The [`OAuth2Manager`] struct manages OAuth2 authentication flows for multiple providers,
//! including Google, GitHub, Discord, and Microsoft. It handles generating authorization URLs,
//! exchanging authorization codes for tokens, refreshing tokens, and fetching user information.
//!
//! ## Supported Providers
//!
//! - Google
//! - GitHub
//! - Discord
//! - Microsoft
//!
//! ## Main Features
//!
//! - Provider configuration management
//! - HTTP requests for OAuth2 endpoints
//! - Parsing provider-specific user info responses
//! - Token exchange and refresh
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use authen::core::oauth::{manager::OAuth2Manager, store::{OAuth2Config, OAuth2Provider}};
//! use std::collections::HashMap;
//!
//! let mut configs = HashMap::new();
//! configs.insert(OAuth2Provider::Google, OAuth2Config {
//!     app_name: "example-app".to_string(),
//!     client_id: "client-id".to_string(),
//!     client_secret: "client-secret".to_string(),
//!     redirect_callback_uri: "http://localhost:3000/oauth/google/callback".to_string(),
//!     redirect_frontend_uri: "http://localhost:5173/auth/callback".to_string(),
//!     additional_scopes: vec!["email".to_string()],
//! });
//! let manager = OAuth2Manager::new(configs);
//! ```

use async_trait::async_trait;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointSet, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl, basic::BasicClient,
    basic::BasicTokenType,
};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;

use super::OAuth2Service;
use super::store::{OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo};
use crate::AuthError;

use log::{debug, info};

/// Type alias for a fully configured OAuth2 BasicClient.
///
/// This alias simplifies the usage of the [`oauth2::Client`] type with all required generic parameters for standard OAuth2 flows.
/// It is used internally to manage provider-specific OAuth2 clients, ensuring type safety and consistency across supported providers.
type ConfiguredBasicClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    EndpointSet,
>;

/// Manages OAuth2 authentication flows for multiple providers.
///
/// The [`OAuth2Manager`] struct implements the [`OAuth2Service`] trait and provides methods for:
/// - Generating authorization URLs for OAuth2 login flows
/// - Exchanging authorization codes for access and refresh tokens
/// - Refreshing expired access tokens
/// - Fetching user information from provider-specific endpoints
/// - Managing provider configuration and HTTP clients
///
/// # Supported Providers
/// - Google
/// - GitHub
/// - Discord
/// - Microsoft
///
/// # Example
/// ```rust,no_run
/// use authen::core::oauth::{manager::OAuth2Manager, store::{OAuth2Config, OAuth2Provider}};
/// use std::collections::HashMap;
/// let mut configs = HashMap::new();
/// configs.insert(OAuth2Provider::Google, OAuth2Config {
///     app_name: "example-app".to_string(),
///     client_id: "client-id".to_string(),
///     client_secret: "client-secret".to_string(),
///     redirect_callback_uri: "http://localhost:3000/oauth/google/callback".to_string(),
///     redirect_frontend_uri: "http://localhost:5173/auth/callback".to_string(),
///     additional_scopes: vec!["email".to_string()],
/// });
/// let manager = OAuth2Manager::new(configs);
/// ```
pub struct OAuth2Manager {
    /// Map of OAuth2 providers to their configuration.
    configs: HashMap<OAuth2Provider, OAuth2Config>,
}

impl OAuth2Manager {
    /// Creates a new [`OAuth2Manager`] with the provided provider configurations.
    ///
    /// # Arguments
    /// * `configs` - A map of [`OAuth2Provider`] to [`OAuth2Config`] containing all provider-specific settings.
    ///
    /// # Returns
    /// A new [`OAuth2Manager`] instance ready to manage OAuth2 flows for the configured providers.
    pub fn new(configs: HashMap<OAuth2Provider, OAuth2Config>) -> Self {
        info!(
            "Initializing OAuth2Manager with {} provider configs",
            configs.len()
        );

        Self { configs }
    }

    /// Returns a configured HTTP client for the given provider with the appropriate User-Agent.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider for which to create the HTTP client.
    ///
    /// # Errors
    /// Returns [`AuthError::ConfigError`] if the provider configuration is missing or the client cannot be built.
    ///
    /// # Example
    /// ```rust,ignore
    /// let client = manager.get_http_client(OAuth2Provider::Google)?;
    /// ```
    fn get_http_client(&self, provider: OAuth2Provider) -> Result<Client, AuthError> {
        let config = self.configs.get(&provider).ok_or_else(|| {
            AuthError::ConfigError(format!("No config found for provider: {provider:?}"))
        })?;

        Client::builder()
            .user_agent(&config.app_name)
            .build()
            .map_err(|e| AuthError::ConfigError(format!("Failed to create HTTP client: {e}")))
    }

    /// Returns a configured OAuth2 client for the given provider.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider for which to create the client.
    ///
    /// # Errors
    /// Returns [`AuthError::ConfigError`] if the provider configuration is missing or contains invalid URLs.
    ///
    /// # Example
    /// ```rust,ignore
    /// let client = manager.get_client(OAuth2Provider::GitHub)?;
    /// ```
    pub fn get_client(&self, provider: OAuth2Provider) -> Result<ConfiguredBasicClient, AuthError> {
        debug!("Getting OAuth2 client for provider: {provider:?}");
        let config = self.configs.get(&provider).ok_or_else(|| {
            debug!("No config found for provider: {provider:?}");
            AuthError::ConfigError(format!("No config found for provider: {provider:?}"))
        })?;

        let app_name = &config.app_name;

        let auth_url = AuthUrl::new(config.auth_url(provider).to_string()).map_err(|e| {
            debug!("Invalid auth URL for provider {provider:?}: {e}");
            AuthError::ConfigError(format!("Invalid auth URL: {e}"))
        })?;

        let token_url = TokenUrl::new(config.token_url(provider).to_string()).map_err(|e| {
            debug!("Invalid token URL for provider {provider:?}: {e}");
            AuthError::ConfigError(format!("Invalid token URL: {e}"))
        })?;

        let redirect_url = RedirectUrl::new(config.redirect_callback_uri.clone()).map_err(|e| {
            debug!("Invalid redirect URL for provider {provider:?}: {e}");
            AuthError::ConfigError(format!("Invalid redirect URL: {e}"))
        })?;

        debug!("OAuth2 client configured for provider: {provider:?}");
        debug!("App Name: {app_name}");
        debug!("Client ID: {}", config.client_id);
        debug!("Redirect URI: {}", config.redirect_callback_uri);
        debug!("Auth URL: {}", config.auth_url(provider));
        debug!("Token URL: {}", config.token_url(provider));
        let client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        Ok(client)
    }

    /// Parses user information from the provider's user info response.
    ///
    /// This method extracts and normalizes user profile data from the JSON response returned by the provider's user info endpoint.
    /// The parsing logic is provider-specific and handles differences in field names and formats.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider whose response is being parsed.
    /// * `response_body` - The JSON response body from the provider's user info endpoint.
    ///
    /// # Returns
    /// Returns [`OAuth2UserInfo`] on success, or [`AuthError`] if required fields are missing or the response is invalid.
    ///
    /// # Example
    /// ```rust,ignore
    /// let user_info = manager.parse_user_info(OAuth2Provider::Google, json_response).await?;
    /// ```
    pub async fn parse_user_info(
        &self,
        provider: OAuth2Provider,
        response_body: Value,
    ) -> Result<OAuth2UserInfo, AuthError> {
        let now = chrono::Utc::now().naive_utc();

        debug!("Parsing user info for provider: {provider:?}");

        match provider {
            OAuth2Provider::Google => {
                debug!("Google user info response: {response_body:?}");
                let email = response_body["email"].as_str().map(|s| s.to_string());
                let name = response_body["name"].as_str().map(|s| s.to_string());
                let avatar_url = response_body["picture"].as_str().map(|s| s.to_string());
                let verified_email = response_body["verified_email"].as_bool();
                let locale = response_body["locale"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                Ok(OAuth2UserInfo {
                    user_id: String::new(), // Will be set when linking to authen user
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email,
                    locale,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::GitHub => {
                debug!("GitHub user info response: {response_body:?}");
                let name = response_body["name"].as_str().map(|s| s.to_string());
                let avatar_url = response_body["avatar_url"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_u64()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                // GitHub requires a separate API call for email
                let email = if let Some(email_str) = response_body["email"].as_str() {
                    if !email_str.is_empty() {
                        Some(email_str.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                Ok(OAuth2UserInfo {
                    user_id: String::new(), // Will be set when linking to authen user
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email: None,
                    locale: None,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::Discord => {
                debug!("Discord user info response: {response_body:?}");
                let email = response_body["email"].as_str().map(|s| s.to_string());
                let name = response_body["username"].as_str().map(|s| s.to_string());
                let avatar = response_body["avatar"].as_str();
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                let avatar_url = avatar.map(|avatar_hash| {
                    format!(
                        "https://cdn.discordapp.com/avatars/{provider_user_id}/{avatar_hash}.png"
                    )
                });

                let verified_email = response_body["verified"].as_bool();
                let locale = response_body["locale"].as_str().map(|s| s.to_string());

                Ok(OAuth2UserInfo {
                    user_id: String::new(), // Will be set when linking to authen user
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email,
                    locale,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::Microsoft => {
                debug!("Microsoft user info response: {response_body:?}");
                let email = response_body["mail"]
                    .as_str()
                    .or_else(|| response_body["userPrincipalName"].as_str())
                    .map(|s| s.to_string());
                let name = response_body["displayName"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                Ok(OAuth2UserInfo {
                    user_id: String::new(), // Will be set when linking to authen user
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url: None, // Microsoft Graph doesn't provide avatar URL directly
                    verified_email: None,
                    locale: None,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
        }
    }
}

#[async_trait]
impl OAuth2Service for OAuth2Manager {
    /// Generates the OAuth2 authorization URL for the specified provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    /// * `state` - CSRF state parameter.
    /// * `scopes` - Optional additional scopes to request.
    ///
    /// # Returns
    ///
    /// Returns the authorization URL as a string, or [`AuthError`] on failure.
    async fn generate_auth_url(
        &self,
        provider: OAuth2Provider,
        state: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<String, AuthError> {
        info!(
            "Generating auth URL for provider: {:?}, state: {}",
            provider, state
        );
        let client = self.get_client(provider)?;

        let config = self.configs.get(&provider).unwrap();
        // Collect default and additional scopes.
        let mut all_scopes = provider
            .default_scopes()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        if let Some(additional_scopes) = scopes {
            all_scopes.extend(additional_scopes);
        }
        all_scopes.extend(config.additional_scopes.clone());

        // Deduplicate scopes.
        all_scopes.sort();
        all_scopes.dedup();

        debug!("Final scopes for auth URL: {all_scopes:?}");
        let mut auth_request = client.authorize_url(|| CsrfToken::new(state.to_string()));

        for scope in all_scopes {
            auth_request = auth_request.add_scope(Scope::new(scope));
        }

        let (auth_url, _csrf_token) = auth_request.url();
        info!("Generated auth URL: {}", auth_url);
        Ok(auth_url.to_string())
    }

    /// Exchanges an authorization code for an access token for the specified provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    /// * `code` - The authorization code received from the provider.
    /// * `_state` - The CSRF state parameter (unused).
    ///
    /// # Returns
    ///
    /// Returns an [`OAuth2Token`] on success, or [`AuthError`] on failure.
    async fn exchange_code_for_token(
        &self,
        provider: OAuth2Provider,
        code: &str,
        _state: &str,
    ) -> Result<OAuth2Token, AuthError> {
        info!("Exchanging code for token for provider: {:?}", provider);
        debug!("Authorization code: {}", code);
        let client = self.get_client(provider)?;
        let http_client = self.get_http_client(provider)?;

        let token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(&http_client) // Utilise le client HTTP configuré avec le bon User-Agent
            .await
            .map_err(|e| {
                debug!("Token exchange failed for provider {provider:?}: {e}");
                debug!("Full error details: {e:?}");
                AuthError::OAuthTokenExchange(format!("Token exchange failed: {e}"))
            })?;

        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result.refresh_token().map(|rt| rt.secret().clone());
        let expires_at = token_result.expires_in().map(|duration| {
            chrono::Utc::now().naive_utc()
                + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::seconds(0))
        });
        let token_type = token_result.token_type().as_ref().to_string();
        let scope = token_result.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        });

        info!("Token exchange successful for provider: {:?}", provider);
        debug!("Access token: {}", access_token);
        Ok(OAuth2Token {
            access_token,
            refresh_token,
            expires_at,
            token_type,
            scope,
            provider,
            created_at: chrono::Utc::now().naive_utc(),
        })
    }

    /// Fetches user information from the provider's user info endpoint using the access token.
    ///
    /// # Arguments
    ///
    /// * `token` - The [`OAuth2Token`] containing the access token and provider.
    ///
    /// # Returns
    ///
    /// Returns [`OAuth2UserInfo`] on success, or [`AuthError`] on failure.
    async fn fetch_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo, AuthError> {
        info!("Fetching user info for provider: {:?}", token.provider);
        debug!("Access token: {}", token.access_token);
        let config = self.configs.get(&token.provider).ok_or_else(|| {
            debug!("No config found for provider: {:?}", token.provider);
            AuthError::ConfigError(format!(
                "No config found for provider: {:?}",
                token.provider
            ))
        })?;

        let user_info_url = config.user_info_url(token.provider);
        debug!("User info URL: {}", user_info_url);
        let http_client = self.get_http_client(token.provider)?;

        let response = http_client
            .get(user_info_url)
            .bearer_auth(&token.access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                debug!(
                    "Failed to fetch user info for provider {:?}: {}",
                    token.provider, e
                );
                AuthError::OAuthNetwork(format!("Failed to fetch user info: {e}"))
            })?;

        if !response.status().is_success() {
            debug!(
                "User info request failed with status: {}",
                response.status()
            );
            return Err(AuthError::OAuthUserInfo(format!(
                "User info request failed with status: {}",
                response.status()
            )));
        }

        let response_body: Value = response.json().await.map_err(|e| {
            debug!(
                "Invalid JSON response for provider {:?}: {}",
                token.provider, e
            );
            AuthError::OAuthInvalidResponse(format!("Invalid JSON response: {e}"))
        })?;

        self.parse_user_info(token.provider, response_body).await
    }

    /// Refreshes the access token using the refresh token for the specified provider.
    ///
    /// # Arguments
    ///
    /// * `token` - The [`OAuth2Token`] containing the refresh token and provider.
    ///
    /// # Returns
    ///
    /// Returns a new [`OAuth2Token`] on success, or [`AuthError`] on failure.
    async fn refresh_token(&self, token: &OAuth2Token) -> Result<OAuth2Token, AuthError> {
        info!("Refreshing token for provider: {:?}", token.provider);
        debug!("Current refresh token: {:?}", token.refresh_token);
        let client = self.get_client(token.provider)?;
        let http_client = self.get_http_client(token.provider)?;

        let refresh_token = token.refresh_token.as_ref().ok_or_else(|| {
            debug!(
                "No refresh token available for provider: {:?}",
                token.provider
            );
            AuthError::OAuthTokenExchange("No refresh token available".to_string())
        })?;

        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.clone()))
            .request_async(&http_client) // Utilise le client HTTP configuré avec le bon User-Agent
            .await
            .map_err(|e| {
                debug!(
                    "Token refresh failed for provider {:?}: {}",
                    token.provider, e
                );
                AuthError::OAuthTokenExchange(format!("Token refresh failed: {e}"))
            })?;

        let access_token = token_result.access_token().secret().clone();
        let new_refresh_token = token_result
            .refresh_token()
            .map(|rt| rt.secret().clone())
            .or_else(|| token.refresh_token.clone());
        let expires_at = token_result.expires_in().map(|duration| {
            chrono::Utc::now().naive_utc()
                + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::seconds(0))
        });
        let token_type = token_result.token_type().as_ref().to_string();
        let scope = token_result
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .or_else(|| token.scope.clone());

        info!(
            "Token refresh successful for provider: {:?}",
            token.provider
        );
        debug!("New access token: {}", access_token);
        Ok(OAuth2Token {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
            token_type,
            scope,
            provider: token.provider,
            created_at: chrono::Utc::now().naive_utc(),
        })
    }

    async fn get_redirect_frontend_uri(
        &self,
        provider: OAuth2Provider,
    ) -> Result<String, AuthError> {
        OAuth2Manager::get_redirect_frontend_uri(self, provider)
    }
}

impl OAuth2Manager {
    /// Gets the frontend redirect URI for the given provider.
    ///
    /// This URI is typically used to redirect users back to the frontend application after completing the OAuth2 flow.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider for which to retrieve the frontend redirect URI.
    ///
    /// # Returns
    /// Returns the frontend redirect URI as a string, or an [`AuthError`] if the provider configuration is missing.
    ///
    /// # Example
    /// ```rust,ignore
    /// let uri = manager.get_redirect_frontend_uri(OAuth2Provider::Discord)?;
    /// ```
    pub fn get_redirect_frontend_uri(&self, provider: OAuth2Provider) -> Result<String, AuthError> {
        let config = self.configs.get(&provider).ok_or_else(|| {
            AuthError::ConfigError(format!("No config found for provider: {provider:?}"))
        })?;
        Ok(config.redirect_frontend_uri.clone())
    }

    /// Sets the `user_id` field in [`OAuth2UserInfo`] to link it to a authen user.
    ///
    /// This is used to associate an external OAuth2 identity with an internal user account.
    ///
    /// # Arguments
    /// * `oauth_info` - The OAuth user info to update.
    /// * `user_id` - The authen user ID to link to.
    ///
    /// # Returns
    /// The updated [`OAuth2UserInfo`] with the `user_id` field set.
    ///
    /// # Example
    /// ```rust,ignore
    /// let linked_info = OAuth2Manager::link_to_user(oauth_info, user_id);
    /// ```
    pub fn link_to_user(mut oauth_info: OAuth2UserInfo, user_id: String) -> OAuth2UserInfo {
        info!("Linking OAuth2UserInfo to user_id: {user_id}");
        oauth_info.user_id = user_id;
        oauth_info
    }
}

/// Provides a default empty [`OAuth2Manager`] with no provider configurations.
///
/// This implementation is useful for testing or initializing the manager before loading provider configs.
///
/// # Example
/// ```rust,no_run
/// use authen::core::oauth::manager::OAuth2Manager;
/// let manager = OAuth2Manager::default();
/// ```
impl Default for OAuth2Manager {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}
