//! OAuth2 provider, token, user info, config, and session types for authentication flows.
//!
//! This module defines enums and structs for representing OAuth2 providers, tokens, user information,
//! configuration, and session state. It also provides utility methods for working with these types.
//!
//! # OAuth2 Flow with Frontend Redirect
//!
//! The OAuth2 implementation supports automatic redirection to frontend applications after successful
//! authentication. Here's how the flow works:
//!
//! 1. **Generate Auth URL**: Client requests authorization URL from `/oauth/{provider}/auth`
//! 2. **User Authorization**: User is redirected to provider (Google, GitHub, etc.) for authorization
//! 3. **Provider Callback**: Provider redirects back to `/oauth/{provider}/callback` with auth code
//! 4. **Token Exchange**: Server exchanges code for tokens automatically
//! 5. **Frontend Redirect**: Server redirects user to `redirect_frontend_uri` with tokens in URL fragment
//!
//! ## Example Configuration
//!
//! ```rust,no_run
//! use authen::core::oauth::store::OAuth2Config;
//!
//! let config = OAuth2Config {
//!     app_name: "My App".to_string(),
//!     client_id: "your-client-id".to_string(),
//!     client_secret: "your-client-secret".to_string(),
//!     redirect_callback_uri: "https://api.myapp.com/oauth/google/callback".to_string(),
//!     redirect_frontend_uri: "https://myapp.com/auth/callback".to_string(),
//!     additional_scopes: vec!["profile".to_string()],
//! };
//! ```
//!
//! ## Frontend Token Extraction
//!
//! Your frontend application should handle the redirect and extract tokens from the URL fragment:
//!
//! ```javascript
//! // At your redirect_frontend_uri (e.g., https://myapp.com/auth/callback)
//! function handleOAuthCallback() {
//!   const fragment = window.location.hash.substring(1);
//!   const params = new URLSearchParams(fragment);
//!
//!   if (params.has('error')) {
//!     console.error('OAuth error:', params.get('error'));
//!   } else {
//!     const accessToken = params.get('access_token');
//!     const refreshToken = params.get('refresh_token');
//!     const userId = params.get('user_id');
//!
//!     // Store tokens and proceed
//!     localStorage.setItem('accessToken', accessToken);
//!     // ... redirect to your app
//!   }
//! }
//! ```

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// Supported OAuth2 providers for authentication.
///
/// This enum lists all external providers supported by the authentication system.
/// Each variant represents a third-party OAuth2 provider that can be used for user authentication.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum OAuth2Provider {
    /// Google OAuth2 provider.
    Google,
    /// GitHub OAuth2 provider.
    GitHub,
    /// Discord OAuth2 provider.
    Discord,
    /// Microsoft OAuth2 provider.
    Microsoft,
}

impl OAuth2Provider {
    /// Returns the display name of the provider as a human-readable string.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::OAuth2Provider;
    /// let provider = OAuth2Provider::Google;
    /// assert_eq!(provider.display_name(), "Google");
    /// ```
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::GitHub => "GitHub",
            Self::Discord => "Discord",
            Self::Microsoft => "Microsoft",
        }
    }

    /// Returns the default OAuth2 scopes required for the provider.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::OAuth2Provider;
    /// let scopes = OAuth2Provider::Google.default_scopes();
    /// assert!(scopes.contains(&"email"));
    /// ```
    pub fn default_scopes(&self) -> Vec<&'static str> {
        match self {
            Self::Google => vec!["openid", "email", "profile"],
            Self::GitHub => vec!["user:email"],
            Self::Discord => vec!["identify", "email"],
            Self::Microsoft => vec!["openid", "email", "profile"],
        }
    }
}

impl std::str::FromStr for OAuth2Provider {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            "discord" => Ok(Self::Discord),
            "microsoft" => Ok(Self::Microsoft),
            _ => Err("expected one of: google, github, discord, microsoft".to_string()),
        }
    }
}

/// Represents an OAuth2 token, including access and refresh tokens, expiration, and provider info.
///
/// This struct holds all relevant information about an OAuth2 token issued by a provider,
/// including the access token, optional refresh token, expiration, token type, scope, provider, and creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    /// The access token string used for authenticated requests.
    pub access_token: String,
    /// The optional refresh token string, used to obtain new access tokens.
    pub refresh_token: Option<String>,
    /// The expiration time of the access token, if available.
    pub expires_at: Option<NaiveDateTime>,
    /// The type of token (usually "Bearer").
    pub token_type: String,
    /// The scope of the token, if provided by the provider.
    pub scope: Option<String>,
    /// The OAuth2 provider that issued the token.
    pub provider: OAuth2Provider,
    /// The time the token was created.
    pub created_at: NaiveDateTime,
}

impl OAuth2Token {
    /// Checks if the token is expired.
    ///
    /// Returns `true` if the current time is past the expiration time, or `false` otherwise.
    /// If `expires_at` is `None`, returns `false`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::{OAuth2Provider, OAuth2Token};
    /// let token = OAuth2Token {
    ///     access_token: "access".to_string(),
    ///     refresh_token: Some("refresh".to_string()),
    ///     expires_at: Some(chrono::Utc::now().naive_utc()),
    ///     token_type: "Bearer".to_string(),
    ///     scope: None,
    ///     provider: OAuth2Provider::Google,
    ///     created_at: chrono::Utc::now().naive_utc(),
    /// };
    /// let expired = token.is_expired();
    /// ```
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| chrono::Utc::now().naive_utc() > exp)
            .unwrap_or(false)
    }

    /// Checks if the token will expire within the given threshold (in seconds).
    ///
    /// # Arguments
    ///
    /// * `threshold_secs` - Number of seconds to check for imminent expiration.
    ///
    /// Returns `true` if the token will expire within `threshold_secs` seconds, or `false` otherwise.
    /// If `expires_at` is `None`, returns `false`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::{OAuth2Provider, OAuth2Token};
    /// let token = OAuth2Token {
    ///     access_token: "access".to_string(),
    ///     refresh_token: Some("refresh".to_string()),
    ///     expires_at: Some(chrono::Utc::now().naive_utc()),
    ///     token_type: "Bearer".to_string(),
    ///     scope: None,
    ///     provider: OAuth2Provider::Google,
    ///     created_at: chrono::Utc::now().naive_utc(),
    /// };
    /// let soon = token.expires_soon(60);
    /// ```
    pub fn expires_soon(&self, threshold_secs: u64) -> bool {
        self.expires_at
            .map(|exp| {
                let now = chrono::Utc::now().naive_utc();
                let duration = exp.signed_duration_since(now).num_seconds();
                duration < threshold_secs as i64
            })
            .unwrap_or(false)
    }
}

/// Represents user information returned by an OAuth2 provider.
///
/// This struct contains all relevant user profile information returned by an OAuth2 provider after authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    /// The internal user ID assigned by the application.
    pub user_id: String,
    /// The OAuth2 provider that authenticated the user.
    pub provider: OAuth2Provider,
    /// The unique user ID from the provider.
    pub provider_user_id: String,
    /// The user's email address, if available.
    pub email: Option<String>,
    /// The user's display name, if available.
    pub name: Option<String>,
    /// The user's avatar URL, if available.
    pub avatar_url: Option<String>,
    /// Whether the user's email is verified, if available.
    pub verified_email: Option<bool>,
    /// The user's locale, if available.
    pub locale: Option<String>,
    /// The time the user info was last updated.
    pub updated_at: NaiveDateTime,
    /// The raw user info data as returned by the provider, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<serde_json::Value>,
}

/// Configuration for OAuth2 authentication with a provider.
///
/// This struct defines the configuration required to set up OAuth2 authentication for a specific provider.
/// It includes client credentials, redirect URIs, and additional scopes.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// The name of the application using OAuth2.
    pub app_name: String,
    /// The OAuth2 client ID issued by the provider.
    pub client_id: String,
    /// The OAuth2 client secret issued by the provider.
    pub client_secret: String,
    /// The redirect URI for OAuth2 callbacks.
    /// This is where the OAuth2 provider will redirect users after authorization.
    /// It should point to your server's callback endpoint (e.g., `/oauth/{provider}/callback`).
    pub redirect_callback_uri: String,
    /// The redirect URI for the user to go back to the frontend application.
    /// After successful OAuth2 authentication, the server will redirect the user to this URI
    /// with authentication tokens included in the URL fragment (e.g., `#access_token=...&refresh_token=...`).
    /// This should point to a frontend page that can handle token extraction from the URL fragment.
    pub redirect_frontend_uri: String,
    /// Additional scopes to request during authentication.
    pub additional_scopes: Vec<String>,
}

impl OAuth2Config {
    /// Returns the authorization URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider for which to get the authorization URL.
    ///
    /// # Returns
    ///
    /// A static string containing the provider's authorization endpoint URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::{OAuth2Config, OAuth2Provider};
    /// let config = OAuth2Config {
    ///     app_name: "My App".to_string(),
    ///     client_id: "your-client-id".to_string(),
    ///     client_secret: "your-client-secret".to_string(),
    ///     redirect_callback_uri: "https://api.myapp.com/oauth/google/callback".to_string(),
    ///     redirect_frontend_uri: "https://myapp.com/auth/callback".to_string(),
    ///     additional_scopes: vec!["profile".to_string()],
    /// };
    /// let url = config.auth_url(OAuth2Provider::Google);
    /// ```
    pub fn auth_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/authorize",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/authorize",
            OAuth2Provider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            }
        }
    }

    /// Returns the token endpoint URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider for which to get the token endpoint URL.
    ///
    /// # Returns
    ///
    /// A static string containing the provider's token endpoint URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::{OAuth2Config, OAuth2Provider};
    /// let config = OAuth2Config {
    ///     app_name: "My App".to_string(),
    ///     client_id: "your-client-id".to_string(),
    ///     client_secret: "your-client-secret".to_string(),
    ///     redirect_callback_uri: "https://api.myapp.com/oauth/google/callback".to_string(),
    ///     redirect_frontend_uri: "https://myapp.com/auth/callback".to_string(),
    ///     additional_scopes: vec!["profile".to_string()],
    /// };
    /// let url = config.token_url(OAuth2Provider::Google);
    /// ```
    pub fn token_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://oauth2.googleapis.com/token",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/access_token",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/token",
            OAuth2Provider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
        }
    }

    /// Returns the user info endpoint URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider for which to get the user info endpoint URL.
    ///
    /// # Returns
    ///
    /// A static string containing the provider's user info endpoint URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use authen::core::oauth::store::{OAuth2Config, OAuth2Provider};
    /// let config = OAuth2Config {
    ///     app_name: "My App".to_string(),
    ///     client_id: "your-client-id".to_string(),
    ///     client_secret: "your-client-secret".to_string(),
    ///     redirect_callback_uri: "https://api.myapp.com/oauth/google/callback".to_string(),
    ///     redirect_frontend_uri: "https://myapp.com/auth/callback".to_string(),
    ///     additional_scopes: vec!["profile".to_string()],
    /// };
    /// let url = config.user_info_url(OAuth2Provider::Google);
    /// ```
    pub fn user_info_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://www.googleapis.com/oauth2/v2/userinfo",
            OAuth2Provider::GitHub => "https://api.github.com/user",
            OAuth2Provider::Discord => "https://discord.com/api/users/@me",
            OAuth2Provider::Microsoft => "https://graph.microsoft.com/v1.0/me",
        }
    }
}

/// Represents an OAuth2 session, including state, provider, PKCE verifier, and timing info.
///
/// This struct tracks the state of an ongoing OAuth2 authentication session, including CSRF protection,
/// provider, PKCE verifier, and session timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Session {
    /// The session state string (used for CSRF protection).
    pub state: String,
    /// The OAuth2 provider for this session.
    pub provider: OAuth2Provider,
    /// The PKCE verifier string, if used for enhanced security.
    pub pkce_verifier: Option<String>,
    /// The time the session was created.
    pub created_at: NaiveDateTime,
    /// The time the session expires.
    pub expires_at: NaiveDateTime,
}
