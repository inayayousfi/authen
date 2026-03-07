//! Web server and HTTP API integration for Authen using Axum.
//!
//! This module provides the Axum-based web server and HTTP API endpoints for authentication,
//! user management, token operations, and OAuth2 integration. It exposes routes for signup,
//! login, health check, token refresh, token validation, OAuth2 authorization, and OAuth2
//! callbacks, connecting them to the core authentication service.
//!
//! All endpoints expect and return JSON. Error responses are also JSON-encoded.
//!
//! # Features
//! - Only compiled and available with the `web` feature enabled.
//! - Designed for use with the `AuthService` abstraction.
//! - Full OAuth2 support for Google, GitHub, Discord, and Microsoft.
//!
//! # API Endpoints Reference
//!
//! ## Authentication Endpoints
//!
//! ### POST `/signup`
//! Create a new user account with username and password.
//!
//! **Request:**
//! ```json
//! {
//!   "username": "john_doe",
//!   "password": "secure_password123"
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "id": "user-uuid-here",
//!   "identifier": "john_doe"
//! }
//! ```
//!
//! **Error Response (400/500):**
//! ```json
//! {
//!   "error": "Username already exists"
//! }
//! ```
//!
//! ### POST `/login`
//! Authenticate user and receive access and refresh tokens.
//!
//! **Request:**
//! ```json
//! {
//!   "username": "john_doe",
//!   "password": "secure_password123"
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "id": "user-uuid-here",
//!   "identifier": "john_doe",
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "refresh_token": "refresh-token-string-here"
//! }
//! ```
//!
//! **Error Response (401/400):**
//! ```json
//! {
//!   "error": "Invalid credentials"
//! }
//! ```
//!
//! ## Token Management
//!
//! ### POST `/token/refresh`
//! Refresh an expired access token using a valid refresh token.
//!
//! **Request:**
//! ```json
//! {
//!   "refresh_token": "refresh-token-string-here"
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "access_token": "new-access-token-here",
//!   "refresh_token": "new-or-same-refresh-token"
//! }
//! ```
//!
//! ### POST `/token/validate`
//! Validate an access token and get user claims.
//!
//! **Request:**
//! ```json
//! {
//!   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "valid": true,
//!   "claims": {
//!     "sub": "user-uuid-here",
//!     "exp": 1640995200
//!   }
//! }
//! ```
//!
//! ## OAuth2 Endpoints
//!
//! ### GET `/oauth/{provider}/auth`
//! Generate OAuth2 authorization URL for the specified provider.
//! Supported providers: `google`, `github`, `discord`, `microsoft`
//!
//! **Query Parameters:**
//! - `state` (required): CSRF protection state parameter
//! - `scopes` (optional): Comma-separated additional scopes
//!
//! **Example Request:**
//! ```
//! GET /oauth/google/auth?state=random-csrf-token&scopes=openid,email,profile
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=..."
//! }
//! ```
//!
//! ### GET `/oauth/{provider}/callback`
//! OAuth2 callback endpoint (usually called by the provider after user authorization).
//! This endpoint automatically redirects users to the configured frontend URI with tokens
//! included in the URL fragment for security.
//!
//! **Query Parameters:**
//! - `code` (required): Authorization code from provider
//! - `state` (required): State parameter for CSRF verification
//!
//! **Example Request:**
//! ```
//! GET /oauth/google/callback?code=auth-code-from-provider&state=random-csrf-token
//! ```
//!
//! **Success Response:**
//! HTTP 302 Redirect to `{redirect_frontend_uri}#access_token=...&refresh_token=...&user_id=...&token_type=Bearer&expires_in=3600`
//!
//! **Error Response:**
//! HTTP 302 Redirect to `{redirect_frontend_uri}#error=authentication_failed&error_description=...`
//!
//!
//! ### POST `/oauth/signup`
//! Create a new user account using OAuth2 authorization code.
//!
//! **Request:**
//! ```json
//! {
//!   "provider": "google",
//!   "code": "authorization-code-from-provider",
//!   "state": "random-csrf-token"
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "id": "user-uuid-here",
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "refresh_token": "refresh-token-string-here",
//!   "oauth_info": {
//!     "provider": "google",
//!     "email": "user@example.com",
//!     "name": "John Doe"
//!   }
//! }
//! ```
//!
//! ### POST `/oauth/login`
//! Login with an existing OAuth2 account.
//!
//! **Request:**
//! ```json
//! {
//!   "provider": "google",
//!   "code": "authorization-code-from-provider",
//!   "state": "random-csrf-token"
//! }
//! ```
//!
//! **Success Response (200):**
//! ```json
//! {
//!   "id": "user-uuid-here",
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "refresh_token": "refresh-token-string-here"
//! }
//! ```
//!
//! ## Health Check
//!
//! ### GET `/health`
//! Simple health check endpoint.
//!
//! **Response (200):**
//! ```
//! OK
//! ```
//!
//! # Client Usage Examples
//!
//! ## Basic Authentication Flow (JavaScript/TypeScript)
//!
//! ```javascript
//! // 1. Sign up a new user
//! const signupResponse = await fetch('http://localhost:3000/signup', {
//!   method: 'POST',
//!   headers: { 'Content-Type': 'application/json' },
//!   body: JSON.stringify({
//!     username: 'john_doe',
//!     password: 'secure_password123'
//!   })
//! });
//! const userData = await signupResponse.json();
//!
//! // 2. Login and get tokens
//! const loginResponse = await fetch('http://localhost:3000/login', {
//!   method: 'POST',
//!   headers: { 'Content-Type': 'application/json' },
//!   body: JSON.stringify({
//!     username: 'john_doe',
//!     password: 'secure_password123'
//!   })
//! });
//! const { access_token, refresh_token } = await loginResponse.json();
//!
//! // 3. Use access token for authenticated requests
//! const protectedResponse = await fetch('http://your-api.com/protected', {
//!   headers: { 'Authorization': `Bearer ${access_token}` }
//! });
//!
//! // 4. Refresh token when needed
//! const refreshResponse = await fetch('http://localhost:3000/token/refresh', {
//!   method: 'POST',
//!   headers: { 'Content-Type': 'application/json' },
//!   body: JSON.stringify({ refresh_token })
//! });
//! const { access_token: newAccessToken } = await refreshResponse.json();
//! ```
//!
//! ## OAuth2 Flow (JavaScript/TypeScript)
//!
//! ```javascript
//! // 1. Generate authorization URL
//! const state = crypto.randomUUID(); // Generate CSRF token
//! const authResponse = await fetch(
//!   `http://localhost:3000/oauth/google/auth?state=${state}&scopes=openid,email,profile`
//! );
//! const { authorization_url } = await authResponse.json();
//!
//! // 2. Redirect user to authorization URL
//! window.location.href = authorization_url;
//!
//! // 3. Handle callback automatically via redirect
//! // The OAuth2 callback endpoint will automatically redirect the user back to your
//! // frontend application with tokens in the URL fragment. Your frontend should
//! // handle this redirect and extract tokens from the URL fragment:
//!
//! // Example frontend redirect handler (e.g., at your redirect_frontend_uri)
//! function handleOAuthCallback() {
//!   const fragment = window.location.hash.substring(1); // Remove the '#'
//!   const params = new URLSearchParams(fragment);
//!
//!   if (params.has('error')) {
//!     const error = params.get('error');
//!     const errorDescription = params.get('error_description');
//!     console.error('OAuth error:', error, errorDescription);
//!     // Handle error
//!   } else {
//!     const accessToken = params.get('access_token');
//!     const refreshToken = params.get('refresh_token');
//!     const userId = params.get('user_id');
//!
//!     // Store tokens and proceed with authentication
//!     localStorage.setItem('accessToken', accessToken);
//!     localStorage.setItem('refreshToken', refreshToken);
//!     localStorage.setItem('userId', userId);
//!
//!     // Redirect to your app's main page or show success
//!     window.location.href = '/dashboard';
//!   }
//! }
//! ```
//!
//! ## cURL Examples
//!
//! ```bash
//! # Sign up
//! curl -X POST http://localhost:3000/signup \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"john_doe","password":"secure_password123"}'
//!
//! # Login
//! curl -X POST http://localhost:3000/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"john_doe","password":"secure_password123"}'
//!
//! # Refresh token
//! curl -X POST http://localhost:3000/token/refresh \
//!   -H "Content-Type: application/json" \
//!   -d '{"refresh_token":"your-refresh-token-here"}'
//!
//! # Validate token
//! curl -X POST http://localhost:3000/token/validate \
//!   -H "Content-Type: application/json" \
//!   -d '{"token":"your-access-token-here"}'
//!
//! # Get OAuth authorization URL
//! curl "http://localhost:3000/oauth/google/auth?state=csrf-token"
//!
//! # OAuth signup
//! curl -X POST http://localhost:3000/oauth/signup \
//!   -H "Content-Type: application/json" \
//!   -d '{"provider":"google","code":"auth-code","state":"csrf-token"}'
//! ```
//!
//! # Error Handling
//!
//! All error responses follow this format:
//! ```json
//! {
//!   "error": "Descriptive error message"
//! }
//! ```
//!
//! Common HTTP status codes:
//! - `200`: Success
//! - `400`: Bad Request (invalid JSON, missing fields)
//! - `401`: Unauthorized (invalid credentials, expired token)
//! - `409`: Conflict (username already exists)
//! - `500`: Internal Server Error
//!
//! # Server Setup Example
//! ```no_run
//! use authen::auth_service::AuthService;
//! use authen::web_axum::start_server;
//! use std::sync::Arc;
//! # async fn run(auth_service: Arc<AuthService>) {
//!     start_server(auth_service, None).await;
//! # }
//! ```
use crate::auth_service::AuthService;
#[cfg(feature = "axum")]
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;

/// Simple URL encoding function for OAuth2 callback parameters
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(feature = "axum")]
/// Starts the Axum web server with all authentication routes.
///
/// Binds to `0.0.0.0:3000` and serves the API endpoints for signup, login, health check,
/// token refresh, token validation, and OAuth2 integration (authorization URLs, callbacks,
/// OAuth login/signup). This function does not return unless the server fails.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance used for all authentication logic.
///
/// # Panics
/// Panics if the TCP listener cannot bind or the server fails to start.
pub async fn start_server(
    auth_service: Arc<AuthService>,
    address: impl Into<Option<std::net::SocketAddr>>,
) {
    use axum::serve;
    use tokio::net::TcpListener;
    let app = get_authen_axum_router(auth_service.clone());

    let addr = address
        .into()
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 3000)));
    log::info!("Axum server running at http://{addr}");
    let listener = TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
}

#[cfg(feature = "axum")]
/// Returns an Axum `Router` with all Authen authentication routes registered.
///
/// This is useful for integrating Authen's API into an existing Axum application or for testing.
/// Includes all authentication endpoints: credentials-based signup/login, token operations,
/// and OAuth2 integration with support for Google, GitHub, Discord, and Microsoft.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance.
///
/// # Returns
/// An Axum `Router` with all authentication, token, and OAuth2 endpoints.
pub fn get_authen_axum_router(auth_service: Arc<AuthService>) -> Router {
    use axum::routing::{get, post};
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", get(health_handler).post(health_handler))
        .route("/token/refresh", post(refresh_token_handler))
        .route("/token/validate", post(validate_token_handler))
        .route("/oauth/{provider}/auth", get(oauth_auth_handler))
        .route("/oauth/{provider}/callback", get(oauth_callback_handler))
        .route("/oauth/signup", post(oauth_signup_handler))
        .route("/oauth/login", post(oauth_login_handler))
        .with_state(auth_service)
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/signup` endpoint.
///
/// Accepts a JSON body with `username` and `password` fields, creates a new user,
/// and returns the user ID and identifier on success. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "username": "string", "password": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "identifier": "..." }`
/// - Error: `{ "error": "..." }`
async fn signup_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /signup request: {_body}");
    #[derive(Deserialize)]
    struct SignupRequest {
        username: String,
        password: String,
    }

    let req: Result<SignupRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(signup) => {
            log::info!(
                "Attempting signup for user: {username}",
                username = signup.username
            );
            // Use the new unified signup method with credentials
            match _auth
                .signup(crate::auth_service::SignupMethod::Credentials {
                    identifier: signup.username,
                    password: signup.password,
                })
                .await
            {
                Ok((user, _tokens)) => {
                    log::info!("Signup successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string())
                    })
                    .to_string().into_response()
                }
                Err(e) => {
                    log::error!("Signup failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid signup request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {e}")
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/login` endpoint.
///
/// Accepts a JSON body with `username` and `password` fields, authenticates the user,
/// and returns user info and tokens on success. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "username": "string", "password": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "identifier": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn login_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /login request: {_body}");
    #[derive(Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    let req: Result<LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            log::info!(
                "Attempting login for user: {username}",
                username = login.username
            );
            match _auth
                .login(crate::auth_service::LoginMethod::Credentials {
                    identifier: login.username,
                    password: login.password,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("Login successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string()),
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string().into_response()
                }
                Err(e) => {
                    log::error!("Login failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid login request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {e}")
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/health` endpoint.
///
/// Returns a simple "OK" string for health checks.
async fn health_handler() -> String {
    log::info!("Received /health request");
    "OK".to_string()
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/token/refresh` endpoint.
///
/// Accepts a JSON body with a `refresh_token` field, and returns new access and refresh tokens
/// if the refresh token is valid. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "refresh_token": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn refresh_token_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /token/refresh request: {_body}");
    #[derive(Deserialize)]
    struct RefreshRequest {
        refresh_token: String,
    }

    let req: Result<RefreshRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(refresh) => {
            log::info!("Attempting token refresh");
            match _auth.refresh_access_token(&refresh.refresh_token).await {
                Ok(tokens) => {
                    log::info!("Token refresh successful");
                    serde_json::json!({
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                    .into_response()
                }
                Err(e) => {
                    log::error!("Token refresh failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid refresh token request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {}", e)
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/token/validate` endpoint.
///
/// Accepts a JSON body with a `token` field, validates the access token, and returns
/// claims information if valid. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "token": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "valid": true, "subject": "...", "expiration": ... }`
/// - Error: `{ "valid": false, "error": "..." }`
async fn validate_token_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /token/validate request: {_body}");
    #[derive(Deserialize)]
    struct ValidateRequest {
        token: String,
    }

    let req: Result<ValidateRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(validate) => {
            log::info!("Validating access token");
            match _auth.validate_access_token(&validate.token).await {
                Ok(claims) => {
                    log::info!(
                        "Token valid for subject: {subject}",
                        subject = claims.get_subject()
                    );
                    serde_json::json!({
                        "valid": true,
                        "subject": claims.get_subject(),
                        "expiration": claims.get_expiration()
                    })
                    .to_string()
                    .into_response()
                }
                Err(e) => {
                    log::error!("Token validation failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "valid": false,
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid validate token request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {}", e)
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/oauth/{provider}/auth` endpoint.
///
/// Generates an OAuth2 authorization URL for the specified provider.
/// Accepts query parameters for state and optional scopes.
///
/// # Query Parameters
/// - `state`: Required state parameter for CSRF protection
/// - `scopes`: Optional comma-separated list of additional scopes
///
/// # Response JSON
/// - Success: `{ "auth_url": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_auth_handler(
    State(_auth): State<Arc<AuthService>>,
    Path(provider_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    log::info!("Received /oauth/{provider_str}/auth request with params: {params:?}");
    // Parse the provider from the path parameter
    let provider = match provider_str.to_lowercase().as_str() {
        "google" => crate::core::oauth::store::OAuth2Provider::Google,
        "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
        "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
        "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Unsupported OAuth2 provider: {}", provider_str)
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Get the state parameter (required)
    let state = match params.get("state") {
        Some(state) => state,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "Missing required 'state' parameter"
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Parse optional scopes parameter
    let scopes = params
        .get("scopes")
        .map(|s| s.split(',').map(|scope| scope.trim().to_string()).collect());

    // Generate the OAuth2 authorization URL
    match _auth
        .generate_oauth2_auth_url(provider, state, scopes)
        .await
    {
        Ok(auth_url) => {
            log::info!("Generated OAuth2 auth URL for provider: {provider_str}");
            serde_json::json!({
                "auth_url": auth_url
            })
            .to_string()
            .into_response()
        }
        Err(e) => {
            log::error!("OAuth2 auth URL generation failed: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": e.to_string()
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/oauth/{provider}/callback` endpoint.
///
/// Handles OAuth2 callback from providers. This endpoint would typically be called
/// by the OAuth2 provider after user authorization. Redirects user to the frontend
/// application with tokens included in the URL fragment.
///
/// # Query Parameters
/// - `code`: The authorization code from the provider
/// - `state`: The state parameter for CSRF verification
///
/// # Response
/// - Success: HTTP 302 redirect to frontend URI with tokens in URL fragment
/// - Error: JSON error response
async fn oauth_callback_handler(
    State(_auth): State<Arc<AuthService>>,
    Path(provider_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    log::info!("Received /oauth/{provider_str}/callback request with params: {params:?}");
    // Parse the provider from the path parameter
    let provider = match provider_str.to_lowercase().as_str() {
        "google" => crate::core::oauth::store::OAuth2Provider::Google,
        "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
        "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
        "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Unsupported OAuth2 provider: {}", provider_str)
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Get required parameters
    let code = match params.get("code") {
        Some(code) => code,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "Missing required 'code' parameter"
                })
                .to_string(),
            )
                .into_response();
        }
    };

    let state = match params.get("state") {
        Some(state) => state,
        None => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": "Missing required 'state' parameter"
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Get the frontend redirect URI for this provider
    let frontend_uri = match _auth.get_oauth2_redirect_frontend_uri(provider).await {
        Ok(uri) => uri,
        Err(e) => {
            log::error!("Failed to get frontend redirect URI: {e}");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "error": format!("Configuration error: {e}")
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Use the login method with OAuth2
    match _auth
        .login(crate::auth_service::LoginMethod::OAuth2 {
            provider,
            code: code.clone(),
            state: state.clone(),
        })
        .await
    {
        Ok((user, tokens)) => {
            log::info!(
                "OAuth2 callback login successful for user_id: {id}",
                id = user.id
            );

            // Build the redirect URL with tokens in the fragment
            let redirect_url = format!(
                "{}#access_token={}&refresh_token={}&user_id={}&token_type=Bearer&expires_in=3600",
                frontend_uri,
                url_encode(&tokens.access_token),
                url_encode(&tokens.refresh_token),
                url_encode(&user.id)
            );

            log::info!("Redirecting user to frontend: {redirect_url}");

            // Return HTTP 302 redirect
            axum::response::Redirect::permanent(&redirect_url).into_response()
        }
        Err(e) => {
            log::error!("OAuth2 callback login failed: {e}");

            // Redirect to frontend with error
            let error_redirect_url = format!(
                "{}#error={}&error_description={}",
                frontend_uri,
                url_encode("authentication_failed"),
                url_encode(&e.to_string())
            );

            log::info!("Redirecting user to frontend with error: {error_redirect_url}");
            axum::response::Redirect::permanent(&error_redirect_url).into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/oauth/signup` endpoint.
///
/// Handles OAuth2 signup/registration using an authorization code.
/// Creates a new user account or links to existing account.
///
/// # Request JSON
/// ```json
/// { "provider": "google|github|discord|microsoft", "code": "string", "state": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_signup_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /oauth/signup request: {_body}");
    #[derive(Deserialize)]
    struct OAuth2SignupRequest {
        provider: String,
        code: String,
        state: String,
    }

    let req: Result<OAuth2SignupRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(signup) => {
            log::info!(
                "Attempting OAuth2 signup for provider: {provider}",
                provider = signup.provider
            );
            // Parse the provider
            let provider = match signup.provider.to_lowercase().as_str() {
                "google" => crate::core::oauth::store::OAuth2Provider::Google,
                "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
                "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
                "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
                _ => {
                    log::error!(
                        "Unsupported OAuth2 provider: {provider}",
                        provider = signup.provider
                    );
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": format!("Unsupported OAuth2 provider: {}", signup.provider)
                        })
                        .to_string(),
                    )
                        .into_response();
                }
            };

            // Use the unified signup method with OAuth2
            match _auth
                .signup(crate::auth_service::SignupMethod::OAuth2 {
                    provider,
                    code: signup.code,
                    state: signup.state,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("OAuth2 signup successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                    .into_response()
                }
                Err(e) => {
                    log::error!("OAuth2 signup failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid OAuth2 signup request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {}", e)
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(feature = "axum")]
/// HTTP handler for the `/oauth/login` endpoint.
///
/// Handles OAuth2 login using an authorization code.
/// Authenticates existing user or creates account if needed.
///
/// # Request JSON
/// ```json
/// { "provider": "google|github|discord|microsoft", "code": "string", "state": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_login_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    log::info!("Received /oauth/login request: {_body}");
    #[derive(Deserialize)]
    struct OAuth2LoginRequest {
        provider: String,
        code: String,
        state: String,
    }

    let req: Result<OAuth2LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            log::info!(
                "Attempting OAuth2 login for provider: {provider}",
                provider = login.provider
            );
            // Parse the provider
            let provider = match login.provider.to_lowercase().as_str() {
                "google" => crate::core::oauth::store::OAuth2Provider::Google,
                "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
                "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
                "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
                _ => {
                    log::error!(
                        "Unsupported OAuth2 provider: {provider}",
                        provider = login.provider
                    );
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": format!("Unsupported OAuth2 provider: {}", login.provider)
                        })
                        .to_string(),
                    )
                        .into_response();
                }
            };

            // Use the unified login method with OAuth2
            match _auth
                .login(crate::auth_service::LoginMethod::OAuth2 {
                    provider,
                    code: login.code,
                    state: login.state,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("OAuth2 login successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                    .into_response()
                }
                Err(e) => {
                    log::error!("OAuth2 login failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid OAuth2 login request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {}", e)
                })
                .to_string(),
            )
                .into_response()
        }
    }
}
