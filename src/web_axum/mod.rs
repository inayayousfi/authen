//! Web server and HTTP API integration for Authen using Axum.
//!
//! This module provides the Axum-based web server and HTTP API endpoints for
//! authentication, user management, token operations, and OAuth2 integration.
//! It exposes routes for signup, login, health checks, token refresh, token
//! validation, OAuth2 authorization, OAuth2 callbacks, and authenticated user
//! resolution through middleware.
//!
//! All endpoint responses are JSON except for the OAuth callback route, which
//! redirects to the configured frontend URI with authentication details in the
//! URL fragment.
//!
//! # Features
//! - Available when the `axum` feature is enabled.
//! - Designed around the shared [`crate::AuthService`] abstraction.
//! - Includes auth-context middleware for bearer-token user resolution.
//! - Supports OAuth2 flows for Google, GitHub, Discord, and Microsoft.
//!
//! # Routes
//! - `POST /signup`: Register a user with username and password.
//! - `POST /login`: Authenticate a user and issue access and refresh tokens.
//! - `GET|POST /health`: Health check endpoint.
//! - `GET /me`: Return the authenticated user resolved from a bearer token.
//! - `POST /token/refresh`: Refresh an access token with a refresh token.
//! - `POST /token/validate`: Validate an access token and inspect claims.
//! - `GET /oauth/{provider}/auth`: Generate an OAuth2 authorization URL.
//! - `GET /oauth/{provider}/callback`: Complete OAuth login and redirect.
//! - `POST /oauth/signup`: Create a user from an OAuth2 authorization code.
//! - `POST /oauth/login`: Log in with an OAuth2 authorization code.
//!
//! # Middleware usage
//! Use [`AuthenticatedUser`] in a handler signature to require authentication,
//! or [`OptionalAuthenticatedUser`] to read the current user when present.
//!
//! ```no_run
//! use authen::{AuthService, web_axum::{AuthenticatedUser, get_authen_axum_router}};
//! use axum::{Json, Router, routing::get};
//! use std::sync::Arc;
//!
//! async fn protected_route(user: AuthenticatedUser) -> Json<String> {
//!     Json(user.id.clone())
//! }
//!
//! # fn build_router() {
//! let auth_service = Arc::new(AuthService::default());
//! let app: Router = get_authen_axum_router(auth_service)
//!     .route("/protected", get(protected_route));
//! # let _ = app;
//! # }
//! ```

mod app;
mod handlers;
mod middleware;
mod models;
mod response;

pub use app::{get_authen_axum_router, start_server};
pub use middleware::{AuthenticatedUser, OptionalAuthenticatedUser, auth_context_middleware};
