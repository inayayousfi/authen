//! # Axum Web Server Example for Authen
//!
//! This example demonstrates how to run the authentication service as a web server using [Axum](https://github.com/tokio-rs/axum).
//!
//! ## Overview
//!
//! This example launches a simple authentication web server that exposes several endpoints for user signup, login, health checks, token refresh, and token validation. It uses in-memory storage and is intended for demonstration and testing purposes only.
//!
//! ## Usage
//!
//! To run the example, use the following command:
//!
//! ```bash
//! cargo run --manifest-path examples/web_server/Cargo.toml
//! ```
//!
//! The server will start and listen on `http://0.0.0.0:3000`.
//!
//! ## Endpoints
//!
//! ### `POST /signup`
//! Registers a new user with a username and password.
//!
//! **Request Body:**
//! ```json
//! { "username": "alice", "password": "secret123" }
//! ```
//!
//! **Example cURL:**
//! ```bash
//! curl -X POST http://localhost:3000/signup \
//!   -H "Content-Type: application/json" \
//!   -d '{"username": "alice", "password": "secret123"}'
//! ```
//!
//! ### `POST /login`
//! Authenticates a user and returns access and refresh tokens.
//!
//! **Request Body:**
//! ```json
//! { "username": "alice", "password": "secret123" }
//! ```
//!
//! **Example cURL:**
//! ```bash
//! curl -X POST http://localhost:3000/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username": "alice", "password": "secret123"}'
//! ```
//!
//! ### `POST /health`
//! Checks the health of the server.
//!
//! **Example cURL:**
//! ```bash
//! curl -X POST http://localhost:3000/health
//! ```
//!
//! ### `GET /health`
//! Checks the health of the server (GET variant).
//!
//! **Example cURL:**
//! ```bash
//! curl http://localhost:3000/health
//! ```
//!
//! ### `POST /token/refresh`
//! Refreshes an access token using a valid refresh token.
//!
//! **Request Body:**
//! ```json
//! { "refresh_token": "<refresh_token>" }
//! ```
//!
//! **Example cURL:**
//! ```bash
//! curl -X POST http://localhost:3000/token/refresh \
//!   -H "Content-Type: application/json" \
//!   -d '{"refresh_token": "<refresh_token>"}'
//! ```
//!
//! ### `POST /token/validate`
//! Validates an access token.
//!
//! **Request Body:**
//! ```json
//! { "token": "<access_token>" }
//! ```
//!
//! **Example cURL:**
//! ```bash
//! curl -X POST http://localhost:3000/token/validate \
//!   -H "Content-Type: application/json" \
//!   -d '{"token": "<access_token>"}'
//! ```
//!
//! ## Notes
//!
//! - Requires the `web` feature flag to be enabled.
//! - Uses in-memory storage (no persistence between restarts).
//! - For production use, implement persistent storage and proper security measures.
//!
//! ## Example
//!
//! ```rust
//! use authen::{AuthService, web_axum::start_server};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     env_logger::init();
//!     let auth_service = Arc::new(AuthService::default());
//!     #[cfg(feature = "axum")]
//!     start_server(auth_service).await;
//!     #[cfg(not(feature = "web"))]
//!     println!("Please enable the 'web' feature to run the web server example.");
//! }
//! ```
//!
//! ---
//!
//! # Source
//!
//! The code below shows the entry point for the Axum web server example.

use authen::{AuthService, web_axum::start_server};
use std::sync::Arc;

/// Entry point for the Axum web server example.
///
/// Initializes logging, creates an in-memory [`AuthService`], and starts the Axum web server if the `web` feature is enabled.
///
/// # Behavior
/// - If the `web` feature is enabled, the server is started and listens on `0.0.0.0:3000`.
/// - If the `web` feature is not enabled, a message is printed to enable the feature.
///
/// # Panics
/// This function will panic if the Tokio runtime cannot be started.
#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    let auth_service = Arc::new(AuthService::default());
    start_server(auth_service, None).await;
}
