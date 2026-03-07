use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, post},
};

use crate::auth_service::AuthService;

use super::{handlers, middleware::auth_context_middleware};

/// Starts the Axum web server with all Authen routes registered.
///
/// The server binds to `0.0.0.0:3000` by default and serves credential-based
/// authentication, token utilities, OAuth2 endpoints, and the authenticated
/// user endpoint powered by auth-context middleware.
///
/// # Arguments
/// - `auth_service`: Shared authentication service used by all handlers.
/// - `address`: Optional socket address override. When omitted, the server uses
///   `0.0.0.0:3000`.
///
/// # Panics
/// Panics if the TCP listener cannot bind or the Axum server fails to start.
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

/// Returns an Axum router with Authen's HTTP API mounted.
///
/// The returned router includes the full authentication surface as well as the
/// auth-context middleware that resolves a bearer token into [`super::AuthenticatedUser`]
/// and makes it available to downstream handlers through request extensions.
///
/// # Registered routes
/// - `POST /signup`
/// - `POST /login`
/// - `GET|POST /health`
/// - `GET /me`
/// - `POST /token/refresh`
/// - `POST /token/validate`
/// - `GET /oauth/{provider}/auth`
/// - `GET /oauth/{provider}/callback`
/// - `POST /oauth/signup`
/// - `POST /oauth/login`
pub fn get_authen_axum_router(auth_service: Arc<AuthService>) -> Router {
    let auth_context_layer =
        middleware::from_fn_with_state(auth_service.clone(), auth_context_middleware);

    Router::new()
        .route("/signup", post(handlers::auth::signup))
        .route("/login", post(handlers::auth::login))
        .route(
            "/health",
            get(handlers::system::health).post(handlers::system::health),
        )
        .route("/me", get(handlers::system::me))
        .route("/token/refresh", post(handlers::token::refresh))
        .route("/token/validate", post(handlers::token::validate))
        .route("/oauth/{provider}/auth", get(handlers::oauth::authorize))
        .route("/oauth/{provider}/callback", get(handlers::oauth::callback))
        .route("/oauth/signup", post(handlers::oauth::signup))
        .route("/oauth/login", post(handlers::oauth::login))
        .layer(auth_context_layer)
        .with_state(auth_service)
}
