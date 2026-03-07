use std::{ops::Deref, sync::Arc};

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::Response,
};

use crate::{auth_service::AuthService, core::user::User};

use super::response::ApiError;

/// Extractor for a required authenticated user.
///
/// The value is attached by [`auth_context_middleware`] after reading an
/// `Authorization: Bearer <token>` header and resolving the user through the
/// [`AuthService`]. Handlers that include this extractor automatically return a
/// `401 Unauthorized` response when authentication is missing or invalid.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(pub User);

/// Extractor for an optional authenticated user.
///
/// This is useful for mixed public/private routes that can adapt their behavior
/// when a valid bearer token is present.
#[derive(Clone, Debug, Default)]
pub struct OptionalAuthenticatedUser(pub Option<User>);

#[derive(Clone, Debug)]
struct AuthenticationFailure {
    message: String,
}

impl Deref for AuthenticatedUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get::<AuthenticatedUser>().cloned() {
            return Ok(user);
        }

        if let Some(error) = parts.extensions.get::<AuthenticationFailure>() {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                error.message.clone(),
            ));
        }

        Err(ApiError::unauthorized("Authentication required"))
    }
}

impl<S> FromRequestParts<S> for OptionalAuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<AuthenticatedUser>()
                .cloned()
                .map(|user| user.0),
        ))
    }
}

/// Middleware that resolves the current authenticated user from a bearer token.
///
/// When the request includes `Authorization: Bearer <token>`, the middleware
/// attempts to load the matching user with [`AuthService::get_user_from_token`].
/// On success, an [`AuthenticatedUser`] is inserted into request extensions.
/// On failure, the error is recorded so a later [`AuthenticatedUser`] extractor
/// can return a consistent `401 Unauthorized` response.
pub async fn auth_context_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(token) = bearer_token(request.headers()) {
        match auth_service.get_user_from_token(token).await {
            Ok(user) => {
                request.extensions_mut().insert(AuthenticatedUser(user));
            }
            Err(error) => {
                request.extensions_mut().insert(AuthenticationFailure {
                    message: error.to_string(),
                });
            }
        }
    }

    next.run(request).await
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header_value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = header_value.strip_prefix("Bearer ")?.trim();

    if token.is_empty() {
        return None;
    }

    Some(token)
}
