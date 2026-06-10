use std::sync::Arc;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};

use crate::{
    auth_service::{AuthService, LoginMethod, SignupMethod},
    error::AuthError,
    web_axum::{
        models::{CredentialsRequest, LoginResponse, UserResponse},
        response::{ApiError, ApiResult},
    },
};

pub(crate) async fn signup(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<CredentialsRequest>, JsonRejection>,
) -> ApiResult<UserResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;

    let (user, _) = auth_service
        .signup(SignupMethod::Credentials {
            identifier: payload.username,
            password: payload.password,
        })
        .await
        .map_err(|error| match error {
            AuthError::UserAlreadyExists => ApiError::conflict(error),
            AuthError::SignupError(message)
                if message.to_lowercase().contains("already exists") =>
            {
                ApiError::conflict(AuthError::SignupError(message))
            }
            _ => ApiError::bad_request(error),
        })?;

    Ok(Json(UserResponse::from(user)))
}

pub(crate) async fn login(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<CredentialsRequest>, JsonRejection>,
) -> ApiResult<LoginResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;

    let (user, tokens) = auth_service
        .login(LoginMethod::Credentials {
            identifier: payload.username,
            password: payload.password,
        })
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => ApiError::unauthorized(error.to_string()),
            _ => ApiError::bad_request(error),
        })?;

    Ok(Json(LoginResponse::from_user_and_tokens(user, tokens)))
}
