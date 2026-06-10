use std::sync::Arc;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};

use crate::{
    AuthError,
    auth_service::AuthService,
    web_axum::{
        models::{
            RefreshTokenRequest, TokenPairResponse, ValidateTokenRequest, ValidateTokenResponse,
        },
        response::{ApiError, ApiResult},
    },
};

pub(crate) async fn refresh(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<RefreshTokenRequest>, JsonRejection>,
) -> ApiResult<TokenPairResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;

    let tokens = auth_service
        .refresh_access_token(&payload.refresh_token)
        .await
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;

    Ok(Json(TokenPairResponse::from(tokens)))
}

pub(crate) async fn validate(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<ValidateTokenRequest>, JsonRejection>,
) -> ApiResult<ValidateTokenResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;

    match auth_service.validate_access_token(&payload.token).await {
        Ok(claims) => Ok(Json(ValidateTokenResponse {
            valid: true,
            subject: claims.get_subject().to_string(),
            expiration: claims.get_expiration(),
        })),
        Err(
            AuthError::InvalidToken(_) | AuthError::TokenExpired | AuthError::TokenValidation(_),
        ) => Ok(Json(ValidateTokenResponse {
            valid: false,
            subject: String::new(),
            expiration: 0,
        })),
        Err(err) => Err(ApiError::internal(format!(
            "token validation service error: {}",
            err
        ))),
    }
}
