use axum::Json;

use crate::web_axum::{
    middleware::AuthenticatedUser, models::UserProfileResponse, response::ApiResult,
};

pub(crate) async fn health() -> &'static str {
    "OK"
}

pub(crate) async fn me(user: AuthenticatedUser) -> ApiResult<UserProfileResponse> {
    Ok(Json(UserProfileResponse::from(user.0)))
}
