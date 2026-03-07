use axum::{
    Json,
    extract::rejection::{JsonRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub(crate) type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(error: impl ToString) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error.to_string())
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn internal(error: impl ToString) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Configuration error: {}", error.to_string()),
        )
    }

    pub fn from_json_rejection(rejection: JsonRejection) -> Self {
        Self::bad_request(format!("Invalid request body: {}", rejection.body_text()))
    }

    pub fn from_query_rejection(rejection: QueryRejection) -> Self {
        Self::bad_request(format!(
            "Invalid query parameters: {}",
            rejection.body_text()
        ))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}
