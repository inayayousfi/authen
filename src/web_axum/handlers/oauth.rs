use std::sync::Arc;

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    response::Redirect,
};

use crate::{
    auth_service::{AuthService, LoginMethod, SignupMethod},
    web_axum::{
        models::{
            LoginResponse, OAuthAuthQuery, OAuthAuthUrlResponse, OAuthCallbackQuery,
            OAuthCodeRequest, TokenPairResponse, parse_oauth_provider,
        },
        response::{ApiError, ApiResult},
    },
};

pub(crate) async fn authorize(
    State(auth_service): State<Arc<AuthService>>,
    Path(provider): Path<String>,
    query: Result<Query<OAuthAuthQuery>, QueryRejection>,
) -> ApiResult<OAuthAuthUrlResponse> {
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    let provider = parse_oauth_provider(&provider)?;
    let scopes = query.scopes();

    let auth_url = auth_service
        .generate_oauth2_auth_url(provider, &query.state, scopes)
        .await
        .map_err(ApiError::bad_request)?;

    Ok(Json(OAuthAuthUrlResponse { auth_url }))
}

pub(crate) async fn callback(
    State(auth_service): State<Arc<AuthService>>,
    Path(provider): Path<String>,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Redirect, ApiError> {
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    let provider = parse_oauth_provider(&provider)?;
    let frontend_uri = auth_service
        .get_oauth2_redirect_frontend_uri(provider)
        .await
        .map_err(ApiError::internal)?;

    match auth_service
        .login(LoginMethod::OAuth2 {
            provider,
            code: query.code,
            state: query.state,
        })
        .await
    {
        Ok((user, tokens)) => {
            let redirect_url = format!(
                "{}#access_token={}&refresh_token={}&user_id={}&token_type=Bearer&expires_in=3600",
                frontend_uri,
                url_encode(&tokens.access_token),
                url_encode(&tokens.refresh_token),
                url_encode(&user.id)
            );

            Ok(Redirect::permanent(&redirect_url))
        }
        Err(error) => {
            let redirect_url = format!(
                "{}#error={}&error_description={}",
                frontend_uri,
                url_encode("authentication_failed"),
                url_encode(&error.to_string())
            );

            Ok(Redirect::permanent(&redirect_url))
        }
    }
}

pub(crate) async fn signup(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<OAuthCodeRequest>, JsonRejection>,
) -> ApiResult<TokenPairResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let provider = parse_oauth_provider(&payload.provider)?;

    let (user, tokens) = auth_service
        .signup(SignupMethod::OAuth2 {
            provider,
            code: payload.code,
            state: payload.state,
        })
        .await
        .map_err(ApiError::bad_request)?;

    Ok(Json(TokenPairResponse::from_user_and_tokens(user, tokens)))
}

pub(crate) async fn login(
    State(auth_service): State<Arc<AuthService>>,
    payload: Result<Json<OAuthCodeRequest>, JsonRejection>,
) -> ApiResult<LoginResponse> {
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let provider = parse_oauth_provider(&payload.provider)?;

    let (user, tokens) = auth_service
        .login(LoginMethod::OAuth2 {
            provider,
            code: payload.code,
            state: payload.state,
        })
        .await
        .map_err(ApiError::bad_request)?;

    Ok(Json(LoginResponse::from_user_and_tokens(user, tokens)))
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
