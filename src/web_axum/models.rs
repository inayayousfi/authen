use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use crate::{
    core::{oauth::store::OAuth2Provider, token::TokenPair, user::User},
    error::AuthError,
};

use super::response::ApiError;

#[derive(Deserialize)]
pub(crate) struct CredentialsRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub(crate) struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub(crate) struct ValidateTokenRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub(crate) struct OAuthAuthQuery {
    pub state: String,
    pub scopes: Option<String>,
}

impl OAuthAuthQuery {
    pub fn scopes(&self) -> Option<Vec<String>> {
        self.scopes.as_ref().map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Deserialize)]
pub(crate) struct OAuthCodeRequest {
    pub provider: String,
    pub code: String,
    pub state: String,
}

#[derive(Serialize)]
pub(crate) struct UserResponse {
    pub id: String,
    pub identifier: Option<String>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            identifier: user.credentials.map(|credentials| credentials.identifier),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct LoginResponse {
    pub id: String,
    pub identifier: Option<String>,
    pub access_token: String,
    pub refresh_token: String,
}

impl LoginResponse {
    pub fn from_user_and_tokens(user: User, tokens: TokenPair) -> Self {
        Self {
            id: user.id,
            identifier: user.credentials.map(|credentials| credentials.identifier),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl From<TokenPair> for TokenPairResponse {
    fn from(tokens: TokenPair) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            id: None,
        }
    }
}

impl TokenPairResponse {
    pub fn from_user_and_tokens(user: User, tokens: TokenPair) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            id: Some(user.id),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ValidateTokenResponse {
    pub valid: bool,
    pub subject: String,
    pub expiration: usize,
}

#[derive(Serialize)]
pub(crate) struct OAuthAuthUrlResponse {
    pub auth_url: String,
}

#[derive(Serialize)]
pub(crate) struct UserProfileResponse {
    pub id: String,
    pub identifier: Option<String>,
    pub oauth_accounts: Vec<OAuthAccountResponse>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl From<User> for UserProfileResponse {
    fn from(user: User) -> Self {
        let mut oauth_accounts: Vec<_> = user
            .oauth_accounts
            .into_values()
            .map(OAuthAccountResponse::from)
            .collect();

        oauth_accounts.sort_by_key(|account| account.provider.display_name());

        Self {
            id: user.id,
            identifier: user.credentials.map(|credentials| credentials.identifier),
            oauth_accounts,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct OAuthAccountResponse {
    pub provider: OAuth2Provider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub verified_email: Option<bool>,
    pub locale: Option<String>,
}

impl From<crate::core::oauth::store::OAuth2UserInfo> for OAuthAccountResponse {
    fn from(info: crate::core::oauth::store::OAuth2UserInfo) -> Self {
        Self {
            provider: info.provider,
            provider_user_id: info.provider_user_id,
            email: info.email,
            name: info.name,
            avatar_url: info.avatar_url,
            verified_email: info.verified_email,
            locale: info.locale,
        }
    }
}

pub(crate) fn parse_oauth_provider(value: &str) -> Result<OAuth2Provider, ApiError> {
    match value.to_lowercase().as_str() {
        "google" => Ok(OAuth2Provider::Google),
        "github" => Ok(OAuth2Provider::GitHub),
        "discord" => Ok(OAuth2Provider::Discord),
        "microsoft" => Ok(OAuth2Provider::Microsoft),
        _ => Err(ApiError::bad_request(AuthError::InvalidInput(format!(
            "Unsupported OAuth2 provider: {value}"
        )))),
    }
}
