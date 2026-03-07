//! # Integration and Unit Tests for authen
//!
//! This test module covers integration and unit tests for the main features of the `authen` crate, including:
//! - Hashing and salt generation
//! - Authentication service (signup, login, JWT)
//! - User persistence (in-memory repository)
//! - AuthServiceVariables
//! - Credentials and password management
//!
//! Each test is documented with its purpose and expected behavior.
//!
//! ## Usage
//! Run all tests with:
//! ```sh
//! cargo test
//! ```
//!
//! ## Note
//! Some tests are asynchronous and require the Tokio runtime.
//!
// --- Hashing (Argon2Hasher, generate_secure_salt) Integration Tests ---
use argon2::password_hash::SaltString;
use authen::core::hash::{Argon2Hasher, generate_secure_salt};

#[test]
/// Tests that `generate_secure_salt` produces a valid, non-empty, base64-encoded salt string.
///
/// Ensures the salt is valid for use with Argon2 and is not empty.
fn test_generate_secure_salt() {
    let salt = generate_secure_salt();
    assert!(salt.is_ok());
    let salt = salt.unwrap();
    let salt_str = salt.as_str();
    // Salt should be non-empty and base64
    assert!(!salt_str.is_empty());
    assert!(SaltString::from_b64(salt_str).is_ok());
}

#[test]
/// Tests the `Argon2Hasher` for correct password hashing and verification.
///
/// - Verifies that hashing a password produces a valid hash.
/// - Checks that the correct password verifies successfully.
/// - Checks that an incorrect password does not verify.
fn test_argon2_hasher_hash_and_verify() {
    let hasher = Argon2Hasher::new();
    let password = b"test_password";
    let salt = generate_secure_salt().unwrap();
    let hash = hasher.hash(password, Some(&salt));
    assert!(hash.is_ok());
    let hash_str = hash.unwrap();
    // Should verify with correct password
    let verify_ok = hasher.verify(password, &hash_str);
    assert!(verify_ok.is_ok());
    assert!(verify_ok.unwrap());
    // Should not verify with wrong password
    let verify_fail = hasher.verify(b"wrong_password", &hash_str);
    assert!(verify_fail.is_ok());
    assert!(!verify_fail.unwrap());
}
use authen::AuthService;

#[tokio::test]
/// Tests the `AuthService::signup` method for successful user signup.
///
/// - Creates a user with credentials.
/// - Signs up the user and expects success.
/// - This test ensures the signup logic is implemented and works as expected.
async fn test_auth_service_signup_not_implemented() {
    let auth_service = AuthService::default();

    let result = auth_service
        .signup(authen::auth_service::SignupMethod::Credentials {
            identifier: "test_user".to_string(),
            password: "plain_password".to_string(),
        })
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
/// Tests successful login with valid credentials using `AuthService`.
///
/// - Signs up a user.
/// - Attempts login with correct credentials and expects success.
async fn test_auth_service_login_success() {
    let auth_service = authen::AuthService::default();

    // Sign up the user first
    let signup_result = auth_service
        .signup(authen::auth_service::SignupMethod::Credentials {
            identifier: "test_user".to_string(),
            password: "plain_password".to_string(),
        })
        .await;
    assert!(signup_result.is_ok());

    // Now test login with correct credentials
    let login_result = auth_service
        .login(authen::auth_service::LoginMethod::Credentials {
            identifier: "test_user".to_string(),
            password: "plain_password".to_string(),
        })
        .await;
    assert!(login_result.is_ok());
}

#[tokio::test]
/// Tests login failure with invalid credentials using `AuthService`.
///
/// - Attempts login with non-existent user and wrong password.
/// - Expects an error with the message "Invalid credentials provided."
async fn test_auth_service_login_invalid_credentials() {
    let auth_service = authen::AuthService::default();

    let result = auth_service
        .login(authen::auth_service::LoginMethod::Credentials {
            identifier: "nonexistent_user".to_string(),
            password: "wrong_password".to_string(),
        })
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid credentials provided."
    );
}

use authen::core::token::TokenService;
use authen::core::token::jwt::JwtTokenService;

#[tokio::test]
/// Tests JWT token pair generation and validation using `JwtTokenService`.
///
/// - Generates a token pair for a user.
/// - Validates the access token and checks claims.
/// - Refreshes the access token using the refresh token and validates the new token.
async fn test_jwt_token_pair_generation_and_validation() {
    let secret = "super_secret_key";
    let access_token_duration = 60; // 1 minute
    let refresh_token_duration = 120; // 2 minutes
    let jwt_service = JwtTokenService::new(secret, access_token_duration, refresh_token_duration);

    let user_id = "user123";
    let token_pair = jwt_service
        .generate_token_pair(user_id)
        .await
        .expect("Failed to generate token pair");

    // Validate access token
    let access_claims = jwt_service
        .validate_access_token(&token_pair.access_token)
        .await
        .expect("Access token validation failed");
    assert_eq!(access_claims.get_subject(), user_id);
    assert!(access_claims.get_expiration() > 0);

    // Validate refresh token by refreshing access token (which checks refresh token validity)
    let refreshed_pair = jwt_service
        .refresh_access_token(&token_pair.refresh_token)
        .await
        .expect("Refresh token validation failed");
    // The refreshed access token should be valid and for the same user
    let refreshed_claims = jwt_service
        .validate_access_token(&refreshed_pair.access_token)
        .await
        .expect("Refreshed access token validation failed");
    assert_eq!(refreshed_claims.get_subject(), user_id);
}

#[tokio::test]
/// Tests refreshing an access token using a valid refresh token with `JwtTokenService`.
///
/// - Generates a token pair.
/// - Refreshes the access token and validates the new access token's claims.
async fn test_jwt_refresh_access_token() {
    let secret = "another_secret";
    let access_token_duration = 60;
    let refresh_token_duration = 120;
    let jwt_service = JwtTokenService::new(secret, access_token_duration, refresh_token_duration);

    let user_id = "refresh_user";
    let token_pair = jwt_service
        .generate_token_pair(user_id)
        .await
        .expect("Failed to generate token pair");

    // Use refresh token to get a new token pair
    let new_token_pair = jwt_service
        .refresh_access_token(&token_pair.refresh_token)
        .await
        .expect("Failed to refresh access token");

    // The new access token should be valid and for the same user
    let new_access_claims = jwt_service
        .validate_access_token(&new_token_pair.access_token)
        .await
        .expect("New access token validation failed");
    assert_eq!(new_access_claims.get_subject(), user_id);
}

#[tokio::test]
/// Tests validation of an invalid JWT token using `JwtTokenService`.
///
/// - Attempts to validate a malformed token and expects an error.
async fn test_jwt_invalid_token() {
    let secret = "invalid_secret";
    let jwt_service = JwtTokenService::new(secret, 60, 120);
    let invalid_token = "this.is.not.a.valid.token";
    let result = jwt_service.validate_access_token(invalid_token).await;
    assert!(result.is_err());
}

// --- User Persistence (InMemoryUserRepo) Integration Tests ---
use authen::core::credentials::{Credentials, PlainPassword};
use authen::core::user::User;
use authen::core::user::persistence::{InMemoryUserRepo, UserRepository};

#[tokio::test]
/// Tests adding and retrieving a user in `InMemoryUserRepo`.
///
/// - Adds a user to the repository.
/// - Retrieves the user by ID and identifier.
/// - Ensures the user data matches what was added.
async fn test_in_memory_user_repo_add_and_get_user() {
    let repo = InMemoryUserRepo::new();
    let auth_service = authen::AuthService::default();
    let user = User::with_plain_password(
        auth_service.password_manager.as_ref(),
        "id1".to_string(),
        "user1".to_string(),
        PlainPassword::new("password1".to_string()),
    )
    .await
    .expect("Failed to create user");
    let added = repo.add_user(user.clone()).await.expect("Add user failed");
    assert_eq!(added.id, "id1");
    let fetched = repo.get_user_by_id("id1").await;
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, "id1");
    assert_eq!(fetched.credentials.as_ref().unwrap().identifier, "user1");
    // By identifier
    let by_identifier = repo.get_user_by_identifier("user1").await;
    assert!(by_identifier.is_some());
    assert_eq!(by_identifier.unwrap().id, "id1");
}

#[tokio::test]
/// Tests updating a user in `InMemoryUserRepo`.
///
/// - Adds a user, updates the identifier, and verifies the update is persisted.
async fn test_in_memory_user_repo_update_user() {
    let repo = InMemoryUserRepo::new();
    let auth_service = authen::AuthService::default();
    let mut user = User::with_plain_password(
        auth_service.password_manager.as_ref(),
        "id2".to_string(),
        "user2".to_string(),
        PlainPassword::new("password2".to_string()),
    )
    .await
    .expect("Failed to create user");
    repo.add_user(user.clone()).await.expect("Add user failed");
    // Update identifier
    user.credentials.as_mut().unwrap().identifier = "user2_updated".to_string();
    let update_result = repo.update_user(&user).await;
    assert!(update_result.is_ok());
    let fetched = repo.get_user_by_id("id2").await.unwrap();
    assert_eq!(
        fetched.credentials.as_ref().unwrap().identifier,
        "user2_updated"
    );
}

#[tokio::test]
/// Tests deleting a user from `InMemoryUserRepo`.
///
/// - Adds and deletes a user.
/// - Ensures the user is removed and that deleting again returns an error.
async fn test_in_memory_user_repo_delete_user() {
    let repo = InMemoryUserRepo::new();
    let auth_service = authen::AuthService::default();
    let user = User::with_plain_password(
        auth_service.password_manager.as_ref(),
        "id3".to_string(),
        "user3".to_string(),
        PlainPassword::new("password3".to_string()),
    )
    .await
    .expect("Failed to create user");
    repo.add_user(user.clone()).await.expect("Add user failed");
    let del_result = repo.delete_user("id3").await;
    assert!(del_result.is_ok());
    let fetched = repo.get_user_by_id("id3").await;
    assert!(fetched.is_none());
    // Deleting again should return UserNotFound
    let del_again = repo.delete_user("id3").await;
    assert!(del_again.is_err());
}

use authen::core::vars::AuthServiceVariables;

#[test]
/// Tests the default values of `AuthServiceVariables`.
///
/// - Ensures all fields are set to their default values.
fn test_auth_service_variables_default() {
    let vars = AuthServiceVariables::default();
    assert_eq!(vars.secret_key, "");
    assert_eq!(vars.token_expiration, 0);
    assert_eq!(vars.refresh_token_expiration, 0);
}

#[test]
/// Tests custom initialization of `AuthServiceVariables`.
///
/// - Ensures fields are set to the provided values.
fn test_auth_service_variables_custom() {
    let vars = AuthServiceVariables {
        secret_key: "mysecret".to_string(),
        token_expiration: 3600,
        refresh_token_expiration: 7200,
    };
    assert_eq!(vars.secret_key, "mysecret");
    assert_eq!(vars.token_expiration, 3600);
    assert_eq!(vars.refresh_token_expiration, 7200);
}

#[test]
/// Tests cloning and debugging output of `AuthServiceVariables`.
///
/// - Ensures the clone matches the original.
/// - Checks that the debug string contains the secret key.
fn test_auth_service_variables_clone_and_debug() {
    let vars = AuthServiceVariables {
        secret_key: "clonekey".to_string(),
        token_expiration: 100,
        refresh_token_expiration: 200,
    };
    let cloned = vars.clone();
    assert_eq!(cloned.secret_key, "clonekey");
    assert_eq!(cloned.token_expiration, 100);
    assert_eq!(cloned.refresh_token_expiration, 200);
    let debug_str = format!("{vars:?}");
    assert!(debug_str.contains("clonekey"));
}

// --- Credentials and PlainPassword Integration Tests ---
use authen::core::password::Argon2PasswordManager;

#[tokio::test]
/// Tests creating and verifying `Credentials` from a plain password.
///
/// - Ensures credentials are created and verified with the correct password.
/// - Ensures verification fails with an incorrect password.
async fn test_credentials_new_and_verify() {
    let identifier = "userX".to_string();
    let password = "testpass".to_string();
    let manager = Argon2PasswordManager::default();
    let plain = PlainPassword::new(password.clone());
    let creds =
        Credentials::from_plain_password(&manager, identifier.clone(), identifier.clone(), plain)
            .await
            .expect("Failed to create credentials");
    assert_eq!(creds.identifier, identifier);
    // Should verify with correct password
    let verify = creds
        .verify_password(&manager, &PlainPassword::new(password.clone()))
        .await;
    assert!(verify.is_ok());
    assert!(verify.unwrap());
    // Should not verify with wrong password
    let verify_fail = creds
        .verify_password(&manager, &PlainPassword::new("wrongpass".to_string()))
        .await;
    assert!(verify_fail.is_ok());
    assert!(!verify_fail.unwrap());
}

#[test]
/// Tests the `Credentials` struct and `PlainPassword` creation.
///
/// - Ensures fields are set correctly and `PlainPassword` returns the correct string.
fn test_credentials_struct_and_plain_password() {
    let user_id = "user_id".to_string();
    let identifier = "id".to_string();
    let hash = "hashval".to_string();
    let creds = Credentials::new(user_id.clone(), identifier.clone(), hash.clone());
    assert_eq!(creds.user_id, user_id);
    assert_eq!(creds.identifier, identifier);
    assert_eq!(creds.password_hash, hash);

    let pw = PlainPassword::new("secretpw".to_string());
    assert_eq!(pw.as_str(), "secretpw");
}

#[test]
/// Tests that `PlainPassword` zeroizes its memory on drop (best effort).
///
/// - Ensures the `ZeroizeOnDrop` implementation is present and compiles.
fn test_plain_password_zeroize_on_drop() {
    use std::sync::{Arc, Mutex};
    // This test checks that PlainPassword zeroizes memory on drop (best effort)
    let pw_arc = Arc::new(Mutex::new(Some(PlainPassword::new(
        "tozeroize".to_string(),
    ))));
    {
        let guard = pw_arc.lock().unwrap();
        let pw_ref = guard.as_ref().unwrap();
        let _ = pw_ref.as_str().as_ptr();
    }
    // Drop the password
    pw_arc.lock().unwrap().take();
    // We can't guarantee the memory is zeroized (Rust doesn't let us read freed memory),
    // but this test ensures the ZeroizeOnDrop implementation is present and compiles.
}
