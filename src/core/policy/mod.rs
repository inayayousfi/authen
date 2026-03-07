//! Security policy module.
//!
//! This module defines security policies and rules for authentication,
//! such as password complexity requirements. It provides the [`PasswordPolicy`] struct,
//! which allows you to specify and validate password strength requirements.
//!
//! # Example
//!
//! ```rust
//! use authen::core::policy::PasswordPolicy;
//!
//! let policy = PasswordPolicy::default();
//! assert!(policy.validate_password("Str0ng!Passw0rd").is_ok());
//! ```

use crate::error::AuthError;

/// Represents the requirements for a strong password.
///
/// This struct allows you to configure password complexity rules such as minimum length,
/// and whether to require uppercase, lowercase, digit, and special characters.
///
/// # Fields
/// - `min_length`: Minimum number of characters required.
/// - `require_uppercase`: If `true`, at least one uppercase letter is required.
/// - `require_lowercase`: If `true`, at least one lowercase letter is required.
/// - `require_digit`: If `true`, at least one digit is required.
/// - `require_special_char`: If `true`, at least one non-alphanumeric character is required.
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special_char: bool,
}

impl Default for PasswordPolicy {
    /// Returns a [`PasswordPolicy`] with strong default requirements:
    ///
    /// - Minimum length: 12
    /// - Requires uppercase, lowercase, digit, and special character
    fn default() -> Self {
        PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
        }
    }
}

impl PasswordPolicy {
    /// Validates whether a password meets the requirements defined by this policy.
    ///
    /// # Arguments
    /// * `password` - The password string to validate.
    ///
    /// # Returns
    /// * `Ok(())` if the password satisfies all requirements.
    /// * `Err(AuthError)` with a descriptive message if any requirement is not met.
    ///
    /// # Example
    /// ```rust
    /// use authen::core::policy::PasswordPolicy;
    /// let policy = PasswordPolicy::default();
    /// assert!(policy.validate_password("Str0ng!Passw0rd").is_ok());
    /// assert!(policy.validate_password("weak").is_err());
    /// ```
    pub fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.min_length {
            return Err(AuthError::InvalidInput(format!(
                "Password must be at least {} characters long.",
                self.min_length
            )));
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one uppercase letter.".to_string(),
            ));
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one lowercase letter.".to_string(),
            ));
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one digit.".to_string(),
            ));
        }
        if self.require_special_char && !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one special character.".to_string(),
            ));
        }
        Ok(())
    }
}
