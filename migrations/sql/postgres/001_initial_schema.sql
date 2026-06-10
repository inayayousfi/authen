--
-- Authen Database Schema
--
-- This schema defines the core tables for user authentication and credential management in the Authen system.
--
-- Tables:
--   - authen_users: Stores user identities (UUID primary key) with timestamps.
--   - authen_credentials: Stores user credentials, including unique identifier and password hash.
--   - authen_oauth_accounts: Stores OAuth account linkings to users.
--
-- Relationships:
--   - Each credential is linked to a user via user_id (foreign key).
--   - Each OAuth account is linked to a user via user_id (foreign key).
--   - Deleting a user cascades to delete their credentials and OAuth accounts.
--
-- Notes:
--   - Identifiers (e.g., email, username) must be unique.
--   - Passwords are stored as secure hashes, not plaintext.
--   - OAuth accounts are identified by provider and provider_user_id combination.
--
CREATE TABLE authen_users
(
  id UUID PRIMARY KEY,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE authen_credentials
(
  user_id UUID PRIMARY KEY,
  identifier VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES authen_users(id) ON DELETE CASCADE
);

CREATE TABLE authen_oauth_accounts
(
  user_id UUID NOT NULL,
  provider VARCHAR(50) NOT NULL,
  provider_user_id VARCHAR(255) NOT NULL,
  email VARCHAR(255),
  name VARCHAR(255),
  avatar_url TEXT,
  verified_email BOOLEAN,
  locale VARCHAR(10),
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  raw_data JSONB,
  PRIMARY KEY (user_id, provider),
  UNIQUE (provider, provider_user_id),
  FOREIGN KEY (user_id) REFERENCES authen_users(id) ON DELETE CASCADE
);

-- Index for faster OAuth lookups by provider and provider_user_id
CREATE INDEX idx_oauth_provider_user ON authen_oauth_accounts(provider, provider_user_id);

-- Index for faster OAuth lookups by email
CREATE INDEX idx_oauth_email ON authen_oauth_accounts(email) WHERE email IS NOT NULL;

-- Tracks the applied database schema version for migrations.
CREATE TABLE authen_version(version bigint NOT NULL);

INSERT INTO authen_version(version) VALUES (1);
