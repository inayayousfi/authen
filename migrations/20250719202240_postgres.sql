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
