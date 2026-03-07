//! # CLI Example for Interacting with the Postgres User Repository
//!
//! This binary provides a command-line interface for interacting with a Postgres-backed user repository.
//! It demonstrates basic operations such as schema validation, user creation, and user retrieval.
//!
//! ## Usage
//!
//! ```sh
//! cargo run --manifest-path examples/pg/Cargo.toml -- <DATABASE_URL> <command> [args]
//! ```
//!
//! - `<DATABASE_URL>`: The Postgres connection string (e.g., `postgres://user:password@localhost:5432/authen`)
//! - `<command>`: One of the supported commands (see below)
//! - `[args]`: Additional arguments required by the command
//!
//! ## Supported Commands
//!
//! - `check_schema`: Validates the database schema for the user repository.
//!   - Example:
//!     ```sh
//!     cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" check_schema
//!     ```
//!
//! - `add_user <id> <identifier> <password_hash>`: Adds a new user to the repository.
//!   - `<id>`: The user's UUID (e.g., `11111111-1111-1111-1111-111111111111`)
//!   - `<identifier>`: The user's identifier (e.g., email address)
//!   - `<password_hash>`: The hashed password for the user
//!   - Example:
//!     ```sh
//!     cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" add_user 11111111-1111-1111-1111-111111111111 alice@example.com myhashedpassword
//!     ```
//!
//! - `get_user_by_id <id>`: Retrieves a user by their UUID.
//!   - Example:
//!     ```sh
//!     cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" get_user_by_id 11111111-1111-1111-1111-111111111111
//!     ```
//!
//! - `get_user_by_identifier <identifier>`: Retrieves a user by their identifier (e.g., email).
//!   - Example:
//!     ```sh
//!     cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" get_user_by_identifier alice@example.com
//!     ```
//!
//! ## Example
//!
//! ```sh
//! # Check schema
//! cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" check_schema
//!
//! # Add a user
//! cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" add_user 11111111-1111-1111-1111-111111111111 alice@example.com myhashedpassword
//!
//! # Get user by ID
//! cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" get_user_by_id 11111111-1111-1111-1111-111111111111
//!
//! # Get user by identifier
//! cargo run --manifest-path examples/pg/Cargo.toml -- "postgres://myuser:mypassword@localhost:5432/authen" get_user_by_identifier alice@example.com
//! ```
//!
//! ## Notes
//!
//! - This example is intended for demonstration and development purposes.
//! - Ensure the database schema is up to date before running commands.
//! - Passwords should be securely hashed before being stored.
//!
//! ---
//!
//! See the project README for more details.

use authen::core::user::persistence::traits::UserRepository;
use authen::{core::user::User, postgres::PgUserRepo};
use sqlx::PgConnection;
use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <DATABASE_URL> <command> [args]", args[0]);
        eprintln!("Commands:");
        eprintln!("  check_schema");
        eprintln!("  add_user <id> <identifier> <password_hash>");
        eprintln!("  get_user_by_id <id>");
        eprintln!("  get_user_by_identifier <identifier>");
        return;
    }

    let db_url = &args[1];
    let command = &args[2];

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("Failed to create pool");
    let mut conn = pool.acquire().await.expect("Failed to acquire connection");
    if let Err(e) = PgUserRepo::check_schema(&mut conn).await {
        eprintln!("Schema check failed: {e}");
        return;
    }

    let pg_connection: PgConnection = conn.detach();
    let repo = PgUserRepo::new(pg_connection)
        .await
        .expect("Failed to create repo");

    match command.as_str() {
        "check_schema" => {
            println!("Schema is valid.");
        }
        "add_user" => {
            if args.len() != 6 {
                eprintln!("Usage: add_user <id> <identifier> <password_hash>");
                return;
            }
            let user = User {
                id: args[3].clone(),
                credentials: authen::core::credentials::Credentials {
                    user_id: args[3].clone(),
                    identifier: args[4].clone(),
                    password_hash: args[5].clone(),
                },
            };
            match repo.add_user(user).await {
                Ok(u) => println!("User added: {}", u.id),
                Err(e) => eprintln!("Failed to add user: {e}"),
            }
        }
        "get_user_by_id" => {
            if args.len() != 4 {
                eprintln!("Usage: get_user_by_id <id>");
                return;
            }
            match repo.get_user_by_id(&args[3]).await {
                Some(u) => println!("User: id={} identifier={}", u.id, u.credentials.identifier),
                None => println!("User not found"),
            }
        }
        "get_user_by_identifier" => {
            if args.len() != 4 {
                eprintln!("Usage: get_user_by_identifier <identifier>");
                return;
            }
            match repo.get_user_by_identifier(&args[3]).await {
                Some(u) => println!("User: id={} identifier={}", u.id, u.credentials.identifier),
                None => println!("User not found"),
            }
        }
        _ => {
            eprintln!("Unknown command: {command}");
        }
    }
}
