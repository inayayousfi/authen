# `authen`

A robust and secure Rust crate for authentication, meticulously designed to provide a solid foundation for your applications. This library aims to deliver reliable and easy-to-use authentication primitives.

Note: this project was previously named cryptic auth.

## Features

* **Modular Design**: Offers a high-level interface with a modular architecture, allowing for easy integration and customization.
* **User Management**: Provides user registration, login, and management functionalities.
* **OAuth2 Support**: Includes OAuth2 support for third-party authentication.
* **Secure Password Hashing**: Utilizes modern algorithms like Argon2.
* **Session/Token Management**: Supports JSON Web Tokens (JWT) with access and refresh tokens.
* **Robust and Secure Error Handling**.
* **Asynchronous API**: Built on `async/await` for optimal performance.
* **SQLX**: Supports PostgreSQL via SQLX. (Optional)
* **Web Server**: Supports web server via Axum. (Optional)

## Quick Start

Add this line to your `Cargo.toml`:

```toml
[dependencies]
authen = { version = "0.3.0", features = ["full"] }
```

## Development

### Prerequisites

* Rust stable (2021 edition or newer)
* Cargo (installed with Rust)

### Running Tests

```bash
cargo test
```

### Running Benchmarks

```bash
cargo bench
```

### Checking Format and Linting

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## Contribution

Contributions are welcome! Please see `CONTRIBUTING.md` for more details.

## License

This project is licensed under the [Apache-2.0 License](LICENCE).

---
*Developed by Zied.*
