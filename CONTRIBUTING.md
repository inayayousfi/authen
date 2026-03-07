# Contribution Guide for `authen`

We are delighted that you are interested in contributing to the `authen` crate! Your help is invaluable in making this library a secure foundation for Rust applications.

## Before Contributing

1. **Read `README.md`**: It contains information about the crate's purpose and features.
2. **Check Existing Issues**: Before starting work, take a look at the issues on GitHub.
3. **Discuss New Features**: For major new features, it is best to open an issue first.

## How to Contribute

1. **Fork the Repository**: Start by forking the `authen` repository to your GitHub account.
2. **Clone Your Fork**:

    ```bash
    git clone https://github.com/your-username/authen.git
    cd authen
    ```

3. **Create a New Branch**:

    ```bash
    git checkout -b my-new-branch
    ```

4. **Develop Your Contribution**:
    * Write your code following Rust conventions.
    * **Write Tests**: Any new feature should be accompanied by tests.
    * **Update Documentation**: If necessary.
5. **Run Tests and Lints**:

    ```bash
    cargo test
    cargo fmt --check
    cargo clippy -- -D warnings
    ```

6. **Commit and Push**:

    ```bash
    git add .
    git commit -m "feat: your commit message"
    git push origin my-new-branch
    ```

7. **Create a Pull Request**

## Code Standards

* **Formatting**: Follow `rustfmt` conventions.
* **Linting**: Ensure `clippy` reports no warnings.
* **Naming Conventions**: Adopt standard Rust naming conventions.

Thank you for contributing to this project! Your help is invaluable.
