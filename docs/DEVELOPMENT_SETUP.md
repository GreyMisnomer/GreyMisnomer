# GreyMisnomer Development Setup Guide

This guide outlines the minimal setup required to develop the GreyMisnomer core protocol.

## Environments

### 1. Primary: GitHub Codespaces / Dev Containers
This is the **recommended** path. It guarantees a sandboxed, reproducible environment.
- Open the repository in GitHub Codespaces OR open locally in VS Code and select "Reopen in Container".
- The existing `.devcontainer` configuration automatically provisions Rust, Git, the GitHub CLI (`gh`), and necessary extensions.
- **Zero local setup required.**

### 2. Fallback: Local Development (Windows/macOS/Linux)
If you prefer running natively, install these tools manually:
- [Git](https://git-scm.com/downloads) (Ensure identity is configured with `git config`)
- [Rustup](https://rustup.rs/) (Installs `rustc` and `cargo`)

## Rust Toolchain
We are using the standard stable Rust toolchain.
- **Version:** Latest `stable`
- **Edition:** `2021`

Verify your installation in the terminal:
```bash
cargo --version
rustc --version
```

## Protocol Engineering Workflow (Phase Alpha)

The GreyMisnomer Phase Alpha core is a pure Rust state machine. It does not interact with a blockchain or run heavy cryptographic computations yet.

### Building the Project
Navigate to the root directory (once we initialize Rust) and run:
```bash
cargo build
```

### Running Tests
All protocol invariants (PoI verification logic, serial locking rules, burn irreversibility) must be heavily tested.
```bash
cargo test
```

### Code Formatting and Linting
Please enforce strict formatting and linting rules before opening any Pull Requests:
```bash
cargo fmt
cargo clippy -- -D warnings
```

---
> [!NOTE]
> Phase Alpha does not include blockchain node environments, Web3 providers, or Zero-Knowledge proving systems. Please only add dependencies to `Cargo.toml` that are explicitly required for the core state machine logic.
