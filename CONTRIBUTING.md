# Contributing to GreyMisnomer

First off, thank you for considering contributing to GreyMisnomer! It's people like you that make GreyMisnomer such a great tool for climate integrity.

## Contribution Philosophy
- **Design > Code**: No PRs without an accepted RFC. Discuss architecture first.
- **Registry rules are conservative**: Changes to core invariants require immense scrutiny.
- **Backward compatibility is sacred**: We cannot invalidate existing credits.
- **Security > Performance > UX**: The registry must be bulletproof above all else.

## Development Workflow

### 1. Prerequisites
- Rust (ustup default stable)
- wasm32-unknown-unknown target (ustup target add wasm32-unknown-unknown)
- wasm-pack

### 2. Getting Started
\\\ash
git clone https://github.com/GreyMisnomer/GreyMisnomer.git
cd GreyMisnomer/src/wasm
wasm-pack build --target web --out-dir ../../docs/pkg --out-name grey_misnomer_wasm
\\\

### 3. Making Changes
1. Fork the repo and create your branch from main.
2. If you've added code that should be tested, add tests to src/core/tests.
3. Ensure the test suite passes: cargo test in src/core.
4. Make sure your code lints (e.g. cargo fmt and cargo clippy).

### 4. Pull Requests
- Fill in the required template.
- Do not include issue numbers in the PR title.
- Link the relevant issue in the PR description.
- Request review from a maintainer.

