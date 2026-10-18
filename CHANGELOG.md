# Changelog

All notable changes to the GreyMisnomer protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-10-18

### Milestone: Stage 0 (P0 Critical Audit Fixes) & Stage 1 (Public Alpha Ledger)

This release implements the full Stage 1 specification defined in RFC-001 through RFC-004, resolving all critical audit findings (P0 bugs), introducing canonical integer-only accounting, establishing a pure state machine, and deploying an append-only hash-chained event log with Bitcoin thermodynamic timestamping (OpenTimestamps) and client-side WebAssembly verification.

### Added
- **Canonical Event Log (`events.jsonl` / RFC-004):** Append-only line-delimited JSON log with BLAKE3 cryptographic hash chaining (`prev_hash` -> `hash`).
- **CLI Replayer (`grey-misnomer-cli`):** Independent Rust binary to verify sequence contiguity, validate cryptographic chaining, replay transitions, and verify all 7 protocol invariants.
- **In-Browser WebAssembly Verifier (`docs/app.html`):** Client-side verifier that loads `events.jsonl`, replays all transitions in WASM, and dynamically displays the invariant report.
- **Cryptographic Tamper Sandbox:** Interactive UI tool enabling auditors to modify or corrupt any byte/hash in the ledger and observe real-time cryptographic rejection by WebAssembly.
- **Bitcoin Blockchain Anchoring (OpenTimestamps):** Automated CI pipeline anchoring `events.jsonl` to Bitcoin calendar pools upon every release (`events.jsonl.ots`).
- **End-to-End Browser Lifecycle Test:** Playwright automated test verifying the entire carbon lifecycle (Project -> MRV -> Merkle -> PoI -> Mint -> Retire -> PoO -> Invariants).

### Fixed & Refactored (Stage 0 Audit Items)
- **Eliminate All XSS Injection Sites:** Replaced 29 `innerHTML` occurrences in `app.js` with secure DOM construction APIs (`textContent`, `createElement`, `replaceChildren`).
- **Integer-Only Accounting:** Replaced all floating-point numbers (`f64`) in `grey-misnomer-core` with integer micro-units (`1 credit = 1_000_000 micro_credits (u64)`).
- **Canonical Length-Prefixed Merkle Leaves:** Implemented length-prefixed leaf serialization and domain separation (`0x00` leaf, `0x01` internal node) to prevent second-preimage collision attacks.
- **Pure State Machine:** Refactored core into a pure state transition function `apply(state, event) -> Result<RegistryState, RegistryError>`.
- **Duplicate Prevention:** Enforced global uniqueness on `credit_id` and MRV dataset Merkle roots (`used_data_roots`) to mathematically eliminate double-counting.
- **Safe Arithmetic:** Replaced wrapping arithmetic with checked operations (`checked_sub`, `checked_add`) in `SerialRange`.
- **Panic Elimination:** Replaced core library panics with typed `RegistryError` results.
- **Dynamic Serial Allocation:** Eliminated hardcoded starting serials in frontend to prevent active serial range overlaps.
- **Per-Project MRV Commitments:** Replaced single global commitment with a keyed `HashMap<String, MRVCommitment>`.

---

## [1.1.0] - 2026-09-29
- Overhauled README, expanded test suite, and fixed toast notifications.

## [1.0.0] - 2026-06-26
- Added project structure links and baseline architecture documentation.

## [0.1.0-alpha] - 2026-05-03
- Initial Phase Alpha prototype with CLI demo and credit slice normalization.
