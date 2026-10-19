# Changelog

All notable changes to the GreyMisnomer protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] - 2026-10-19

### Milestone: Stage 2 (The People's Ledger Protocol & Sovereign Multi-Mirror Publishing — RFC-006)

This release implements the full Stage 2 architecture specified in RFC-006 ("The People's Ledger Protocol"). It eliminates all dependency on centralized RPCs, gas tokens, EVM chains, and paid infrastructure, transforming GreyMisnomer into a completely sovereign, locally-deployable, distributed ledger with an in-browser cryptographic signing enclave, zero-gas asynchronous submission channels, canonical distribution manifests, IPFS Content Identifier (CID) integration, and automatic gateway fallback.

### Added
- **RFC-006 Protocol Specification (`docs/rfc/rfc-006.md`):** Complete, formal architecture specifying the 5-tier zero-cost storage topology, sovereign client-side transaction signing, canonical distribution manifest, and multi-mirror gateway failover.
- **WebAssembly Ed25519 Signing Enclave (`src/wasm/`):**
  - `generate_keypair_wasm()`, `derive_pubkey_wasm()`, `sign_transfer_intent_wasm()`, `sign_burn_intent_wasm()`, and `sign_mint_intent_wasm()`.
  - `simulate_apply_wasm()`: Client-side pre-flight simulation engine that dry-runs proposed transactions against current state in local WASM memory and renders byte-identical canonical JSONL lines before any submission.
- **In-Browser Sovereign Key Manager UI (`docs/app.html` & `docs/js/app.js`):**
  - Local Ed25519 keypair generator, public/secret key viewer with reveal toggle, secure clipboard export, and air-gapped JSON identity download.
  - Preset ledger identities for instant testing and auditing: Infosys Corporate Buyer, Tata Solar Developer, TUV NORD Carbon Bureau, Root Registry Authority, and Sequencer.
- **In-Browser Transaction Intent Builder (`#view-signer`):**
  - Interactive signing interfaces for Transfer, Burn/Retire (with legal claim rationales: `CorporateNetZero`, `Payg`, `Compliance`), and Accredited VVB Minting.
  - Automated `op_index` replay protection detector querying current state machine history.
  - Live pre-flight simulation metrics: Projected Sequence #, Next Batch `op_index`, Active Supply, and Retired Supply.
- **Zero-Gas Asynchronous Submission Assistant:**
  - One-click GitHub Issue submission assistant with pre-filled markdown templates containing canonical event lines.
  - Air-gapped `.gmline` single-event bundle download for offline sequencers.
- **Canonical Multi-Mirror Manifest (`manifest.json` & `docs/manifest.json`):**
  - Commits `chain_id`, `log_size`, `head_hash`, latest signed checkpoint, Git & GitHub Pages mirrors, IPFS UnixFS CIDs, public gateway pool, and Internet Archive Wayback Machine snapshot links.
- **Automated Multi-Mirror Publishing Engine (`scripts/publish_mirrors.py` & CI):**
  - Deterministically computes standard IPFS UnixFS CIDv1 without external daemons.
  - Interacts with Internet Archive Save Page Now 2 (SPN2) public API to archive public releases.
  - Integrated into `.github/workflows/pages.yml`.
- **In-Browser Resilient Verification & Gateway Failover:**
  - Web app automatically falls back from Origin HTTP to public IPFS gateways (`dweb.link`, `ipfs.io`, `cloudflare-ipfs.com`) and Archive.org upon network interruption or CDN outage.
  - Real-time Equivocation Defense card alerting auditors if manifest head hash diverges from replayed log tip.
- **Expanded Playwright E2E Test Suite (14 Tests):**
  - Added `test/e2e/signer.spec.js` (Key Manager, intent signing, WASM simulation, rejection of unauthorized keys, op_index replay prevention).
  - Added `test/e2e/mirrors.spec.js` (Multi-mirror status, IPFS CID display, Wayback link, and simulated Origin failover).

---

## [1.3.0] - 2026-10-19

### Milestone: Stage 1.5 (Cryptographic Transparency Log & Signed Events — RFC-005)

This release elevates the GreyMisnomer protocol from an accounting log to a cryptographic transparency log per RFC-005. It eliminates sequencer trust by mandating Ed25519 cryptographic signatures on every state transition, introduces strict length-prefixed binary preimages, provides monotonic replay protection counters, enforces Invariants A1–A3, and adds sequencer-signed checkpoints with in-browser WebAssembly verification.

### Added
- **Ed25519 Cryptographic Signatures & Identity (RFC-005 §2):** Integrated `ed25519-dalek` (zero default features, `alloc` and `serde` enabled). Actors (Root Authority, Sequencer, Accredited VVBs, and Credit Owners) are strictly identified by 32-byte Ed25519 public keys.
- **Canonical Binary Preimages & Domain Separation (§3.4):** Built deterministic big-endian length-prefixed binary preimages with isolated domain tags (`0x10`..`0x13`) for `Genesis`, `VvbRegister`, `VvbRevoke`, `Mint`, `Transfer`, `Burn`, and `Checkpoint`.
- **Monotonic Replay Protection (§3.5):** Introduced per-batch `op_index` counters and an `authority_index` counter. Any reused or non-contiguous index is immediately rejected.
- **Cryptographic Invariants A1–A3 (§3.8):**
  - **Invariant A1 (Strict Signature Validity):** Every state transition must carry a valid Ed25519 signature under the accredited party's public key (Authority for VVB events, VVB for credit minting, current Owner for transfers and burns).
  - **Invariant A2 (Operation Index Contiguity):** Mutations strictly increment monotonically without gaps or repeats.
  - **Invariant A3 (Domain Separation):** All events and checkpoints must target the active `chain_id`.
- **Byte-Identical Canonical-Line Rule (§3.6):** Strict JSONL parser and canonical renderer in `event_log.rs` ensuring zero byte discrepancies, whitespace malleability, or unescaped sequences.
- **Signed Checkpoints & Equivocation Detection (§3.7):** Sequencer publishes signed checkpoint files (`checkpoints/<size>.json`) referencing log size and head hash. Includes client-side algorithm to detect equivocation across audits.
- **CLI Key Management & Checkpoint Tools:** Added subcommands to `grey-misnomer-cli`: `keygen`, `sign-checkpoint`, `checkpoint`, and `verify-checkpoint`, plus `--checkpoints <dir>` audit flag for `replay`.
- **In-Browser WASM Verifier & Trust Root UI:** Compiled native WebAssembly verifying Ed25519 signatures, checkpoints, and Invariants A1–A3 with zero backend trust.
- **Automated Playwright E2E Suite:** 8/8 end-to-end browser tests verifying protocol lifecycle, RBAC, live ledger replay, and tamper rejection.

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
