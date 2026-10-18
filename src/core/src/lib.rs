// The lib.rs file is the entry point for our Rust library (crate).
// Each line declares a module (a .rs file or folder/mod.rs).
// We do NOT use wildcard re-exports to avoid name collisions.

pub mod auth; // Ed25519, canonical encoding (enc), preimages (RFC-005)
pub mod credit; // CarbonCredit, CreditBatch (RFC-001 + RFC-002)
pub mod error; // RegistryError — all protocol failure modes
pub mod event_log; // EventEntry, schema & hash chaining for events.jsonl (RFC-004)
pub mod mrv;
pub mod poi; // Proof-of-Integrity (RFC-001)
pub mod poo; // Proof-of-Offset (RFC-001)
pub mod project; // Project, ProjectStatus (RFC-001)
pub mod registry; // Registry state machine — enforces all 7 invariants (RFC-001)
pub mod serial; // SerialRange — fundamental primitive (RFC-002) // MRV data commitment, Merkle tree (RFC-003)

/// 1 credit = 1_000_000 micro-credits (RFC-001 / Phase Alpha integer accounting)
pub const MICRO_UNITS_PER_CREDIT: u64 = 1_000_000;
