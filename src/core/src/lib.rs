// The lib.rs file is the entry point for our Rust library (crate).
// Each line declares a module (a .rs file or folder/mod.rs).
// We do NOT use wildcard re-exports to avoid name collisions.

pub mod error;    // RegistryError — all protocol failure modes
pub mod serial;   // SerialRange — fundamental primitive (RFC-002)
pub mod project;  // Project, ProjectStatus (RFC-001)
pub mod poi;      // Proof-of-Integrity (RFC-001)
pub mod poo;      // Proof-of-Offset (RFC-001)
pub mod credit;   // CarbonCredit, CreditBatch (RFC-001 + RFC-002)
pub mod registry; // Registry state machine — enforces all 7 invariants (RFC-001)
pub mod mrv;      // MRV data commitment, Merkle tree (RFC-003)
