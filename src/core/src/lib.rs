// The lib.rs file is the entry point for our Rust library (crate).
// Each line declares a module (a .rs file or folder/mod.rs).
// We do NOT use wildcard re-exports to avoid name collisions.

pub mod auth; // Ed25519, canonical encoding (enc), preimages (RFC-005)
pub mod checkpoint; // Signed checkpoints & equivocation detection (RFC-005 §3.7)
pub mod credit; // CarbonCredit, CreditBatch (RFC-001 + RFC-002)
pub mod error; // RegistryError — all protocol failure modes
pub mod event_log; // EventEntry, schema & hash chaining for events.jsonl (RFC-004)
pub mod header; // RFC-007: CheckpointHeaderV2 3-root binary header layout
pub mod manifest; // Canonical Distribution Manifest (RFC-006 §5.2)
pub mod merkle_log; // RFC 9162 / RFC-007: Verifiable Merkle log, inclusion & consistency proofs
pub mod migrate; // RFC-007: Deterministic v1.3 -> v2.0 test/importer converter
pub mod mrv;
pub mod oracle;
pub mod ots; // OpenTimestamps binary proof & SHA-256 commitment verification
pub mod poi; // Proof-of-Integrity (RFC-001)
pub mod poo; // Proof-of-Offset (RFC-001)
pub mod project; // Project, ProjectStatus (RFC-001)
pub mod registry; // Registry state machine — enforces all 7 invariants (RFC-001)
pub mod serial; // SerialRange — fundamental primitive (RFC-002) // MRV data commitment, Merkle tree (RFC-003)
pub mod spv; // RFC-007: Active unspentness and permanent retirement SPV proofs
pub mod uco; // RFC-007: Hybrid UCO primitives, OutPoint, ProofOfOffsetCommitment
pub mod uco_engine; // RFC-007: Pure apply_uco engine, monotonic cursors & partition splits // RFC-007: Hardened MRV oracle quorums, scoped VVBs & buffer pool

/// 1 credit = 1_000_000 micro-credits (RFC-001 / Phase Alpha integer accounting)
pub const MICRO_UNITS_PER_CREDIT: u64 = 1_000_000;
