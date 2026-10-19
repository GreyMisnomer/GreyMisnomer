use serde::{Deserialize, Serialize};
use thiserror::Error;

// RegistryError — the single error type for the entire protocol.
// Every invariant violation, bad input, or invalid state transition maps here.
// thiserror::Error auto-implements Display so each variant prints a clean message.

// PartialEq lets tests use assert_eq!(result.unwrap_err(), RegistryError::InvalidRange)
#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryError {
    // RFC-002: SerialRange where start > end
    #[error("invalid serial range: start must be <= end")]
    InvalidRange,

    // RFC-001 Invariant 3: a new range overlaps an already-locked range
    #[error("serial range overlaps with an existing locked range — double counting prevented")]
    RangeOverlap,

    // RFC-001 Invariant 1: mint attempted without a valid PoI
    #[error("minting requires a valid PoI — none provided or PoI is not VALID")]
    MissingPoI,

    // RFC-001 Invariant 2: Q_mint > Q_auth (requested more credits than PoI authorizes)
    #[error("requested mint amount exceeds the PoI-authorized supply cap")]
    SupplyExceeded,

    // RFC-001 Invariant 7: PoI was already consumed by a previous mint — cannot reuse
    #[error("this PoI has already been used — a USED PoI cannot authorize another mint")]
    PoIAlreadyUsed,

    // RFC-001 Invariant 4: tried to re-activate or re-mint a burned serial range
    #[error("burn is irreversible — this serial range cannot re-enter circulation")]
    BurnIrreversible,

    // RFC-001 Invariant 5: a PoO was already issued for this serial range
    #[error("a PoO has already been issued for this serial range — cannot issue twice")]
    PoOAlreadyIssued,

    // RFC-002 §5: partial burn requested but no active slice contains the burn range.
    #[error("no active slice contains the requested burn range {start}–{end}")]
    BurnRangeNotFound { start: u64, end: u64 },

    // RFC-001: any lifecycle transition not permitted by the state machine
    #[error("invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    // A credit with this credit_id has already been minted
    #[error("a credit batch with this credit_id already exists")]
    DuplicateCreditId,

    // General: referenced a credit_id or project_id that doesn't exist in the registry
    #[error("entity not found: {id}")]
    NotFound { id: String },

    // Integer overflow in arithmetic calculation
    #[error("integer overflow in serial range calculation")]
    Overflow,

    // RFC-001 / RFC-003: An MRV data root was already used for minting — double counting prevented
    #[error(
        "duplicate MRV data root: this dataset has already been minted — double counting prevented"
    )]
    DuplicateDataRoot,

    // RFC-002: Internal consistency check failed after mutation
    #[error("internal state consistency check failed: credit batch corrupted after mutation")]
    CorruptedState,

    // RFC-005: Ed25519 signature verification failed
    #[error("cryptographic signature verification failed")]
    BadSignature,

    // RFC-005: Transaction was not signed by the required authority or owner
    #[error("unauthorized signer: {signer}")]
    UnauthorizedSigner { signer: String },

    // RFC-005: Referencing a VVB that is not in the accredited whitelist
    #[error("unknown or unregistered VVB: {vvb}")]
    UnknownVvb { vvb: String },

    // RFC-005: VVB was revoked prior to this transaction
    #[error("VVB has been revoked: {vvb}")]
    VvbRevoked { vvb: String },

    // RFC-005: Sequence mismatch on credit op_index
    #[error("operation index mismatch: expected {expected}, found {found}")]
    BadOpIndex { expected: u64, found: u64 },

    // RFC-005: Sequence mismatch on authority_index
    #[error("authority index mismatch: expected {expected}, found {found}")]
    BadAuthorityIndex { expected: u64, found: u64 },

    // RFC-005: Invalid public key encoding or small-order curve point
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),

    // RFC-005: Signature was created for a different registry chain_id
    #[error("chain_id mismatch: expected {expected}, found {found}")]
    WrongChain { expected: String, found: String },

    // RFC-005: Canonical line check failed (unknown fields, formatting, whitespace)
    #[error("non-canonical line format on line {line}: {reason}")]
    NonCanonicalLine { line: u64, reason: String },

    // RFC-005: Current owner does not match expected batch owner
    #[error("credit owner mismatch: expected {expected}, found {found}")]
    OwnerMismatch { expected: String, found: String },

    // RFC-005 §3.7: Checkpoint head hash does not match replayed event log head
    #[error("checkpoint head hash mismatch at size {size}: expected {expected}, found {found}")]
    CheckpointHeadMismatch {
        size: u64,
        expected: String,
        found: String,
    },

    // RFC-005 §3.7: Two different valid head hashes for the same checkpoint size
    #[error(
        "checkpoint equivocation detected at size {size}: conflicting heads {head_a} vs {head_b}"
    )]
    CheckpointEquivocation {
        size: u64,
        head_a: String,
        head_b: String,
    },
}
