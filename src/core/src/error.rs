use thiserror::Error;

// RegistryError — the single error type for the entire protocol.
// Every invariant violation, bad input, or invalid state transition maps here.
// thiserror::Error auto-implements Display so each variant prints a clean message.

// PartialEq lets tests use assert_eq!(result.unwrap_err(), RegistryError::InvalidRange)
#[derive(Error, Debug, PartialEq)]
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

    // General: referenced a credit_id or project_id that doesn't exist in the registry
    #[error("entity not found: {id}")]
    NotFound { id: String },
}
