//! RFC-007 §3: Hybrid Unretired Credit Output (UCO) primitives.
//!
//! Every UCO embeds an explicit half-open serial interval `[start_micro_unit, end_micro_unit)`
//! measured in integer micro-units (`MICRO_UNITS_PER_CREDIT = 1_000_000`).
//! This prevents fungible commingling across projects, vintages, and serial ranges
//! as required by RFC-001 and RFC-002.

use crate::auth::{PubKey, Signature};
use crate::error::RegistryError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol constants (RFC-007 §3.1 / §3.2)
// ---------------------------------------------------------------------------

/// Maximum micro-units in a single UCO output.
/// Bounded at `2^53 - 1` (`Number.MAX_SAFE_INTEGER`) so JavaScript clients
/// using `JSON.parse()` never silently truncate amounts.
/// Represents ~9 billion tCO₂e at gram-level precision — far beyond any
/// realistic single-batch issuance.
pub const MAX_UCO_MICRO_UNITS: u64 = 9_000_000_000_000_000;

/// Maximum number of outputs in a single transaction.
/// Acts as a coinless anti-spam cap preventing UTXO-set bloat attacks.
pub const MAX_TX_OUTPUTS: usize = 16;

// ---------------------------------------------------------------------------
// OutPoint — unique identifier for a UCO
// ---------------------------------------------------------------------------

/// Unique reference to a specific output within a transaction.
///
/// Modeled after Bitcoin's OutPoint (`txid:vout`), but `txid` here is the
/// canonical BLAKE3 event/leaf ID of the issuing or transfer transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Canonical BLAKE3 event/leaf ID of the issuing or transfer transaction
    #[serde(with = "crate::auth::hex_bytes32")]
    pub txid: [u8; 32],
    /// 0-based output index within that transaction
    pub vout: u32,
}

impl OutPoint {
    /// Byte size of a serialized OutPoint (32 bytes txid + 4 bytes vout).
    pub const BYTE_SIZE: usize = 36;

    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Encode to canonical big-endian bytes for hashing/signing.
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut buf = [0u8; Self::BYTE_SIZE];
        buf[..32].copy_from_slice(&self.txid);
        buf[32..36].copy_from_slice(&self.vout.to_be_bytes());
        buf
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", hex::encode(self.txid), self.vout)
    }
}

impl std::str::FromStr for OutPoint {
    type Err = RegistryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let txid_hex = parts
            .next()
            .ok_or_else(|| RegistryError::NotFound { id: s.to_string() })?;
        let vout_str = parts
            .next()
            .ok_or_else(|| RegistryError::NotFound { id: s.to_string() })?;
        if parts.next().is_some() {
            return Err(RegistryError::NotFound { id: s.to_string() });
        }
        let txid_bytes =
            hex::decode(txid_hex).map_err(|_| RegistryError::NotFound { id: s.to_string() })?;
        if txid_bytes.len() != 32 {
            return Err(RegistryError::NotFound { id: s.to_string() });
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let vout: u32 = vout_str
            .parse()
            .map_err(|_| RegistryError::NotFound { id: s.to_string() })?;

        Ok(Self::new(txid, vout))
    }
}

// ---------------------------------------------------------------------------
// UnretiredCreditOutput (UCO) — the core v2 "UTXO" with serial intervals
// ---------------------------------------------------------------------------

/// An active, unretired carbon credit output with explicit serial interval.
///
/// Each UCO represents a contiguous range `[start_micro_unit, end_micro_unit)`
/// of micro-units within a specific project, vintage, and batch.
///
/// UCOs are created by `UcoMint` or `UcoSplitTransfer` and consumed by
/// `UcoSplitTransfer` (spent) or `UcoBurnPoO` (permanently retired).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnretiredCreditOutput {
    /// Unique output reference
    pub outpoint: OutPoint,
    /// Deterministic batch identifier
    pub batch_id: String,
    /// Registered project slug
    pub project_id: String,
    /// Vintage year of sequestration/avoidance
    pub vintage_year: u16,
    /// Inclusive start of half-open interval `[start, end)`
    pub start_micro_unit: u64,
    /// Exclusive end (`> start_micro_unit`)
    pub end_micro_unit: u64,
    /// Exact mass: `end_micro_unit - start_micro_unit`
    pub micro_units: u64,
    /// Ed25519 owner verifying key
    pub owner: PubKey,
    /// Per-output monotonic counter (replay defense)
    pub op_index: u64,
    /// BLAKE3 hash of the methodology document
    #[serde(with = "crate::auth::hex_bytes32")]
    pub methodology_hash: [u8; 32],
    /// BLAKE3 Merkle root of MRV evidence (RFC-003)
    #[serde(with = "crate::auth::hex_bytes32")]
    pub mrv_data_root: [u8; 32],
    /// Optional mirror hints (content verified via BLAKE3, not trusted by URL)
    #[serde(default)]
    pub mrv_blob_mirrors: Vec<String>,
    /// Pre-retirement dispute window end epoch (0 if immediate / cleared)
    pub challenge_until_epoch: u64,
    /// Optional Tier-2 statutory lock tag (Stage 6)
    #[serde(default)]
    pub locked_escrow_program: Option<String>,
}

impl UnretiredCreditOutput {
    /// Validate internal consistency of this UCO.
    pub fn validate(&self) -> Result<(), RegistryError> {
        // Half-open interval must be non-empty
        if self.end_micro_unit <= self.start_micro_unit {
            return Err(RegistryError::InvalidRange);
        }

        // micro_units must exactly equal the interval width
        let width = self
            .end_micro_unit
            .checked_sub(self.start_micro_unit)
            .ok_or(RegistryError::Overflow)?;
        if width != self.micro_units {
            return Err(RegistryError::UcoIntervalMismatch {
                expected: width,
                found: self.micro_units,
            });
        }

        // JS MAX_SAFE_INTEGER guard
        if self.micro_units > MAX_UCO_MICRO_UNITS {
            return Err(RegistryError::ExceedsJsSafeMax {
                value: self.micro_units,
                max: MAX_UCO_MICRO_UNITS,
            });
        }

        if self.start_micro_unit > MAX_UCO_MICRO_UNITS {
            return Err(RegistryError::ExceedsJsSafeMax {
                value: self.start_micro_unit,
                max: MAX_UCO_MICRO_UNITS,
            });
        }

        if self.end_micro_unit > MAX_UCO_MICRO_UNITS {
            return Err(RegistryError::ExceedsJsSafeMax {
                value: self.end_micro_unit,
                max: MAX_UCO_MICRO_UNITS,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProofOfOffsetCommitment (PoO v2) — permanent retirement receipt
// ---------------------------------------------------------------------------

/// Immutable receipt of a permanently retired carbon credit.
///
/// Created when a UCO is consumed via `BurnPoO`. Once archived, the
/// commitment is append-only and covered by `poo_archive_root` in
/// `CheckpointHeaderV2`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfOffsetCommitment {
    /// The consumed output reference
    pub consumed_outpoint: OutPoint,
    /// Batch from which the UCO originated
    pub batch_id: String,
    /// Source project
    pub project_id: String,
    /// Vintage year
    pub vintage_year: u16,
    /// Inclusive start of retired interval
    pub start_micro_unit: u64,
    /// Exclusive end of retired interval
    pub end_micro_unit: u64,
    /// Exact retired mass
    pub micro_units: u64,
    /// Corporate entity or program claiming the offset
    pub beneficiary: String,
    /// Offset claim category
    pub claim_type: PoOClaimType,
    /// Log epoch at which retirement was finalized
    pub retirement_epoch: u64,
    /// Owner's Ed25519 authorization signature over the burn preimage
    pub owner_sig: Signature,
}

impl ProofOfOffsetCommitment {
    /// Validate internal consistency.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.end_micro_unit <= self.start_micro_unit {
            return Err(RegistryError::InvalidRange);
        }
        let width = self
            .end_micro_unit
            .checked_sub(self.start_micro_unit)
            .ok_or(RegistryError::Overflow)?;
        if width != self.micro_units {
            return Err(RegistryError::UcoIntervalMismatch {
                expected: width,
                found: self.micro_units,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PoO Claim Type (v2 enriched)
// ---------------------------------------------------------------------------

/// Categories of carbon offset claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoOClaimType {
    /// Voluntary market retirement (Scope 1/2/3 offsetting)
    Voluntary,
    /// Compliance / statutory retirement (CCTS, EU ETS, etc.)
    Compliance,
    /// Corporate Net-Zero / Science-Based Target alignment
    NetZero,
    /// Philanthropic or public-good cancellation
    Cancellation,
}

impl std::fmt::Display for PoOClaimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Voluntary => write!(f, "voluntary"),
            Self::Compliance => write!(f, "compliance"),
            Self::NetZero => write!(f, "net_zero"),
            Self::Cancellation => write!(f, "cancellation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;

    fn test_outpoint() -> OutPoint {
        OutPoint::new([0xABu8; 32], 0)
    }

    fn test_uco(start: u64, end: u64) -> UnretiredCreditOutput {
        let kp = Keypair::generate();
        UnretiredCreditOutput {
            outpoint: test_outpoint(),
            batch_id: "BATCH-001".to_string(),
            project_id: "PROJ-001".to_string(),
            vintage_year: 2026,
            start_micro_unit: start,
            end_micro_unit: end,
            micro_units: end.saturating_sub(start),
            owner: kp.pubkey(),
            op_index: 0,
            methodology_hash: [0x11; 32],
            mrv_data_root: [0x22; 32],
            mrv_blob_mirrors: vec![],
            challenge_until_epoch: 0,
            locked_escrow_program: None,
        }
    }

    #[test]
    fn test_uco_validate_valid() {
        let uco = test_uco(0, 1_000_000);
        assert!(uco.validate().is_ok());
    }

    #[test]
    fn test_uco_validate_empty_interval() {
        let mut uco = test_uco(100, 100);
        uco.micro_units = 0;
        assert_eq!(uco.validate().unwrap_err(), RegistryError::InvalidRange);
    }

    #[test]
    fn test_uco_validate_inverted_interval() {
        let mut uco = test_uco(500, 100);
        uco.micro_units = 0;
        assert_eq!(uco.validate().unwrap_err(), RegistryError::InvalidRange);
    }

    #[test]
    fn test_uco_validate_micro_units_mismatch() {
        let mut uco = test_uco(0, 1_000_000);
        uco.micro_units = 999_999; // wrong
        assert!(matches!(
            uco.validate().unwrap_err(),
            RegistryError::UcoIntervalMismatch { .. }
        ));
    }

    #[test]
    fn test_uco_validate_exceeds_js_safe_max() {
        // micro_units itself exceeds MAX_UCO_MICRO_UNITS
        let mut uco = test_uco(0, MAX_UCO_MICRO_UNITS + 1);
        uco.micro_units = MAX_UCO_MICRO_UNITS + 1;
        assert!(matches!(
            uco.validate().unwrap_err(),
            RegistryError::ExceedsJsSafeMax { .. }
        ));
    }

    #[test]
    fn test_uco_validate_at_max_boundary() {
        let uco = test_uco(0, MAX_UCO_MICRO_UNITS);
        assert!(uco.validate().is_ok());
    }

    #[test]
    fn test_outpoint_display() {
        let op = OutPoint::new([0xABu8; 32], 3);
        let s = op.to_string();
        assert!(s.ends_with(":3"));
        assert!(s.starts_with("abab"));
    }

    #[test]
    fn test_outpoint_byte_roundtrip() {
        let op = OutPoint::new([0x42u8; 32], 7);
        let bytes = op.to_bytes();
        assert_eq!(bytes.len(), OutPoint::BYTE_SIZE);
        assert_eq!(&bytes[..32], &[0x42u8; 32]);
        assert_eq!(
            u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
            7
        );
    }

    #[test]
    fn test_poo_commitment_validate() {
        let kp = Keypair::generate();
        let poo = ProofOfOffsetCommitment {
            consumed_outpoint: test_outpoint(),
            batch_id: "BATCH-001".to_string(),
            project_id: "PROJ-001".to_string(),
            vintage_year: 2026,
            start_micro_unit: 0,
            end_micro_unit: 500_000,
            micro_units: 500_000,
            beneficiary: "Acme Corp".to_string(),
            claim_type: PoOClaimType::Voluntary,
            retirement_epoch: 100,
            owner_sig: kp.sign(b"test"),
        };
        assert!(poo.validate().is_ok());
    }

    #[test]
    fn test_poo_claim_type_display() {
        assert_eq!(PoOClaimType::Voluntary.to_string(), "voluntary");
        assert_eq!(PoOClaimType::Compliance.to_string(), "compliance");
        assert_eq!(PoOClaimType::NetZero.to_string(), "net_zero");
        assert_eq!(PoOClaimType::Cancellation.to_string(), "cancellation");
    }

    #[test]
    fn test_uco_serde_roundtrip() {
        let uco = test_uco(1_000, 2_000_000);
        let json = serde_json::to_string(&uco).unwrap();
        let parsed: UnretiredCreditOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(uco.outpoint, parsed.outpoint);
        assert_eq!(uco.start_micro_unit, parsed.start_micro_unit);
        assert_eq!(uco.end_micro_unit, parsed.end_micro_unit);
        assert_eq!(uco.micro_units, parsed.micro_units);
        assert_eq!(uco.batch_id, parsed.batch_id);
        assert_eq!(uco.vintage_year, parsed.vintage_year);
    }

    #[test]
    fn test_outpoint_ordering() {
        let op_a = OutPoint::new([0x00; 32], 0);
        let op_b = OutPoint::new([0x00; 32], 1);
        let op_c = OutPoint::new([0x01; 32], 0);
        assert!(op_a < op_b);
        assert!(op_b < op_c);
    }
}
