//! RFC-004: Event Log Schema & Hash-Chained Audit Trail (`events.jsonl`)
//!
//! Provides the canonical data structures, serialization formats, and cryptographic
//! hashing rules for the append-only event log used in GreyMisnomer Stage 1 Public Alpha.
//!
//! # Specification Summary
//! - Format: JSON Lines (JSONL), one compact JSON object per line (no pretty printing, no trailing commas).
//! - Chaining: Each line contains a sequence number `seq`, the previous entry's `prev_hash`,
//!   the state transition `event` (type & payload), and a cryptographic `hash`.
//! - Genesis: The initial line has `seq == 0` and `prev_hash == "0000000000000000000000000000000000000000000000000000000000000000"`.
//! - Hash preimage: BLAKE3 256-bit hash of canonical serialization `{"seq": N, "prev_hash": "...", "type": "...", "payload": {...}}`.

use crate::error::RegistryError;
use crate::registry::RegistryEvent;
use serde::{Deserialize, Serialize};

/// Genesis entry's `prev_hash`: 64 zeroes representing null 32-byte hash.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// A single line in `events.jsonl`, representing an immutable, hash-chained state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEntry {
    /// 0-indexed monotonically increasing sequence number (0, 1, 2, ...)
    pub seq: u64,
    /// 64-character lowercase hex string of the preceding entry's hash
    pub prev_hash: String,
    /// The discrete protocol event (tagged with "type" and "payload")
    #[serde(flatten)]
    pub event: RegistryEvent,
    /// 64-character lowercase hex BLAKE3 hash committing to (seq, prev_hash, event)
    pub hash: String,
}

#[derive(Serialize)]
struct HashPreimage<'a> {
    seq: u64,
    prev_hash: &'a str,
    #[serde(flatten)]
    event: &'a RegistryEvent,
}

/// Computes the canonical BLAKE3 hash for an event log entry given its sequence, prev_hash, and event.
pub fn compute_entry_hash(
    seq: u64,
    prev_hash: &str,
    event: &RegistryEvent,
) -> Result<String, RegistryError> {
    let preimage = HashPreimage {
        seq,
        prev_hash,
        event,
    };
    let json_bytes = serde_json::to_vec(&preimage).map_err(|_| RegistryError::CorruptedState)?;
    Ok(blake3::hash(&json_bytes).to_hex().to_string())
}

impl EventEntry {
    /// Creates a new hash-chained EventEntry, computing the cryptographic hash automatically.
    pub fn new(seq: u64, prev_hash: String, event: RegistryEvent) -> Result<Self, RegistryError> {
        let hash = compute_entry_hash(seq, &prev_hash, &event)?;
        Ok(Self {
            seq,
            prev_hash,
            event,
            hash,
        })
    }

    /// Verifies that this entry's `hash` accurately matches its canonical content.
    pub fn verify_hash(&self) -> bool {
        match compute_entry_hash(self.seq, &self.prev_hash, &self.event) {
            Ok(expected) => self.hash == expected,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mrv::MRVCommitment;
    use crate::poi::{PoI, PoIStatus};
    use crate::poo::ClaimType;
    use crate::project::MarketScope;
    use crate::serial::SerialRange;

    fn make_test_poi(credit_id: &str, start: u64, end: u64) -> PoI {
        let mut root = [0u8; 32];
        let bytes = credit_id.as_bytes();
        let len = bytes.len().min(32);
        root[..len].copy_from_slice(&bytes[..len]);

        PoI {
            project_id: "PRJ-001".to_string(),
            mrv_commitment: MRVCommitment {
                merkle_root: root,
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 1,
                timestamp: 1_700_000_000,
            },
            methodology_hash: "0xMETH01".to_string(),
            vvb_signature: "0xSIG01".to_string(),
            serialization_range: SerialRange::new(start, end).unwrap(),
            amount_tco2e: end - start + 1,
            jurisdiction: "IN".to_string(),
            market_scope: MarketScope::Vcm,
            credit_id: credit_id.to_string(),
            valid_from: 1_700_000_000,
            valid_until: 1_730_000_000,
            poi_valid: true,
            cc_mint_amount: end - start + 1,
            owner: "Alice".to_string(),
            status: PoIStatus::Valid,
        }
    }

    #[test]
    fn test_genesis_entry_creation_and_verification() {
        let poi = make_test_poi("CC-TEST-1", 1000, 1999);
        let event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };

        let entry = EventEntry::new(0, GENESIS_PREV_HASH.to_string(), event).unwrap();
        assert_eq!(entry.seq, 0);
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(entry.hash.len(), 64);
        assert!(entry.verify_hash());
    }

    #[test]
    fn test_tamper_detection_in_entry() {
        let poi = make_test_poi("CC-TEST-1", 1000, 1999);
        let event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };

        let mut entry = EventEntry::new(0, GENESIS_PREV_HASH.to_string(), event).unwrap();
        assert!(entry.verify_hash());

        // Tamper with seq
        entry.seq = 1;
        assert!(!entry.verify_hash());
        entry.seq = 0;
        assert!(entry.verify_hash());

        // Tamper with prev_hash
        entry.prev_hash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        assert!(!entry.verify_hash());
        entry.prev_hash = GENESIS_PREV_HASH.to_string();
        assert!(entry.verify_hash());

        // Tamper with hash
        entry.hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!entry.verify_hash());
    }

    #[test]
    fn test_jsonl_serialization_schema() {
        let poi = make_test_poi("CC-TEST-1", 1000, 1999);
        let event = RegistryEvent::Mint {
            poi: Box::new(poi),
            owner: "Alice".to_string(),
        };

        let entry = EventEntry::new(0, GENESIS_PREV_HASH.to_string(), event).unwrap();
        let json_line = serde_json::to_string(&entry).unwrap();

        // Must be single line (no newlines)
        assert!(!json_line.contains('\n'));

        // Deserializing back reproduces exact entry
        let deserialized: EventEntry = serde_json::from_str(&json_line).unwrap();
        assert_eq!(entry, deserialized);
        assert!(deserialized.verify_hash());

        // Test second chained entry (Transfer)
        let xfer_event = RegistryEvent::Transfer {
            credit_id: "CC-TEST-1".to_string(),
            new_owner: "Bob".to_string(),
        };
        let entry1 = EventEntry::new(1, entry.hash.clone(), xfer_event).unwrap();
        assert_eq!(entry1.prev_hash, entry.hash);
        assert!(entry1.verify_hash());

        // Test third chained entry (Burn)
        let burn_event = RegistryEvent::Burn {
            credit_id: "CC-TEST-1".to_string(),
            burn_range: SerialRange::new(1200, 1499).unwrap(),
            beneficiary: "CorpX".to_string(),
            claim_type: ClaimType::CorporateNetZero,
        };
        let entry2 = EventEntry::new(2, entry1.hash.clone(), burn_event).unwrap();
        assert_eq!(entry2.prev_hash, entry1.hash);
        assert!(entry2.verify_hash());
    }
}
