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
use crate::registry::{apply, InvariantReport, RegistryEvent, RegistryState};
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

/// Detailed summary of replaying an event log against the protocol state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySummary {
    /// Total number of events successfully validated and replayed
    pub events_count: u64,
    /// Cryptographic hash at the head of the replayed chain
    pub final_hash: String,
    /// Indicates whether the hash chain is intact and valid
    pub chain_valid: bool,
    /// Active credits currently remaining in active slices
    pub active_credits: u64,
    /// Retired / burned credits in finalized status
    pub retired_credits: u64,
    /// Total issued credits across all batches
    pub total_credits: u64,
    /// Total number of credit batches
    pub batches_count: usize,
    /// Full evaluation of all 7 protocol invariants from RFC-001 §5
    pub invariant_report: InvariantReport,
    /// The final evaluated registry state
    pub state: RegistryState,
}

/// Errors encountered while replaying an event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// JSON syntax error on a specific 1-indexed line number
    ParseError { line: u64, message: String },
    /// Non-contiguous or unexpected sequence number
    SequenceMismatch {
        line: u64,
        expected: u64,
        found: u64,
    },
    /// Hash chain broken: prev_hash does not match preceding entry's hash
    HashChainBroken {
        line: u64,
        seq: u64,
        expected: String,
        found: String,
    },
    /// Entry's hash does not match computed hash from its canonical contents
    HashTampered {
        line: u64,
        seq: u64,
        computed: String,
        found: String,
    },
    /// Protocol state transition error rejected by apply()
    StateTransitionError {
        line: u64,
        seq: u64,
        error: RegistryError,
    },
    /// Protocol invariant violation detected during or after replay
    InvariantFailed {
        line: u64,
        seq: u64,
        report: InvariantReport,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::ParseError { line, message } => {
                write!(f, "Parse error on line {line}: {message}")
            }
            ReplayError::SequenceMismatch {
                line,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Sequence mismatch on line {line}: expected {expected}, found {found}"
                )
            }
            ReplayError::HashChainBroken {
                line,
                seq,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Hash chain broken on line {line} (seq {seq}): expected prev_hash {expected}, found {found}"
                )
            }
            ReplayError::HashTampered {
                line,
                seq,
                computed,
                found,
            } => {
                write!(
                    f,
                    "Hash tampered on line {line} (seq {seq}): computed {computed}, found {found}"
                )
            }
            ReplayError::StateTransitionError { line, seq, error } => {
                write!(
                    f,
                    "State transition error on line {line} (seq {seq}): {error:?}"
                )
            }
            ReplayError::InvariantFailed { line, seq, report } => {
                write!(
                    f,
                    "Invariant verification failed on line {line} (seq {seq}): {report:?}"
                )
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// Replays an iterator of text lines from `events.jsonl`, verifying cryptographic hash chaining
/// and applying every transition to produce the final `RegistryState` and `InvariantReport`.
pub fn replay_log<I, S>(lines: I) -> Result<ReplaySummary, ReplayError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut state = RegistryState::new();
    let mut expected_seq: u64 = 0;
    let mut expected_prev_hash: String = GENESIS_PREV_HASH.to_string();
    let mut events_count: u64 = 0;

    for (line_idx, raw_line) in lines.into_iter().enumerate() {
        let line_num = (line_idx + 1) as u64;
        let line_str = raw_line.as_ref().trim();

        // Skip blank lines or comments
        if line_str.is_empty() || line_str.starts_with('#') {
            continue;
        }

        let entry: EventEntry =
            serde_json::from_str(line_str).map_err(|e| ReplayError::ParseError {
                line: line_num,
                message: e.to_string(),
            })?;

        // 1. Verify sequence contiguity
        if entry.seq != expected_seq {
            return Err(ReplayError::SequenceMismatch {
                line: line_num,
                expected: expected_seq,
                found: entry.seq,
            });
        }

        // 2. Verify hash chaining linkage
        if entry.prev_hash != expected_prev_hash {
            return Err(ReplayError::HashChainBroken {
                line: line_num,
                seq: entry.seq,
                expected: expected_prev_hash,
                found: entry.prev_hash,
            });
        }

        // 3. Verify entry hash self-consistency
        let computed =
            compute_entry_hash(entry.seq, &entry.prev_hash, &entry.event).map_err(|e| {
                ReplayError::StateTransitionError {
                    line: line_num,
                    seq: entry.seq,
                    error: e,
                }
            })?;
        if entry.hash != computed {
            return Err(ReplayError::HashTampered {
                line: line_num,
                seq: entry.seq,
                computed,
                found: entry.hash,
            });
        }

        // 4. Apply pure state transition
        state = apply(&state, &entry.event).map_err(|e| ReplayError::StateTransitionError {
            line: line_num,
            seq: entry.seq,
            error: e,
        })?;

        expected_prev_hash = entry.hash;
        expected_seq += 1;
        events_count += 1;
    }

    // 5. Evaluate all 7 protocol invariants on the final state
    let invariant_report = state.check_invariants();
    if !invariant_report.all_passed {
        return Err(ReplayError::InvariantFailed {
            line: events_count,
            seq: expected_seq.saturating_sub(1),
            report: invariant_report,
        });
    }

    // 6. Compute active & retired credit quantities
    let mut active_credits: u64 = 0;
    let mut retired_credits: u64 = 0;
    for batch in &state.credits {
        for slice in &batch.slices {
            if let Ok(sz) = slice.range.size() {
                match slice.status {
                    crate::credit::CreditStatus::Active => {
                        active_credits = active_credits.saturating_add(sz)
                    }
                    crate::credit::CreditStatus::Retired => {
                        retired_credits = retired_credits.saturating_add(sz)
                    }
                    crate::credit::CreditStatus::Expired => {}
                }
            }
        }
    }
    let total_credits = active_credits.saturating_add(retired_credits);
    let batches_count = state.credits.len();

    Ok(ReplaySummary {
        events_count,
        final_hash: expected_prev_hash,
        chain_valid: true,
        active_credits,
        retired_credits,
        total_credits,
        batches_count,
        invariant_report,
        state,
    })
}

/// Convenience helper: replays an entire `events.jsonl` string.
pub fn replay_log_str(content: &str) -> Result<ReplaySummary, ReplayError> {
    replay_log(content.lines())
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

    #[test]
    fn test_replay_valid_log() {
        let poi = make_test_poi("CC-REPLAY-1", 1000, 1999);
        let e0 = EventEntry::new(
            0,
            GENESIS_PREV_HASH.to_string(),
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Alice".to_string(),
            },
        )
        .unwrap();

        let e1 = EventEntry::new(
            1,
            e0.hash.clone(),
            RegistryEvent::Transfer {
                credit_id: "CC-REPLAY-1".to_string(),
                new_owner: "Bob".to_string(),
            },
        )
        .unwrap();

        let e2 = EventEntry::new(
            2,
            e1.hash.clone(),
            RegistryEvent::Burn {
                credit_id: "CC-REPLAY-1".to_string(),
                burn_range: SerialRange::new(1200, 1399).unwrap(),
                beneficiary: "ZeroNet Corp".to_string(),
                claim_type: ClaimType::CorporateNetZero,
            },
        )
        .unwrap();

        let log_content = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap()
        );

        let summary = replay_log_str(&log_content).unwrap();
        assert_eq!(summary.events_count, 3);
        assert_eq!(summary.final_hash, e2.hash);
        assert!(summary.chain_valid);
        assert_eq!(summary.total_credits, 1000);
        assert_eq!(summary.active_credits, 800);
        assert_eq!(summary.retired_credits, 200);
        assert_eq!(summary.batches_count, 1);
        assert!(summary.invariant_report.all_passed);
        assert_eq!(
            summary.state.credits[0].owner,
            crate::auth::PubKey(*blake3::hash(b"Bob").as_bytes())
        );
        assert_eq!(summary.state.credits[0].op_index, 2);
    }

    #[test]
    fn test_replay_detects_broken_hash_chain() {
        let poi = make_test_poi("CC-BROKEN-CHAIN", 1000, 1999);
        let e0 = EventEntry::new(
            0,
            GENESIS_PREV_HASH.to_string(),
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Alice".to_string(),
            },
        )
        .unwrap();

        let mut e1 = EventEntry::new(
            1,
            e0.hash.clone(),
            RegistryEvent::Transfer {
                credit_id: "CC-BROKEN-CHAIN".to_string(),
                new_owner: "Bob".to_string(),
            },
        )
        .unwrap();

        // Corrupt prev_hash of entry 1
        e1.prev_hash =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let log_content = format!(
            "{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap()
        );

        let err = replay_log_str(&log_content).unwrap_err();
        match err {
            ReplayError::HashChainBroken { line, seq, .. } => {
                assert_eq!(line, 2);
                assert_eq!(seq, 1);
            }
            other => panic!("Expected HashChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_detects_tampered_payload() {
        let poi = make_test_poi("CC-TAMPER", 1000, 1999);
        let e0 = EventEntry::new(
            0,
            GENESIS_PREV_HASH.to_string(),
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Alice".to_string(),
            },
        )
        .unwrap();

        let mut e1 = EventEntry::new(
            1,
            e0.hash.clone(),
            RegistryEvent::Transfer {
                credit_id: "CC-TAMPER".to_string(),
                new_owner: "Bob".to_string(),
            },
        )
        .unwrap();

        // Tamper with payload without updating hash
        e1.event = RegistryEvent::Transfer {
            credit_id: "CC-TAMPER".to_string(),
            new_owner: "Attacker".to_string(),
        };

        let log_content = format!(
            "{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap()
        );

        let err = replay_log_str(&log_content).unwrap_err();
        match err {
            ReplayError::HashTampered { line, seq, .. } => {
                assert_eq!(line, 2);
                assert_eq!(seq, 1);
            }
            other => panic!("Expected HashTampered, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_detects_sequence_gap() {
        let poi = make_test_poi("CC-GAP", 1000, 1999);
        let e0 = EventEntry::new(
            0,
            GENESIS_PREV_HASH.to_string(),
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Alice".to_string(),
            },
        )
        .unwrap();

        let mut e1 = EventEntry::new(
            2, // Should be 1!
            e0.hash.clone(),
            RegistryEvent::Transfer {
                credit_id: "CC-GAP".to_string(),
                new_owner: "Bob".to_string(),
            },
        )
        .unwrap();
        // Recompute hash for seq 2
        e1.hash = compute_entry_hash(2, &e0.hash, &e1.event).unwrap();

        let log_content = format!(
            "{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap()
        );

        let err = replay_log_str(&log_content).unwrap_err();
        match err {
            ReplayError::SequenceMismatch {
                line,
                expected,
                found,
            } => {
                assert_eq!(line, 2);
                assert_eq!(expected, 1);
                assert_eq!(found, 2);
            }
            other => panic!("Expected SequenceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_generate_sample_events_jsonl_file() {
        let poi = make_test_poi("CC-IN-SOLAR-2026-001", 1_000_000, 1_000_999);
        let e0 = EventEntry::new(
            0,
            GENESIS_PREV_HASH.to_string(),
            RegistryEvent::Mint {
                poi: Box::new(poi),
                owner: "Tata Power Renewable Energy Ltd".to_string(),
            },
        )
        .unwrap();

        let e1 = EventEntry::new(
            1,
            e0.hash.clone(),
            RegistryEvent::Transfer {
                credit_id: "CC-IN-SOLAR-2026-001".to_string(),
                new_owner: "Infosys Ltd".to_string(),
            },
        )
        .unwrap();

        let e2 = EventEntry::new(
            2,
            e1.hash.clone(),
            RegistryEvent::Burn {
                credit_id: "CC-IN-SOLAR-2026-001".to_string(),
                burn_range: SerialRange::new(1_000_200, 1_000_399).unwrap(),
                beneficiary: "Infosys Bangalore Campus Scope 2 Offset".to_string(),
                claim_type: ClaimType::CorporateNetZero,
            },
        )
        .unwrap();

        let log_content = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap()
        );

        let summary = replay_log_str(&log_content).unwrap();
        assert_eq!(summary.events_count, 3);
        assert!(summary.invariant_report.all_passed);
    }
}
