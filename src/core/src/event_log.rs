//! RFC-005: Signed Events, Authorization & Canonical Line Renderer / Parser (`events.jsonl`)
//!
//! Provides the canonical data structures, serialization formats, strict parser,
//! and cryptographic hashing rules for the append-only event log used in GreyMisnomer Stage 1.5.
//!
//! # Specification Summary (RFC-005 §3.6)
//! - Format: JSON Lines (JSONL), one compact JSON object per line.
//! - Canonical line rule: strictly byte-identical re-rendering match (ordered keys, no whitespace, lowercase hex).
//! - Chaining: entry_hash = BLAKE3(str "GM/v1/entry" || u64 seq || bytes32 prev_hash || body_bytes).
//! - Genesis: seq == 0, prev_hash == 64 zeroes. Its entry_hash establishes the registry's `chain_id`.

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
    /// 64-character lowercase hex BLAKE3 hash committing to (seq, prev_hash, event body bytes)
    pub hash: String,
}

/// Computes the canonical BLAKE3 hash for an event log entry given its sequence, prev_hash, and event (RFC-005 §3.6).
/// entry_hash = BLAKE3(str "GM/v1/entry" || u64 seq || bytes32 prev_hash || body_bytes)
pub fn compute_entry_hash(
    seq: u64,
    prev_hash: &str,
    event: &RegistryEvent,
) -> Result<String, RegistryError> {
    let mut prev_bytes = [0u8; 32];
    hex::decode_to_slice(prev_hash, &mut prev_bytes).map_err(|_| RegistryError::CorruptedState)?;
    let body_bytes = event.to_body_bytes();
    let hash_bytes = crate::auth::compute_entry_hash(seq, &prev_bytes, &body_bytes);
    Ok(hex::encode(hash_bytes))
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
            Ok(expected) => self.hash.eq_ignore_ascii_case(&expected),
            Err(_) => false,
        }
    }
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Renders the canonical JSON payload string with fixed key ordering per RFC-005 §3.6.
pub fn render_canonical_payload(event: &RegistryEvent) -> (&'static str, String) {
    match event {
        RegistryEvent::Genesis {
            chain_name,
            authority,
            sequencer,
            nonce,
            created_at,
            authority_sig,
        } => (
            "genesis",
            format!(
                r#"{{"chain_name":{},"authority":"{}","sequencer":"{}","nonce":"{}","created_at":{},"authority_sig":"{}"}}"#,
                escape_json_str(chain_name),
                authority.to_hex(),
                sequencer.to_hex(),
                hex::encode(nonce),
                created_at,
                authority_sig.to_hex()
            ),
        ),
        RegistryEvent::VvbRegister {
            authority_index,
            vvb,
            label,
            authority_sig,
        } => (
            "vvb_register",
            format!(
                r#"{{"authority_index":{},"vvb":"{}","label":{},"authority_sig":"{}"}}"#,
                authority_index,
                vvb.to_hex(),
                escape_json_str(label),
                authority_sig.to_hex()
            ),
        ),
        RegistryEvent::VvbRevoke {
            authority_index,
            vvb,
            authority_sig,
        } => (
            "vvb_revoke",
            format!(
                r#"{{"authority_index":{},"vvb":"{}","authority_sig":"{}"}}"#,
                authority_index,
                vvb.to_hex(),
                authority_sig.to_hex()
            ),
        ),
        RegistryEvent::Mint {
            project_id,
            credit_id,
            range_start,
            range_end,
            cc_mint_amount,
            merkle_root,
            leaf_count,
            mrv_timestamp,
            methodology_hash,
            jurisdiction,
            market_scope,
            valid_from,
            valid_until,
            initial_owner,
            vvb,
            vvb_sig,
        } => (
            "mint",
            format!(
                r#"{{"project_id":{},"credit_id":{},"range_start":{},"range_end":{},"cc_mint_amount":{},"merkle_root":"{}","leaf_count":{},"mrv_timestamp":{},"methodology_hash":{},"jurisdiction":{},"market_scope":{},"valid_from":{},"valid_until":{},"initial_owner":"{}","vvb":"{}","vvb_sig":"{}"}}"#,
                escape_json_str(project_id),
                escape_json_str(credit_id),
                range_start,
                range_end,
                cc_mint_amount,
                hex::encode(merkle_root),
                leaf_count,
                mrv_timestamp,
                escape_json_str(methodology_hash),
                escape_json_str(jurisdiction),
                escape_json_str(market_scope),
                valid_from,
                valid_until,
                initial_owner.to_hex(),
                vvb.to_hex(),
                vvb_sig.to_hex()
            ),
        ),
        RegistryEvent::Transfer {
            credit_id,
            op_index,
            new_owner,
            owner_sig,
        } => (
            "transfer",
            format!(
                r#"{{"credit_id":{},"op_index":{},"new_owner":"{}","owner_sig":"{}"}}"#,
                escape_json_str(credit_id),
                op_index,
                new_owner.to_hex(),
                owner_sig.to_hex()
            ),
        ),
        RegistryEvent::Burn {
            credit_id,
            op_index,
            range_start,
            range_end,
            beneficiary,
            claim_type,
            owner_sig,
        } => (
            "burn",
            format!(
                r#"{{"credit_id":{},"op_index":{},"range_start":{},"range_end":{},"beneficiary":{},"claim_type":{},"owner_sig":"{}"}}"#,
                escape_json_str(credit_id),
                op_index,
                range_start,
                range_end,
                escape_json_str(beneficiary),
                escape_json_str(claim_type.as_str()),
                owner_sig.to_hex()
            ),
        ),
        RegistryEvent::AuthorityRotate {
            authority_index,
            new_authority,
            authority_sig,
        } => (
            "authority_rotate",
            format!(
                r#"{{"authority_index":{},"new_authority":"{}","authority_sig":"{}"}}"#,
                authority_index,
                new_authority.to_hex(),
                authority_sig.to_hex()
            ),
        ),
        RegistryEvent::SequencerRotate {
            authority_index,
            new_sequencer,
            authority_sig,
        } => (
            "sequencer_rotate",
            format!(
                r#"{{"authority_index":{},"new_sequencer":"{}","authority_sig":"{}"}}"#,
                authority_index,
                new_sequencer.to_hex(),
                authority_sig.to_hex()
            ),
        ),
    }
}

/// Renders an EventEntry to its exact canonical line representation (RFC-005 §3.6).
pub fn render_canonical_line(entry: &EventEntry) -> String {
    let (type_name, payload_json) = render_canonical_payload(&entry.event);
    format!(
        r#"{{"seq":{},"prev_hash":"{}","type":"{}","payload":{},"hash":"{}"}}"#,
        entry.seq,
        entry.prev_hash.to_ascii_lowercase(),
        type_name,
        payload_json,
        entry.hash.to_ascii_lowercase()
    )
}

/// Strictly parses and validates a line of `events.jsonl` under the Canonical-Line Rule (RFC-005 §3.6).
pub fn parse_canonical_line(raw_line: &str, line_num: u64) -> Result<EventEntry, ReplayError> {
    if raw_line.contains('\r') {
        return Err(ReplayError::NonCanonicalLine {
            line: line_num,
            message: "CRLF line endings are strictly forbidden".to_string(),
        });
    }

    let trimmed = raw_line.trim_end_matches('\n');
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with(' ')
        || trimmed.ends_with(' ')
    {
        return Err(ReplayError::NonCanonicalLine {
            line: line_num,
            message: "Blank lines, comments, and whitespace padding are strictly forbidden"
                .to_string(),
        });
    }

    let entry: EventEntry = serde_json::from_str(trimmed).map_err(|e| ReplayError::ParseError {
        line: line_num,
        message: e.to_string(),
    })?;

    // Check prev_hash hex format
    if entry.prev_hash.len() != 64
        || !entry
            .prev_hash
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayError::NonCanonicalLine {
            line: line_num,
            message: "prev_hash must be exactly 64 lowercase hexadecimal characters".to_string(),
        });
    }

    // Check hash hex format
    if entry.hash.len() != 64
        || !entry
            .hash
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReplayError::NonCanonicalLine {
            line: line_num,
            message: "hash must be exactly 64 lowercase hexadecimal characters".to_string(),
        });
    }

    // Byte-identical re-rendering validation (Canonical-Line Rule RFC-005 §3.6)
    let canonical = render_canonical_line(&entry);
    if canonical != trimmed {
        return Err(ReplayError::NonCanonicalLine {
            line: line_num,
            message: "Line is not byte-identical to canonical rendering".to_string(),
        });
    }

    Ok(entry)
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
    /// Full evaluation of all protocol and authorization invariants
    pub invariant_report: InvariantReport,
    /// The final evaluated registry state
    pub state: RegistryState,
}

/// Errors encountered while replaying an event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// JSON syntax error on a specific 1-indexed line number
    ParseError { line: u64, message: String },
    /// Non-canonical formatting (CRLF, comments, whitespace, non-identical re-render)
    NonCanonicalLine { line: u64, message: String },
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
    /// Genesis chain_id does not match the configured trust anchor
    ChainIdMismatch { expected: String, found: String },
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
            ReplayError::NonCanonicalLine { line, message } => {
                write!(f, "Non-canonical line on line {line}: {message}")
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
            ReplayError::ChainIdMismatch { expected, found } => {
                write!(
                    f,
                    "Chain ID mismatch: expected trust anchor {expected}, found {found}"
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
    replay_log_with_anchor(lines, None)
}

/// Replays an event log verifying each entry against an expected `chain_id` trust anchor.
pub fn replay_log_with_anchor<I, S>(
    lines: I,
    expected_chain_id: Option<&[u8; 32]>,
) -> Result<ReplaySummary, ReplayError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut state = RegistryState::new();
    let mut expected_seq: u64 = 0;
    let mut expected_prev_hash: String = GENESIS_PREV_HASH.to_string();
    let mut events_count: u64 = 0;

    #[allow(clippy::explicit_counter_loop)]
    for (line_idx, raw_line) in lines.into_iter().enumerate() {
        let line_num = (line_idx + 1) as u64;
        let line_str = raw_line.as_ref();

        // Strict canonical parser enforces RFC-005 §3.6
        let entry = parse_canonical_line(line_str, line_num)?;

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

        // 5. If genesis, verify against expected chain_id anchor if provided
        if entry.seq == 0 {
            if let Some(anchor) = expected_chain_id {
                if &state.chain_id != anchor {
                    return Err(ReplayError::ChainIdMismatch {
                        expected: hex::encode(anchor),
                        found: hex::encode(state.chain_id),
                    });
                }
            }
        }

        // 6. Invariants re-evaluated after every state transition (RFC-005 §3.8)
        let invariant_report = state.check_invariants();
        if !invariant_report.all_passed {
            return Err(ReplayError::InvariantFailed {
                line: line_num,
                seq: entry.seq,
                report: invariant_report,
            });
        }

        expected_prev_hash = entry.hash;
        expected_seq += 1;
        events_count += 1;
    }

    let invariant_report = state.check_invariants();
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
    use crate::auth::{
        build_authority_event_preimage, build_burn_preimage, build_genesis_preimage,
        build_mint_preimage, build_transfer_preimage, build_vvb_register_payload, Keypair,
        MintAttestationParams, PubKey,
    };
    use crate::poo::ClaimType;

    fn setup_keys() -> (Keypair, Keypair, Keypair, Keypair, Keypair) {
        let authority = Keypair::from_seed_str("authority-seed");
        let sequencer = Keypair::from_seed_str("sequencer-seed");
        let vvb = Keypair::from_seed_str("vvb-seed");
        let alice = Keypair::from_seed_str("alice-seed");
        let bob = Keypair::from_seed_str("bob-seed");
        (authority, sequencer, vvb, alice, bob)
    }

    fn make_genesis_entry(
        authority: &Keypair,
        sequencer: &Keypair,
        chain_name: &str,
    ) -> (EventEntry, [u8; 32]) {
        let nonce = [7u8; 32];
        let created_at = 1_700_000_000;
        let genesis_msg = build_genesis_preimage(
            chain_name,
            &authority.pubkey(),
            &sequencer.pubkey(),
            &nonce,
            created_at,
        );
        let authority_sig = authority.sign(&genesis_msg);
        let event = RegistryEvent::Genesis {
            chain_name: chain_name.to_string(),
            authority: authority.pubkey(),
            sequencer: sequencer.pubkey(),
            nonce,
            created_at,
            authority_sig,
        };
        let entry = EventEntry::new(0, GENESIS_PREV_HASH.to_string(), event).unwrap();
        let chain_id = crate::auth::compute_chain_id(&entry.event.to_body_bytes());
        (entry, chain_id)
    }

    fn make_vvb_register_entry(
        seq: u64,
        prev_hash: &str,
        chain_id: &[u8; 32],
        authority: &Keypair,
        authority_index: u64,
        vvb: &PubKey,
        label: &str,
    ) -> EventEntry {
        let payload = build_vvb_register_payload(vvb, label);
        let msg =
            build_authority_event_preimage("vvb-register", chain_id, authority_index, &payload);
        let authority_sig = authority.sign(&msg);
        let event = RegistryEvent::VvbRegister {
            authority_index,
            vvb: *vvb,
            label: label.to_string(),
            authority_sig,
        };
        EventEntry::new(seq, prev_hash.to_string(), event).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_mint_entry(
        seq: u64,
        prev_hash: &str,
        chain_id: &[u8; 32],
        vvb: &Keypair,
        credit_id: &str,
        start: u64,
        end: u64,
        owner: &PubKey,
    ) -> EventEntry {
        let mut root = [0u8; 32];
        let bytes = credit_id.as_bytes();
        let len = bytes.len().min(32);
        root[..len].copy_from_slice(&bytes[..len]);
        let amount = end - start + 1;

        let params = MintAttestationParams {
            chain_id,
            project_id: "PRJ-001",
            credit_id,
            range_start: start,
            range_end: end,
            cc_mint_amount: amount,
            merkle_root: &root,
            leaf_count: 1,
            mrv_timestamp: 1_700_000_000,
            methodology_hash: "0xMETH01",
            jurisdiction: "IN",
            market_scope: "VCM",
            valid_from: 1_700_000_000,
            valid_until: 1_730_000_000,
            initial_owner: owner,
        };
        let msg = build_mint_preimage(&params);
        let vvb_sig = vvb.sign(&msg);

        let event = RegistryEvent::Mint {
            project_id: "PRJ-001".to_string(),
            credit_id: credit_id.to_string(),
            range_start: start,
            range_end: end,
            cc_mint_amount: amount,
            merkle_root: root,
            leaf_count: 1,
            mrv_timestamp: 1_700_000_000,
            methodology_hash: "0xMETH01".to_string(),
            jurisdiction: "IN".to_string(),
            market_scope: "VCM".to_string(),
            valid_from: 1_700_000_000,
            valid_until: 1_730_000_000,
            initial_owner: *owner,
            vvb: vvb.pubkey(),
            vvb_sig,
        };
        EventEntry::new(seq, prev_hash.to_string(), event).unwrap()
    }

    fn make_transfer_entry(
        seq: u64,
        prev_hash: &str,
        chain_id: &[u8; 32],
        owner_key: &Keypair,
        credit_id: &str,
        op_index: u64,
        new_owner: &PubKey,
    ) -> EventEntry {
        let msg = build_transfer_preimage(chain_id, credit_id, op_index, new_owner);
        let owner_sig = owner_key.sign(&msg);
        let event = RegistryEvent::Transfer {
            credit_id: credit_id.to_string(),
            op_index,
            new_owner: *new_owner,
            owner_sig,
        };
        EventEntry::new(seq, prev_hash.to_string(), event).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn make_burn_entry(
        seq: u64,
        prev_hash: &str,
        chain_id: &[u8; 32],
        owner_key: &Keypair,
        credit_id: &str,
        op_index: u64,
        start: u64,
        end: u64,
        beneficiary: &str,
        claim_type: ClaimType,
    ) -> EventEntry {
        let msg = build_burn_preimage(
            chain_id,
            credit_id,
            op_index,
            start,
            end,
            beneficiary,
            claim_type.as_str(),
        );
        let owner_sig = owner_key.sign(&msg);
        let event = RegistryEvent::Burn {
            credit_id: credit_id.to_string(),
            op_index,
            range_start: start,
            range_end: end,
            beneficiary: beneficiary.to_string(),
            claim_type,
            owner_sig,
        };
        EventEntry::new(seq, prev_hash.to_string(), event).unwrap()
    }

    #[test]
    fn test_canonical_line_rendering_and_parsing() {
        let (authority, sequencer, vvb, alice, _) = setup_keys();
        let (e0, chain_id) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let e1 = make_vvb_register_entry(
            1,
            &e0.hash,
            &chain_id,
            &authority,
            0,
            &vvb.pubkey(),
            "TUV SUD",
        );
        let e2 = make_mint_entry(
            2,
            &e1.hash,
            &chain_id,
            &vvb,
            "CC-TEST-1",
            1000,
            1999,
            &alice.pubkey(),
        );

        for entry in [&e0, &e1, &e2] {
            let line = render_canonical_line(entry);
            assert!(!line.contains('\n'));
            assert!(!line.contains('\r'));
            let parsed = parse_canonical_line(&line, 1).unwrap();
            assert_eq!(entry, &parsed);
            assert!(parsed.verify_hash());
        }
    }

    #[test]
    fn test_rejection_crlf_and_comments() {
        let (authority, sequencer, _, _, _) = setup_keys();
        let (e0, _) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let line = render_canonical_line(&e0);

        // Reject CRLF
        let crlf = format!("{line}\r\n");
        assert!(matches!(
            parse_canonical_line(&crlf, 1),
            Err(ReplayError::NonCanonicalLine { .. })
        ));

        // Reject comment line
        assert!(matches!(
            parse_canonical_line("# This is a comment", 1),
            Err(ReplayError::NonCanonicalLine { .. })
        ));

        // Reject blank line
        assert!(matches!(
            parse_canonical_line("", 1),
            Err(ReplayError::NonCanonicalLine { .. })
        ));

        // Reject padded line
        let padded = format!(" {line} ");
        assert!(matches!(
            parse_canonical_line(&padded, 1),
            Err(ReplayError::NonCanonicalLine { .. })
        ));
    }

    #[test]
    fn test_full_chain_replay_and_invariants() {
        let (authority, sequencer, vvb, alice, bob) = setup_keys();
        let (e0, chain_id) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let e1 = make_vvb_register_entry(
            1,
            &e0.hash,
            &chain_id,
            &authority,
            0,
            &vvb.pubkey(),
            "TUV SUD",
        );
        let e2 = make_mint_entry(
            2,
            &e1.hash,
            &chain_id,
            &vvb,
            "CC-IN-SOLAR-2026-001",
            1_000_000,
            1_000_999,
            &alice.pubkey(),
        );
        let e3 = make_transfer_entry(
            3,
            &e2.hash,
            &chain_id,
            &alice,
            "CC-IN-SOLAR-2026-001",
            0,
            &bob.pubkey(),
        );
        let e4 = make_burn_entry(
            4,
            &e3.hash,
            &chain_id,
            &bob,
            "CC-IN-SOLAR-2026-001",
            1,
            1_000_200,
            1_000_399,
            "ZeroNet Corp",
            ClaimType::CorporateNetZero,
        );

        let lines = vec![
            render_canonical_line(&e0),
            render_canonical_line(&e1),
            render_canonical_line(&e2),
            render_canonical_line(&e3),
            render_canonical_line(&e4),
        ];

        let summary = replay_log_with_anchor(lines, Some(&chain_id)).unwrap();
        assert_eq!(summary.events_count, 5);
        assert_eq!(summary.final_hash, e4.hash);
        assert!(summary.chain_valid);
        assert_eq!(summary.total_credits, 1000);
        assert_eq!(summary.active_credits, 800);
        assert_eq!(summary.retired_credits, 200);
        assert_eq!(summary.batches_count, 1);
        assert!(summary.invariant_report.all_passed);
        assert!(summary.invariant_report.inva1_signature_validity);
        assert!(summary.invariant_report.inva2_op_index_contiguity);
        assert!(summary.invariant_report.inva3_chain_id_binding);
        assert_eq!(summary.state.credits[0].owner, bob.pubkey());
        assert_eq!(summary.state.credits[0].op_index, 2);
    }

    #[test]
    fn test_chain_id_mismatch_rejection() {
        let (authority, sequencer, _, _, _) = setup_keys();
        let (e0, _) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let wrong_anchor = [99u8; 32];
        let lines = vec![render_canonical_line(&e0)];
        let err = replay_log_with_anchor(lines, Some(&wrong_anchor)).unwrap_err();
        assert!(matches!(err, ReplayError::ChainIdMismatch { .. }));
    }

    #[test]
    fn test_replay_detects_broken_hash_chain() {
        let (authority, sequencer, vvb, _, _) = setup_keys();
        let (e0, chain_id) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let mut e1 = make_vvb_register_entry(
            1,
            &e0.hash,
            &chain_id,
            &authority,
            0,
            &vvb.pubkey(),
            "TUV SUD",
        );
        e1.prev_hash =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        e1.hash = compute_entry_hash(1, &e1.prev_hash, &e1.event).unwrap();

        let lines = vec![render_canonical_line(&e0), render_canonical_line(&e1)];
        let err = replay_log(lines).unwrap_err();
        match err {
            ReplayError::HashChainBroken { line, seq, .. } => {
                assert_eq!(line, 2);
                assert_eq!(seq, 1);
            }
            other => panic!("Expected HashChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_detects_tampered_hash() {
        let (authority, sequencer, _, _, _) = setup_keys();
        let (mut e0, _) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        e0.hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let lines = vec![render_canonical_line(&e0)];
        let err = replay_log(lines).unwrap_err();
        match err {
            ReplayError::HashTampered { line, seq, .. } => {
                assert_eq!(line, 1);
                assert_eq!(seq, 0);
            }
            other => panic!("Expected HashTampered, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_detects_sequence_gap() {
        let (authority, sequencer, vvb, _, _) = setup_keys();
        let (e0, chain_id) = make_genesis_entry(&authority, &sequencer, "GreyMisnomer-Alpha");
        let e1 = make_vvb_register_entry(
            2, // Sequence gap: 2 instead of 1
            &e0.hash,
            &chain_id,
            &authority,
            0,
            &vvb.pubkey(),
            "TUV SUD",
        );
        let lines = vec![render_canonical_line(&e0), render_canonical_line(&e1)];
        let err = replay_log(lines).unwrap_err();
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
}
