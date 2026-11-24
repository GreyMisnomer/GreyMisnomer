//! RFC-007 §5: C2SP `tlog-cosignature` Witness Protocol.
//!
//! Provides non-equivocation and split-view immunity across $k$-of-$n$ independent
//! witnesses without requiring heavy multi-round BFT state replication.
//!
//! Specification: [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)
//! Format: `cosignature/v1\ntime <timestamp>\n<checkpoint note>`

use crate::auth::{Keypair, PubKey, Signature};
use crate::error::RegistryError;
use crate::merkle_log::{verify_consistency, ConsistencyProof};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const COSIGNATURE_V1_TAG: &str = "cosignature/v1";

// ---------------------------------------------------------------------------
// Witness Bookmark (~64 bytes per tracked log)
// ---------------------------------------------------------------------------

/// The minimal state a witness stores for a tracked registry chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBookmark {
    pub tree_size: u64,
    #[serde(with = "crate::auth::hex_bytes32")]
    pub events_root: [u8; 32],
}

impl WitnessBookmark {
    pub fn new(tree_size: u64, events_root: [u8; 32]) -> Self {
        Self {
            tree_size,
            events_root,
        }
    }
}

// ---------------------------------------------------------------------------
// Cosignature Record
// ---------------------------------------------------------------------------

/// A signed C2SP cosignature attesting a specific checkpoint note at a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    /// Identifier of the witness (e.g. "climate-ngo-witness", "university-lab-1")
    pub witness_name: String,
    /// 4-byte key identifier (first 4 bytes of witness pubkey or BLAKE3(pubkey))
    pub key_id: [u8; 4],
    /// Unix timestamp in seconds when the cosignature was produced
    pub timestamp: u64,
    /// The detached Ed25519 signature
    pub signature: Signature,
}

impl Cosignature {
    /// Formats as a canonical C2SP cosignature note line:
    /// `— <witness_name> <hex_key_id><hex_timestamp_16><hex_signature_128>`
    pub fn to_note_line(&self) -> String {
        format!(
            "— {} {:08x}{:016x}{}",
            self.witness_name,
            u32::from_be_bytes(self.key_id),
            self.timestamp,
            self.signature.to_hex()
        )
    }

    /// Parses a C2SP cosignature line starting with `—` or `--`.
    pub fn parse_note_line(line: &str) -> Result<Self, RegistryError> {
        let trimmed = line.trim();
        let payload = if let Some(rest) = trimmed.strip_prefix('—') {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix("--") {
            rest.trim()
        } else {
            return Err(RegistryError::BadSignature);
        };

        let mut parts = payload.split_whitespace();
        let witness_name = parts.next().ok_or(RegistryError::BadSignature)?.to_string();
        let blob = parts.next().ok_or(RegistryError::BadSignature)?;

        if blob.len() != 152 {
            return Err(RegistryError::BadSignature);
        }

        let key_id_bytes = hex::decode(&blob[..8]).map_err(|_| RegistryError::BadSignature)?;
        let mut key_id = [0u8; 4];
        key_id.copy_from_slice(&key_id_bytes);

        let timestamp_bytes = hex::decode(&blob[8..24]).map_err(|_| RegistryError::BadSignature)?;
        let timestamp = u64::from_be_bytes(
            timestamp_bytes
                .try_into()
                .map_err(|_| RegistryError::BadSignature)?,
        );

        let signature = Signature::from_hex(&blob[24..152])?;

        Ok(Self {
            witness_name,
            key_id,
            timestamp,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// C2SP Preimage Formatter
// ---------------------------------------------------------------------------

/// Builds the canonical C2SP `cosignature/v1` signing preimage:
/// `cosignature/v1\ntime <timestamp>\n<checkpoint_note>`
pub fn build_cosignature_preimage(checkpoint_note: &str, timestamp: u64) -> Vec<u8> {
    format!("{COSIGNATURE_V1_TAG}\ntime {timestamp}\n{checkpoint_note}").into_bytes()
}

// ---------------------------------------------------------------------------
// Core Witness Evaluation Engine
// ---------------------------------------------------------------------------

/// Request payload submitted to a witness to cosign an updated checkpoint note.
#[derive(Debug, Clone)]
pub struct CosignRequest<'a> {
    pub new_size: u64,
    pub new_root: &'a [u8; 32],
    pub consistency_proof: &'a ConsistencyProof,
    pub checkpoint_note: &'a str,
    pub timestamp: u64,
}

/// Witness evaluation decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessDecision {
    /// Checkpoint is an identical re-submission; returns existing cosignature
    Identical(Cosignature),
    /// Valid extension verified by consistency proof; returns new bookmark & cosignature
    Extended {
        new_bookmark: WitnessBookmark,
        cosignature: Cosignature,
    },
}

/// Evaluates a checkpoint cosigning request against the witness's persistent bookmark.
///
/// Rules (RFC-007 §5.1 & C2SP):
/// 1. If `new_size < bookmark.tree_size`: Equivocation / Rollback attempt! REJECT.
/// 2. If `new_size == bookmark.tree_size`:
///    - If `new_root != bookmark.events_root`: Equivocation fork! REJECT.
///    - If identical: re-cosign / return identical decision.
/// 3. If `new_size > bookmark.tree_size`:
///    - Verify RFC 9162 consistency proof links `bookmark.events_root` to `new_root`.
///    - If valid, advance bookmark and produce new cosignature.
pub fn evaluate_cosign_request(
    bookmark: &WitnessBookmark,
    req: &CosignRequest<'_>,
    witness_name: &str,
    witness_keypair: &Keypair,
) -> Result<WitnessDecision, RegistryError> {
    let key_id = compute_key_id(&witness_keypair.pubkey());

    // 1. Rollback attempt
    if req.new_size < bookmark.tree_size {
        return Err(RegistryError::CheckpointEquivocation {
            size: req.new_size,
            head_a: format!("current bookmark size {}", bookmark.tree_size),
            head_b: format!("attempted rollback size {}", req.new_size),
        });
    }

    // 2. Same size check
    if req.new_size == bookmark.tree_size {
        if *req.new_root != bookmark.events_root {
            return Err(RegistryError::CheckpointEquivocation {
                size: req.new_size,
                head_a: hex::encode(bookmark.events_root),
                head_b: hex::encode(req.new_root),
            });
        }
        let preimage = build_cosignature_preimage(req.checkpoint_note, req.timestamp);
        let signature = witness_keypair.sign(&preimage);
        return Ok(WitnessDecision::Identical(Cosignature {
            witness_name: witness_name.to_string(),
            key_id,
            timestamp: req.timestamp,
            signature,
        }));
    }

    // 3. New extension: verify consistency proof if extending from non-genesis
    if bookmark.tree_size > 0 {
        if req.consistency_proof.old_size != bookmark.tree_size
            || req.consistency_proof.new_size != req.new_size
        {
            return Err(RegistryError::InvalidRange);
        }

        let is_consistent =
            verify_consistency(req.consistency_proof, &bookmark.events_root, req.new_root);
        if !is_consistent {
            return Err(RegistryError::CheckpointHeadMismatch {
                size: req.new_size,
                expected: hex::encode(bookmark.events_root),
                found: hex::encode(req.new_root),
            });
        }
    }

    // Valid extension: sign cosignature
    let preimage = build_cosignature_preimage(req.checkpoint_note, req.timestamp);
    let signature = witness_keypair.sign(&preimage);

    let new_bookmark = WitnessBookmark::new(req.new_size, *req.new_root);
    let cosignature = Cosignature {
        witness_name: witness_name.to_string(),
        key_id,
        timestamp: req.timestamp,
        signature,
    };

    Ok(WitnessDecision::Extended {
        new_bookmark,
        cosignature,
    })
}

/// Verifies that a checkpoint note carries at least $k$-of-$n$ valid witness cosignatures.
pub fn verify_witness_quorum(
    checkpoint_note: &str,
    cosignatures: &[Cosignature],
    witness_keys: &BTreeMap<String, PubKey>,
    k_of_n: usize,
) -> Result<(), RegistryError> {
    if cosignatures.len() < k_of_n {
        return Err(RegistryError::OracleQuorumNotMet {
            required: k_of_n,
            found: cosignatures.len(),
        });
    }

    let mut valid_witnesses = std::collections::BTreeSet::new();

    for cosig in cosignatures {
        let pubkey =
            witness_keys
                .get(&cosig.witness_name)
                .ok_or_else(|| RegistryError::UnknownVvb {
                    vvb: cosig.witness_name.clone(),
                })?;

        let expected_key_id = compute_key_id(pubkey);
        if cosig.key_id != expected_key_id {
            return Err(RegistryError::BadSignature);
        }

        let preimage = build_cosignature_preimage(checkpoint_note, cosig.timestamp);
        pubkey
            .verify_strict(&preimage, &cosig.signature)
            .map_err(|_| RegistryError::BadSignature)?;

        valid_witnesses.insert(cosig.witness_name.clone());
    }

    if valid_witnesses.len() < k_of_n {
        return Err(RegistryError::OracleQuorumNotMet {
            required: k_of_n,
            found: valid_witnesses.len(),
        });
    }

    Ok(())
}

/// Computes the 4-byte key identifier from a public key.
pub fn compute_key_id(pubkey: &PubKey) -> [u8; 4] {
    let hash = blake3::hash(pubkey.as_bytes());
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&hash.as_bytes()[..4]);
    key_id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_log::MerkleLogTree;

    #[test]
    fn test_witness_cosign_valid_extension() {
        let witness_key = Keypair::generate();

        let mut log = MerkleLogTree::new();
        for i in 0..4 {
            log.append(format!("event-{i}").as_bytes());
        }
        let old_root = log.root();
        let bookmark = WitnessBookmark::new(4, old_root);

        // Extend log by 4 more events
        for i in 4..8 {
            log.append(format!("event-{i}").as_bytes());
        }
        let new_root = log.root();
        let proof = log.consistency_proof(4).unwrap();

        let note = "greymisnomerd/test\n8\n...";
        let req = CosignRequest {
            new_size: 8,
            new_root: &new_root,
            consistency_proof: &proof,
            checkpoint_note: note,
            timestamp: 1_700_000_000,
        };
        let decision =
            evaluate_cosign_request(&bookmark, &req, "witness-ngo-1", &witness_key).unwrap();

        match decision {
            WitnessDecision::Extended {
                new_bookmark,
                cosignature,
            } => {
                assert_eq!(new_bookmark.tree_size, 8);
                assert_eq!(new_bookmark.events_root, new_root);
                assert_eq!(cosignature.witness_name, "witness-ngo-1");

                // Verify cosignature against witness pubkey
                let mut keys = BTreeMap::new();
                keys.insert("witness-ngo-1".to_string(), witness_key.pubkey());
                assert!(verify_witness_quorum(note, std::slice::from_ref(&cosignature), &keys, 1).is_ok());

                // Test canonical note line format roundtrip
                let line = cosignature.to_note_line();
                let parsed = Cosignature::parse_note_line(&line).expect("parse cosignature line");
                assert_eq!(parsed, cosignature);
            }
            _ => panic!("expected Extended decision"),
        }
    }

    #[test]
    fn test_witness_rejects_forked_equivocation() {
        let witness_key = Keypair::generate();
        let bookmark = WitnessBookmark::new(4, [0x11; 32]);

        // Attempt to submit a conflicting root for the same size 4
        let conflicting_root = [0x22; 32];
        let empty_proof = ConsistencyProof {
            old_size: 4,
            new_size: 4,
            proof_path: vec![],
        };

        let req = CosignRequest {
            new_size: 4,
            new_root: &conflicting_root,
            consistency_proof: &empty_proof,
            checkpoint_note: "note",
            timestamp: 1_700_000_000,
        };
        let err = evaluate_cosign_request(&bookmark, &req, "witness-1", &witness_key).unwrap_err();

        assert!(matches!(err, RegistryError::CheckpointEquivocation { .. }));
    }

    #[test]
    fn test_witness_rejects_rollback() {
        let witness_key = Keypair::generate();
        let bookmark = WitnessBookmark::new(8, [0x11; 32]);

        let empty_proof = ConsistencyProof {
            old_size: 4,
            new_size: 4,
            proof_path: vec![],
        };

        let req = CosignRequest {
            new_size: 4, // 4 < 8 (rollback!)
            new_root: &[0x22; 32],
            consistency_proof: &empty_proof,
            checkpoint_note: "note",
            timestamp: 1_700_000_000,
        };
        let err = evaluate_cosign_request(&bookmark, &req, "witness-1", &witness_key).unwrap_err();

        assert!(matches!(err, RegistryError::CheckpointEquivocation { .. }));
    }

    #[test]
    fn test_witness_quorum_threshold_enforcement() {
        let w1 = Keypair::generate();
        let w2 = Keypair::generate();
        let w3 = Keypair::generate();

        let mut keys = BTreeMap::new();
        keys.insert("w1".to_string(), w1.pubkey());
        keys.insert("w2".to_string(), w2.pubkey());
        keys.insert("w3".to_string(), w3.pubkey());

        let note = "test-checkpoint-note";
        let ts = 1_700_000_000;
        let p = build_cosignature_preimage(note, ts);

        let cosig1 = Cosignature {
            witness_name: "w1".to_string(),
            key_id: compute_key_id(&w1.pubkey()),
            timestamp: ts,
            signature: w1.sign(&p),
        };
        let cosig2 = Cosignature {
            witness_name: "w2".to_string(),
            key_id: compute_key_id(&w2.pubkey()),
            timestamp: ts,
            signature: w2.sign(&p),
        };

        // 2-of-3 quorum met with w1 and w2
        assert!(verify_witness_quorum(note, &[cosig1.clone(), cosig2], &keys, 2).is_ok());

        // 1-of-3 fails 2-of-3 threshold
        let err = verify_witness_quorum(note, &[cosig1], &keys, 2).unwrap_err();
        assert!(matches!(err, RegistryError::OracleQuorumNotMet { .. }));
    }
}
