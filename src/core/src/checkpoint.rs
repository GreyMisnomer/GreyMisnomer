use crate::auth::{build_checkpoint_preimage, Keypair, PubKey, Signature};
use crate::error::RegistryError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A cryptographically signed checkpoint committing to a log size and head hash (RFC-005 §3.7).
/// Checkpoints are published under `checkpoints/<size>.json` and anchored to Bitcoin via OTS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(with = "crate::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    pub size: u64,
    #[serde(with = "crate::auth::hex_bytes32")]
    pub head_hash: [u8; 32],
    pub timestamp: u64,
    pub sig: Signature,
}

impl Checkpoint {
    /// Constructs and signs a new Checkpoint with the sequencer key.
    pub fn new(
        chain_id: [u8; 32],
        size: u64,
        head_hash: [u8; 32],
        timestamp: u64,
        sequencer_key: &Keypair,
    ) -> Self {
        let msg = build_checkpoint_preimage(&chain_id, size, &head_hash, timestamp);
        let sig = sequencer_key.sign(&msg);
        Self {
            chain_id,
            size,
            head_hash,
            timestamp,
            sig,
        }
    }

    /// Verifies strict Ed25519 signature under the authorized sequencer public key.
    pub fn verify(&self, sequencer: &PubKey) -> Result<(), RegistryError> {
        let msg =
            build_checkpoint_preimage(&self.chain_id, self.size, &self.head_hash, self.timestamp);
        sequencer.verify_strict(&msg, &self.sig)
    }

    /// Renders the canonical JSON string with fixed key order and no whitespace (RFC-005 §3.7).
    pub fn to_canonical_json(&self) -> String {
        format!(
            r#"{{"chain_id":"{}","size":{},"head_hash":"{}","timestamp":{},"sig":"{}"}}"#,
            hex::encode(self.chain_id),
            self.size,
            hex::encode(self.head_hash),
            self.timestamp,
            self.sig
        )
    }

    /// Parses a checkpoint from JSON.
    pub fn from_json(json: &str) -> Result<Self, RegistryError> {
        serde_json::from_str(json).map_err(|_| RegistryError::BadSignature)
    }
}

/// An offline, self-contained proof of sequencer equivocation (RFC-005 §3.7).
/// Two valid sequencer signatures for the same log size but different head hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub size: u64,
    pub chain_id: String,
    pub head_hash_a: String,
    pub sig_a: String,
    pub timestamp_a: u64,
    pub head_hash_b: String,
    pub sig_b: String,
    pub timestamp_b: u64,
}

/// Checks an iterator or slice of checkpoints for equivocation.
/// If any two checkpoints share the same size but have different head hashes, returns an EquivocationProof.
pub fn detect_equivocation<'a>(
    checkpoints: impl IntoIterator<Item = &'a Checkpoint>,
) -> Option<EquivocationProof> {
    let mut by_size: BTreeMap<u64, &'a Checkpoint> = BTreeMap::new();
    for cp in checkpoints {
        if let Some(existing) = by_size.get(&cp.size) {
            if existing.head_hash != cp.head_hash {
                return Some(EquivocationProof {
                    size: cp.size,
                    chain_id: hex::encode(cp.chain_id),
                    head_hash_a: hex::encode(existing.head_hash),
                    sig_a: existing.sig.to_hex(),
                    timestamp_a: existing.timestamp,
                    head_hash_b: hex::encode(cp.head_hash),
                    sig_b: cp.sig.to_hex(),
                    timestamp_b: cp.timestamp,
                });
            }
        } else {
            by_size.insert(cp.size, cp);
        }
    }
    None
}

/// Summary report for a verified checkpoint against replayed log state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointReport {
    pub size: u64,
    pub head_hash: String,
    pub timestamp: u64,
    pub verified: bool,
}

/// Verifies a collection of checkpoints against the replayed log's entry hashes and sequencer key.
///
/// Ensures:
/// 1. No equivocation exists across the checkpoints.
/// 2. Every checkpoint matches the expected chain_id.
/// 3. For any checkpoint with size <= log_size, its head_hash matches the entry hash at index (size - 1).
/// 4. Every checkpoint signature verifies under the designated sequencer public key.
pub fn verify_checkpoints<'a>(
    checkpoints: impl IntoIterator<Item = &'a Checkpoint>,
    entry_hashes: &[[u8; 32]],
    sequencer: &PubKey,
    chain_id: &[u8; 32],
) -> Result<Vec<CheckpointReport>, RegistryError> {
    let cp_list: Vec<&'a Checkpoint> = checkpoints.into_iter().collect();

    // 1. Check for equivocation
    if let Some(equivocation) = detect_equivocation(cp_list.iter().copied()) {
        return Err(RegistryError::CheckpointEquivocation {
            size: equivocation.size,
            head_a: equivocation.head_hash_a,
            head_b: equivocation.head_hash_b,
        });
    }

    let mut reports = Vec::with_capacity(cp_list.len());

    for cp in cp_list {
        // 2. Chain ID check
        if cp.chain_id != *chain_id {
            return Err(RegistryError::WrongChain {
                expected: hex::encode(chain_id),
                found: hex::encode(cp.chain_id),
            });
        }

        // 3. Size check against replayed log
        if cp.size == 0 {
            return Err(RegistryError::InvalidRange);
        }

        if cp.size as usize <= entry_hashes.len() {
            let expected_head = entry_hashes[(cp.size - 1) as usize];
            if cp.head_hash != expected_head {
                return Err(RegistryError::CheckpointHeadMismatch {
                    size: cp.size,
                    expected: hex::encode(expected_head),
                    found: hex::encode(cp.head_hash),
                });
            }
        }

        // 4. Strict Ed25519 signature check
        cp.verify(sequencer)?;

        reports.push(CheckpointReport {
            size: cp.size,
            head_hash: hex::encode(cp.head_hash),
            timestamp: cp.timestamp,
            verified: true,
        });
    }

    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_signing_and_verification() {
        let sequencer = Keypair::from_seed_str("sequencer-test-seed");
        let chain_id = [11u8; 32];
        let head_hash = [22u8; 32];
        let size = 5;
        let timestamp = 1_700_000_000;

        let cp = Checkpoint::new(chain_id, size, head_hash, timestamp, &sequencer);
        assert!(cp.verify(&sequencer.pubkey()).is_ok());

        // Forged sequencer fails
        let imposter = Keypair::from_seed_str("imposter-seed");
        assert!(cp.verify(&imposter.pubkey()).is_err());

        // Tampered head hash fails
        let mut tampered = cp.clone();
        tampered.head_hash[0] ^= 0xff;
        assert!(tampered.verify(&sequencer.pubkey()).is_err());

        // Tampered size fails
        let mut tampered_size = cp.clone();
        tampered_size.size = 6;
        assert!(tampered_size.verify(&sequencer.pubkey()).is_err());
    }

    #[test]
    fn test_canonical_json_roundtrip() {
        let sequencer = Keypair::from_seed_str("sequencer-test-seed");
        let chain_id = [1u8; 32];
        let head_hash = [2u8; 32];
        let cp = Checkpoint::new(chain_id, 3, head_hash, 1_700_000_000, &sequencer);

        let json = cp.to_canonical_json();
        assert!(json.starts_with(r#"{"chain_id":""#));
        assert!(json.contains(r#","size":3,"head_hash":""#));
        assert!(json.ends_with(r#"}"#));

        let parsed = Checkpoint::from_json(&json).unwrap();
        assert_eq!(cp, parsed);
    }

    #[test]
    fn test_equivocation_detection() {
        let sequencer = Keypair::from_seed_str("sequencer-test-seed");
        let chain_id = [1u8; 32];
        let head_a = [10u8; 32];
        let head_b = [20u8; 32];

        let cp1 = Checkpoint::new(chain_id, 5, head_a, 1_700_000_000, &sequencer);
        let cp2 = Checkpoint::new(chain_id, 5, head_b, 1_700_000_001, &sequencer);

        // Different head hash at same size = equivocation detected!
        let equiv = detect_equivocation(&[cp1.clone(), cp2.clone()]);
        assert!(equiv.is_some());
        let proof = equiv.unwrap();
        assert_eq!(proof.size, 5);
        assert_eq!(proof.head_hash_a, hex::encode(head_a));
        assert_eq!(proof.head_hash_b, hex::encode(head_b));

        // Same head hash at same size = no equivocation
        let cp3 = Checkpoint::new(chain_id, 5, head_a, 1_700_000_000, &sequencer);
        assert!(detect_equivocation(&[cp1, cp3]).is_none());
    }

    #[test]
    fn test_verify_checkpoints_against_log_history() {
        let sequencer = Keypair::from_seed_str("sequencer-test-seed");
        let chain_id = [1u8; 32];
        let h0 = [10u8; 32];
        let h1 = [20u8; 32];
        let h2 = [30u8; 32];
        let entry_hashes = vec![h0, h1, h2];

        let cp1 = Checkpoint::new(chain_id, 1, h0, 1_700_000_000, &sequencer);
        let cp2 = Checkpoint::new(chain_id, 3, h2, 1_700_000_010, &sequencer);

        let reports =
            verify_checkpoints(&[cp1, cp2], &entry_hashes, &sequencer.pubkey(), &chain_id).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|r| r.verified));

        // Wrong head hash at size 2
        let wrong_cp = Checkpoint::new(chain_id, 2, [99u8; 32], 1_700_000_005, &sequencer);
        let err = verify_checkpoints(&[wrong_cp], &entry_hashes, &sequencer.pubkey(), &chain_id)
            .unwrap_err();
        assert!(matches!(err, RegistryError::CheckpointHeadMismatch { .. }));
    }
}
