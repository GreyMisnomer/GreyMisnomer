use serde::{Deserialize, Serialize};

// --- MRVRecord -----------------------------------------------------------
// Represents one normalized off-chain measurement (sensor, satellite, meter).
// Each record becomes one leaf in the Merkle Tree.
// Real production records will carry more fields; this is the Phase Alpha shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MRVRecord {
    pub timestamp: u64,   // Unix epoch of the measurement
    pub value: f64,        // Quantity measured (e.g. kWh generated, kg CO2 captured)
    pub unit: String,      // Unit string — "kWh", "tCO2e", etc.
    pub source: String,    // Data source identifier — sensor ID, satellite pass ID, etc.
}

// --- MRVCommitment -------------------------------------------------------
// The single on-chain artifact that represents an entire MRV dataset.
// Stored inside PoI.mrv_commitment — binds the credit to real-world data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MRVCommitment {
    // BLAKE3 Merkle Root of all MRV records for this issuance period
    pub merkle_root: [u8; 32],
    // Algorithm used — "BLAKE3" for Phase Alpha
    pub hash_algorithm: String,
    // Number of leaf records hashed into the tree
    pub leaf_count: u64,
    // Unix timestamp when this commitment was finalized
    pub timestamp: u64,
}

// --- hash_record ---------------------------------------------------------
// RFC-003 §3.2: leaf nodes are Hash(normalized_record).
// We serialize deterministically: "timestamp|value|unit|source"
// This must be stable — changing the format invalidates all existing proofs.
pub fn hash_record(record: &MRVRecord) -> [u8; 32] {
    let data = format!(
        "{}|{}|{}|{}",
        record.timestamp, record.value, record.unit, record.source
    );
    blake3::hash(data.as_bytes()).into()
}

// --- build_merkle_root ---------------------------------------------------
// RFC-003 §3.2: internal nodes are Hash(left_child || right_child).
// Odd leaf at any level is promoted unchanged (no duplication — avoids
// second-preimage attacks from duplicate padding).
// Returns [0u8; 32] for an empty dataset — caller must treat this as invalid.
pub fn build_merkle_root(records: &[MRVRecord]) -> [u8; 32] {
    if records.is_empty() {
        return [0u8; 32];
    }

    // Build leaf layer
    let mut layer: Vec<[u8; 32]> = records.iter().map(hash_record).collect();

    // Reduce bottom-up until one root remains
    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut i = 0;
        while i < layer.len() {
            if i + 1 < layer.len() {
                // Combine pair
                let mut hasher = blake3::Hasher::new();
                hasher.update(&layer[i]);
                hasher.update(&layer[i + 1]);
                next.push(hasher.finalize().into());
                i += 2;
            } else {
                // Odd leaf — promote unchanged
                next.push(layer[i]);
                i += 1;
            }
        }
        layer = next;
    }

    layer[0]
}

// --- generate_inclusion_proof --------------------------------------------
// Produces the sibling-hash path from leaf `index` to the root.
// Each entry is (sibling_hash, is_right_sibling).
// Verifier uses this path to recompute the root independently.
pub fn generate_inclusion_proof(
    records: &[MRVRecord],
    index: usize,
) -> Option<Vec<([u8; 32], bool)>> {
    if records.is_empty() || index >= records.len() {
        return None;
    }

    let mut layer: Vec<[u8; 32]> = records.iter().map(hash_record).collect();
    let mut proof: Vec<([u8; 32], bool)> = Vec::new();
    let mut idx = index;

    while layer.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::new();
        let mut new_idx = 0;
        let mut i = 0;

        while i < layer.len() {
            if i + 1 < layer.len() {
                // Track sibling for the proof path
                if i == idx || i + 1 == idx {
                    if i == idx {
                        // Our node is left; sibling is right
                        proof.push((layer[i + 1], true));
                        new_idx = next.len();
                    } else {
                        // Our node is right; sibling is left
                        proof.push((layer[i], false));
                        new_idx = next.len();
                    }
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(&layer[i]);
                hasher.update(&layer[i + 1]);
                next.push(hasher.finalize().into());
                i += 2;
            } else {
                // Odd leaf promoted
                if i == idx {
                    new_idx = next.len();
                }
                next.push(layer[i]);
                i += 1;
            }
        }

        idx = new_idx;
        layer = next;
    }

    Some(proof)
}

// --- verify_inclusion_proof ----------------------------------------------
// RFC-003 §4.3: recompute root from record + proof path and compare.
// Returns true only if the recomputed root matches the commitment.
pub fn verify_inclusion_proof(
    record: &MRVRecord,
    proof: &[([u8; 32], bool)],
    root: &[u8; 32],
) -> bool {
    let mut current = hash_record(record);

    for (sibling, is_right) in proof {
        let mut hasher = blake3::Hasher::new();
        if *is_right {
            // sibling is to the right — we are the left child
            hasher.update(&current);
            hasher.update(sibling);
        } else {
            // sibling is to the left — we are the right child
            hasher.update(sibling);
            hasher.update(&current);
        }
        current = hasher.finalize().into();
    }

    &current == root
}

// --- Helper: build MRVCommitment from records ----------------------------
// Convenience function used in tests and integration flows.
pub fn commit(records: &[MRVRecord], timestamp: u64) -> MRVCommitment {
    MRVCommitment {
        merkle_root: build_merkle_root(records),
        hash_algorithm: "BLAKE3".to_string(),
        leaf_count: records.len() as u64,
        timestamp,
    }
}

// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(ts: u64, val: f64) -> MRVRecord {
        MRVRecord {
            timestamp: ts,
            value: val,
            unit: "kWh".to_string(),
            source: "SENSOR-001".to_string(),
        }
    }

    // RFC-003 invariant: root computation is deterministic
    #[test]
    fn root_is_deterministic() {
        let records = vec![make_record(1000, 42.0), make_record(1001, 38.5)];
        let root_a = build_merkle_root(&records);
        let root_b = build_merkle_root(&records);
        assert_eq!(root_a, root_b);
    }

    // Empty dataset returns the zero hash (caller must reject this)
    #[test]
    fn empty_dataset_returns_zero_hash() {
        let root = build_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    // Single-record tree: root == hash of that record
    #[test]
    fn single_record_root_equals_leaf_hash() {
        let r = make_record(500, 10.0);
        let root = build_merkle_root(&[r.clone()]);
        assert_eq!(root, hash_record(&r));
    }

    // Inclusion proof: valid record verifies against root
    #[test]
    fn inclusion_proof_valid_record() {
        let records = vec![
            make_record(1, 10.0),
            make_record(2, 20.0),
            make_record(3, 30.0),
            make_record(4, 40.0),
        ];
        let root = build_merkle_root(&records);
        for i in 0..records.len() {
            let proof = generate_inclusion_proof(&records, i).unwrap();
            assert!(
                verify_inclusion_proof(&records[i], &proof, &root),
                "Proof failed for record index {i}"
            );
        }
    }

    // Tampered leaf must NOT verify — RFC-003 invariant
    #[test]
    fn tampered_leaf_fails_proof() {
        let records = vec![make_record(1, 10.0), make_record(2, 20.0)];
        let root = build_merkle_root(&records);
        let proof = generate_inclusion_proof(&records, 0).unwrap();

        // Tamper: change the value
        let tampered = make_record(1, 99.0);
        assert!(!verify_inclusion_proof(&tampered, &proof, &root));
    }

    // Odd-number dataset: promotion logic handles the unpaired leaf
    #[test]
    fn odd_number_of_records() {
        let records = vec![
            make_record(1, 10.0),
            make_record(2, 20.0),
            make_record(3, 30.0),
        ];
        let root = build_merkle_root(&records);
        for i in 0..records.len() {
            let proof = generate_inclusion_proof(&records, i).unwrap();
            assert!(
                verify_inclusion_proof(&records[i], &proof, &root),
                "Proof failed for odd-tree index {i}"
            );
        }
    }

    // Different data must produce different roots
    #[test]
    fn different_data_different_roots() {
        let a = vec![make_record(1, 10.0), make_record(2, 20.0)];
        let b = vec![make_record(1, 10.0), make_record(2, 99.0)];
        assert_ne!(build_merkle_root(&a), build_merkle_root(&b));
    }

    // commit() helper produces correct metadata
    #[test]
    fn commit_helper_correct_metadata() {
        let records = vec![make_record(1, 5.0), make_record(2, 5.0)];
        let c = commit(&records, 9999);
        assert_eq!(c.leaf_count, 2);
        assert_eq!(c.timestamp, 9999);
        assert_eq!(c.hash_algorithm, "BLAKE3");
        assert_eq!(c.merkle_root, build_merkle_root(&records));
    }
}
