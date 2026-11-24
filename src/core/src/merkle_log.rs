//! RFC 9162 / RFC-007 §4: Verifiable Certificate Transparency Merkle Log.
//!
//! Provides the mathematical core for GreyMisnomer v2.0's append-only event log:
//! - RFC 9162 Merkle Tree Hash (`MTH`) with `0x00` leaf and `0x01` internal node prefixes.
//! - O(log N) Merkle Inclusion Proofs (`audit_path`).
//! - O(log N) Append-Only Consistency Proofs (`consistency_proof(m, n)`).
//!
//! Enables light clients and C2SP witnesses to verify non-equivocation and
//! log immutability in logarithmic bytes without downloading full history.

use crate::auth::{hash_log_internal, hash_log_leaf};
use crate::error::RegistryError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Proof Structures
// ---------------------------------------------------------------------------

/// Inclusion proof demonstrating that a specific leaf exists at `leaf_index`
/// within a log of size `tree_size` producing `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    #[serde(with = "crate::auth::hex_bytes32")]
    pub leaf_hash: [u8; 32],
    pub audit_path: Vec<[u8; 32]>,
}

/// Append-only consistency proof demonstrating that the log at `new_size`
/// is a pure append-only extension of the log at `old_size`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub proof_path: Vec<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Math Helper: Largest Power of 2 Less Than n (RFC 9162 §2.1.2)
// ---------------------------------------------------------------------------

/// Computes $k = 2^{\lfloor \log_2(n - 1) \rfloor}$, the largest power of 2 strictly less than $n$.
#[inline]
pub fn split_k(n: usize) -> usize {
    debug_assert!(n > 1);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

// ---------------------------------------------------------------------------
// Pure MTH Calculation Over Slice of Leaf Hashes
// ---------------------------------------------------------------------------

/// Computes the RFC 9162 Merkle Tree Hash (MTH) over an arbitrary slice of
/// pre-computed leaf hashes.
pub fn compute_mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    let n = leaves.len();
    match n {
        0 => *blake3::hash(b"").as_bytes(),
        1 => leaves[0],
        _ => {
            let k = split_k(n);
            let left = compute_mth(&leaves[..k]);
            let right = compute_mth(&leaves[k..]);
            hash_log_internal(&left, &right)
        }
    }
}

// ---------------------------------------------------------------------------
// In-Memory Verifiable Merkle Log
// ---------------------------------------------------------------------------

/// Complete verifiable Merkle log accumulator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleLogTree {
    leaf_hashes: Vec<[u8; 32]>,
}

impl MerkleLogTree {
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leaf_hashes: Vec::with_capacity(capacity),
        }
    }

    /// Appends raw canonical event bytes as a new leaf (`hash_log_leaf(0x00 || bytes)`).
    pub fn append(&mut self, event_bytes: &[u8]) -> [u8; 32] {
        let leaf = hash_log_leaf(event_bytes);
        self.leaf_hashes.push(leaf);
        leaf
    }

    /// Appends a pre-computed leaf hash directly.
    pub fn append_leaf_hash(&mut self, leaf_hash: [u8; 32]) {
        self.leaf_hashes.push(leaf_hash);
    }

    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// Computes the current root of the log (`events_root`).
    pub fn root(&self) -> [u8; 32] {
        compute_mth(&self.leaf_hashes)
    }

    /// Returns the leaf hash at `index`.
    pub fn leaf_hash(&self, index: usize) -> Option<[u8; 32]> {
        self.leaf_hashes.get(index).copied()
    }

    /// Generates an O(log N) inclusion proof for leaf at `leaf_index`.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<InclusionProof, RegistryError> {
        let n = self.leaf_hashes.len();
        if leaf_index >= n {
            return Err(RegistryError::NotFound {
                id: format!("leaf index {leaf_index} out of bounds (size {n})"),
            });
        }

        let mut audit_path = Vec::new();
        generate_audit_path(&self.leaf_hashes, leaf_index, &mut audit_path);

        Ok(InclusionProof {
            leaf_index: leaf_index as u64,
            tree_size: n as u64,
            leaf_hash: self.leaf_hashes[leaf_index],
            audit_path,
        })
    }

    /// Generates an O(log N) append-only consistency proof between `old_size` and current size.
    pub fn consistency_proof(&self, old_size: usize) -> Result<ConsistencyProof, RegistryError> {
        let new_size = self.leaf_hashes.len();
        if old_size == 0 || old_size > new_size {
            return Err(RegistryError::InvalidRange);
        }

        let mut proof_path = Vec::new();
        if old_size < new_size {
            generate_subproof(old_size, &self.leaf_hashes, true, &mut proof_path);
        }

        Ok(ConsistencyProof {
            old_size: old_size as u64,
            new_size: new_size as u64,
            proof_path,
        })
    }
}

// ---------------------------------------------------------------------------
// Path Generators (RFC 9162 §2.1.3 & §2.1.4)
// ---------------------------------------------------------------------------

fn generate_audit_path(leaves: &[[u8; 32]], m: usize, path: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_k(n);
    if m < k {
        generate_audit_path(&leaves[..k], m, path);
        path.push(compute_mth(&leaves[k..]));
    } else {
        generate_audit_path(&leaves[k..], m - k, path);
        path.push(compute_mth(&leaves[..k]));
    }
}

fn generate_subproof(m: usize, leaves: &[[u8; 32]], b: bool, proof: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if m == n {
        if !b {
            proof.push(compute_mth(leaves));
        }
        return;
    }

    let k = split_k(n);
    if m <= k {
        generate_subproof(m, &leaves[..k], b, proof);
        proof.push(compute_mth(&leaves[k..]));
    } else {
        generate_subproof(m - k, &leaves[k..], false, proof);
        proof.push(compute_mth(&leaves[..k]));
    }
}

// ---------------------------------------------------------------------------
// Standalone Proof Verifiers
// ---------------------------------------------------------------------------

/// Verifies an RFC 9162 Merkle inclusion proof.
pub fn verify_inclusion(proof: &InclusionProof, expected_root: &[u8; 32]) -> bool {
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return false;
    }
    if proof.tree_size == 1 {
        return proof.audit_path.is_empty() && proof.leaf_hash == *expected_root;
    }

    let mut fn_idx = proof.leaf_index;
    let mut sn = proof.tree_size - 1;
    let mut current_hash = proof.leaf_hash;

    for sibling in &proof.audit_path {
        if sn == 0 {
            return false;
        }
        if fn_idx % 2 == 1 || fn_idx == sn {
            // current node is on the right
            current_hash = hash_log_internal(sibling, &current_hash);
            while fn_idx.is_multiple_of(2) && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            // current node is on the left
            current_hash = hash_log_internal(&current_hash, sibling);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    sn == 0 && current_hash == *expected_root
}

/// Verifies an RFC 9162 Merkle append-only consistency proof.
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> bool {
    let m = proof.old_size;
    let n = proof.new_size;

    if m == 0 || m > n {
        return false;
    }
    if m == n {
        return proof.proof_path.is_empty() && old_root == new_root;
    }

    // A complete tree must have at least 1 path element
    if proof.proof_path.is_empty() {
        return false;
    }

    let mut path = proof.proof_path.as_slice();

    // If m is a power of 2, fr and sr are initialized to old_root.
    // Otherwise, proof[0] is the intermediate root and is consumed from path.
    let (mut fr, mut sr) = if m.is_power_of_two() {
        (*old_root, *old_root)
    } else {
        let first = path[0];
        path = &path[1..];
        (first, first)
    };

    let mut fn_idx = m - 1;
    let mut sn = n - 1;

    while fn_idx % 2 == 1 {
        fn_idx >>= 1;
        sn >>= 1;
    }

    for sibling in path {
        if sn == 0 {
            return false;
        }
        if fn_idx % 2 == 1 || fn_idx == sn {
            fr = hash_log_internal(sibling, &fr);
            sr = hash_log_internal(sibling, &sr);
            while fn_idx.is_multiple_of(2) && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            sr = hash_log_internal(&sr, sibling);
        }
        fn_idx >>= 1;
        sn >>= 1;
    }

    sn == 0 && fr == *old_root && sr == *new_root
}

// ---------------------------------------------------------------------------
// Tests & RFC Reference Vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_and_single_leaf_root() {
        let mut log = MerkleLogTree::new();
        assert_eq!(log.root(), *blake3::hash(b"").as_bytes());

        let h0 = log.append(b"leaf-0");
        assert_eq!(log.root(), h0);
        assert_eq!(log.len(), 1);

        let proof = log.inclusion_proof(0).unwrap();
        assert!(verify_inclusion(&proof, &h0));
    }

    #[test]
    fn test_split_k_powers_of_two() {
        assert_eq!(split_k(2), 1);
        assert_eq!(split_k(3), 2);
        assert_eq!(split_k(4), 2);
        assert_eq!(split_k(5), 4);
        assert_eq!(split_k(8), 4);
        assert_eq!(split_k(9), 8);
        assert_eq!(split_k(16), 8);
        assert_eq!(split_k(17), 16);
    }

    #[test]
    fn test_inclusion_proof_all_leaves_up_to_32() {
        let mut log = MerkleLogTree::new();
        for i in 0..32 {
            log.append(format!("event-{i}").as_bytes());
            let current_root = log.root();
            let n = log.len();

            // Verify inclusion proof for every leaf added so far
            for leaf_idx in 0..n {
                let proof = log.inclusion_proof(leaf_idx).unwrap();
                assert!(
                    verify_inclusion(&proof, &current_root),
                    "failed inclusion for leaf {leaf_idx} in tree of size {n}"
                );
            }
        }
    }

    #[test]
    fn test_consistency_proof_all_pairs_up_to_16() {
        let mut log = MerkleLogTree::new();
        let mut roots = Vec::new();

        for i in 0..16 {
            log.append(format!("canonical-event-{i}").as_bytes());
            roots.push(log.root());
        }

        // Test every pair (m, n) with 1 <= m <= n <= 16
        for m in 1..=16 {
            for n in m..=16 {
                let old_root = roots[m - 1];
                let new_root = roots[n - 1];

                // Build sub-tree up to n
                let sub_log = MerkleLogTree {
                    leaf_hashes: log.leaf_hashes[..n].to_vec(),
                };
                let proof = sub_log.consistency_proof(m).unwrap();

                assert!(
                    verify_consistency(&proof, &old_root, &new_root),
                    "failed consistency proof from {m} to {n}"
                );
            }
        }
    }

    #[test]
    fn test_consistency_proof_tampered_fails() {
        let mut log = MerkleLogTree::new();
        for i in 0..8 {
            log.append(format!("event-{i}").as_bytes());
        }
        let old_root = MerkleLogTree {
            leaf_hashes: log.leaf_hashes[..4].to_vec(),
        }
        .root();
        let new_root = log.root();

        let mut proof = log.consistency_proof(4).unwrap();
        assert!(verify_consistency(&proof, &old_root, &new_root));

        // Tamper with old root
        let bad_root = [0xFF; 32];
        assert!(!verify_consistency(&proof, &bad_root, &new_root));

        // Tamper with proof path
        proof.proof_path[0] = [0xEE; 32];
        assert!(!verify_consistency(&proof, &old_root, &new_root));
    }

    #[test]
    fn test_inclusion_proof_tampered_fails() {
        let mut log = MerkleLogTree::new();
        for i in 0..7 {
            log.append(format!("event-{i}").as_bytes());
        }
        let root = log.root();
        let mut proof = log.inclusion_proof(3).unwrap();
        assert!(verify_inclusion(&proof, &root));

        // Tamper with leaf hash
        proof.leaf_hash = [0x55; 32];
        assert!(!verify_inclusion(&proof, &root));
    }
}
