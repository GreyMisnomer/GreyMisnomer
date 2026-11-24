//! RFC-007 §4.2 & §4.8: Light-Client SPV Proofs for Active Unspentness & Permanent Retirement.
//!
//! Solves Bitcoin SPV's classic blind spot:
//! In Bitcoin, a light client proving an output existed in Block 100 cannot prove
//! it was not spent in Block 101 without syncing intermediate blocks.
//!
//! In GreyMisnomer v2.0:
//! - `uco_state_root`: Merkle root of all currently active unspent UCOs sorted by `OutPoint`.
//!   Enables O(log M) inclusion proofs (proving UNSPENT) and lexicographical neighbor proofs (proving SPENT).
//! - `poo_archive_root`: Merkle root of all permanently retired Proof-of-Offset receipts.
//!   Enables O(log R) instant offline verification of corporate Net-Zero certificates.

use crate::auth::{enc_bytes32, enc_pubkey, enc_str, enc_u64, hash_poo_leaf, hash_uco_leaf};
use crate::error::RegistryError;
use crate::header::CheckpointHeaderV2;
use crate::merkle_log::{compute_mth, verify_inclusion, InclusionProof, MerkleLogTree};
use crate::uco::{OutPoint, ProofOfOffsetCommitment, UnretiredCreditOutput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Canonical Leaf Hashing Helpers
// ---------------------------------------------------------------------------

/// Computes the domain-separated leaf hash for an active UCO:
/// `BLAKE3("GM-v2-UCO:" || canonical_bytes)`
pub fn compute_uco_leaf_hash(uco: &UnretiredCreditOutput) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&uco.outpoint.to_bytes());
    enc_str(&uco.project_id, &mut buf);
    enc_str(&uco.batch_id, &mut buf);
    enc_u64(uco.vintage_year as u64, &mut buf);
    enc_u64(uco.start_micro_unit, &mut buf);
    enc_u64(uco.end_micro_unit, &mut buf);
    enc_u64(uco.micro_units, &mut buf);
    enc_pubkey(&uco.owner, &mut buf);
    enc_u64(uco.op_index, &mut buf);
    enc_bytes32(&uco.methodology_hash, &mut buf);
    enc_bytes32(&uco.mrv_data_root, &mut buf);
    enc_u64(uco.challenge_until_epoch, &mut buf);
    if let Some(escrow) = &uco.locked_escrow_program {
        enc_str(escrow, &mut buf);
    } else {
        enc_str("", &mut buf);
    }
    hash_uco_leaf(&buf)
}

/// Computes the domain-separated leaf hash for a permanent Proof-of-Offset commitment:
/// `BLAKE3("GM-v2-POO:" || canonical_bytes)`
pub fn compute_poo_leaf_hash(poo: &ProofOfOffsetCommitment) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&poo.consumed_outpoint.to_bytes());
    enc_str(&poo.project_id, &mut buf);
    enc_str(&poo.batch_id, &mut buf);
    enc_u64(poo.vintage_year as u64, &mut buf);
    enc_u64(poo.start_micro_unit, &mut buf);
    enc_u64(poo.end_micro_unit, &mut buf);
    enc_u64(poo.micro_units, &mut buf);
    enc_str(&poo.beneficiary, &mut buf);
    enc_str(&poo.claim_type.to_string(), &mut buf);
    enc_u64(poo.retirement_epoch, &mut buf);
    buf.extend_from_slice(poo.owner_sig.as_bytes());
    hash_poo_leaf(&buf)
}

// ---------------------------------------------------------------------------
// Root Calculators Over State Sets
// ---------------------------------------------------------------------------

/// Computes the `uco_state_root` over an active UCO map by sorting deterministically by OutPoint.
pub fn compute_uco_state_root(ucos: &BTreeMap<OutPoint, UnretiredCreditOutput>) -> [u8; 32] {
    if ucos.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }
    let leaves: Vec<[u8; 32]> = ucos.values().map(compute_uco_leaf_hash).collect();
    compute_mth(&leaves)
}

/// Computes the `poo_archive_root` over cumulative retired ProofOfOffsetCommitments.
pub fn compute_poo_archive_root(poos: &[ProofOfOffsetCommitment]) -> [u8; 32] {
    if poos.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }
    let leaves: Vec<[u8; 32]> = poos.iter().map(compute_poo_leaf_hash).collect();
    compute_mth(&leaves)
}

// ---------------------------------------------------------------------------
// SPV Proof Types
// ---------------------------------------------------------------------------

/// O(log M) SPV proof verifying that a UCO is currently unspent as of a checkpoint header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcoUnspentSpvProof {
    pub uco: UnretiredCreditOutput,
    pub proof: InclusionProof,
}

impl UcoUnspentSpvProof {
    /// Verifies the proof against `uco_state_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let leaf = compute_uco_leaf_hash(&self.uco);
        if self.proof.leaf_hash != leaf {
            return false;
        }
        verify_inclusion(&self.proof, expected_root)
    }

    /// Verifies the proof against a signed `CheckpointHeaderV2`.
    pub fn verify_against_header(&self, header: &CheckpointHeaderV2) -> bool {
        self.verify(&header.uco_state_root)
    }
}

/// O(log R) SPV proof verifying that a Proof-of-Offset retirement is permanently committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PooRetirementSpvProof {
    pub poo: ProofOfOffsetCommitment,
    pub proof: InclusionProof,
}

impl PooRetirementSpvProof {
    /// Verifies the proof against `poo_archive_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let leaf = compute_poo_leaf_hash(&self.poo);
        if self.proof.leaf_hash != leaf {
            return false;
        }
        verify_inclusion(&self.proof, expected_root)
    }

    /// Verifies the proof against a signed `CheckpointHeaderV2`.
    pub fn verify_against_header(&self, header: &CheckpointHeaderV2) -> bool {
        self.verify(&header.poo_archive_root)
    }
}

// ---------------------------------------------------------------------------
// Proof Generators
// ---------------------------------------------------------------------------

/// Builds an active unspentness SPV proof for `target_outpoint`.
pub fn generate_unspent_spv_proof(
    ucos: &BTreeMap<OutPoint, UnretiredCreditOutput>,
    target_outpoint: &OutPoint,
) -> Result<UcoUnspentSpvProof, RegistryError> {
    let target_uco = ucos
        .get(target_outpoint)
        .ok_or_else(|| RegistryError::OutpointNotFound {
            outpoint: target_outpoint.to_string(),
        })?;

    let mut log_tree = MerkleLogTree::new();
    let mut target_idx = None;

    for (idx, (op, uco)) in ucos.iter().enumerate() {
        if op == target_outpoint {
            target_idx = Some(idx);
        }
        let leaf = compute_uco_leaf_hash(uco);
        log_tree.append_leaf_hash(leaf);
    }

    let leaf_index = target_idx.expect("must be found");
    let proof = log_tree.inclusion_proof(leaf_index)?;

    Ok(UcoUnspentSpvProof {
        uco: target_uco.clone(),
        proof,
    })
}

/// Builds a permanent retirement SPV proof for `target_poo_idx`.
pub fn generate_poo_spv_proof(
    poos: &[ProofOfOffsetCommitment],
    target_poo_idx: usize,
) -> Result<PooRetirementSpvProof, RegistryError> {
    let target_poo = poos
        .get(target_poo_idx)
        .ok_or_else(|| RegistryError::NotFound {
            id: format!("PoO index {target_poo_idx} out of bounds"),
        })?;

    let mut log_tree = MerkleLogTree::new();
    for poo in poos {
        let leaf = compute_poo_leaf_hash(poo);
        log_tree.append_leaf_hash(leaf);
    }

    let proof = log_tree.inclusion_proof(target_poo_idx)?;

    Ok(PooRetirementSpvProof {
        poo: target_poo.clone(),
        proof,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;
    use crate::uco::PoOClaimType;

    fn sample_uco(outpoint: OutPoint, units: u64, owner: &Keypair) -> UnretiredCreditOutput {
        UnretiredCreditOutput {
            outpoint,
            batch_id: "BATCH-001".to_string(),
            project_id: "PROJ-001".to_string(),
            vintage_year: 2026,
            start_micro_unit: 0,
            end_micro_unit: units,
            micro_units: units,
            owner: owner.pubkey(),
            op_index: 0,
            methodology_hash: [0x11; 32],
            mrv_data_root: [0x22; 32],
            mrv_blob_mirrors: vec![],
            challenge_until_epoch: 0,
            locked_escrow_program: None,
        }
    }

    #[test]
    fn test_uco_spv_unspentness_proof_verify() {
        let owner = Keypair::generate();
        let mut ucos = BTreeMap::new();

        let op1 = OutPoint::new([0x01; 32], 0);
        let op2 = OutPoint::new([0x02; 32], 0);
        let op3 = OutPoint::new([0x03; 32], 0);

        ucos.insert(op1, sample_uco(op1, 100_000, &owner));
        ucos.insert(op2, sample_uco(op2, 200_000, &owner));
        ucos.insert(op3, sample_uco(op3, 300_000, &owner));

        let root = compute_uco_state_root(&ucos);

        // Generate and verify proof for op2
        let spv_proof = generate_unspent_spv_proof(&ucos, &op2).unwrap();
        assert!(spv_proof.verify(&root));

        // Tamper with root fails
        let fake_root = [0xFF; 32];
        assert!(!spv_proof.verify(&fake_root));
    }

    #[test]
    fn test_poo_spv_retirement_proof_verify() {
        let owner = Keypair::generate();
        let op = OutPoint::new([0x01; 32], 0);

        let poo = ProofOfOffsetCommitment {
            consumed_outpoint: op,
            batch_id: "BATCH-001".to_string(),
            project_id: "PROJ-001".to_string(),
            vintage_year: 2026,
            start_micro_unit: 0,
            end_micro_unit: 50_000,
            micro_units: 50_000,
            beneficiary: "Corporate ESG Target 2026".to_string(),
            claim_type: PoOClaimType::NetZero,
            retirement_epoch: 12,
            owner_sig: owner.sign(b"test burn authorization"),
        };

        let poos = vec![poo.clone()];
        let root = compute_poo_archive_root(&poos);

        let spv_proof = generate_poo_spv_proof(&poos, 0).unwrap();
        assert!(spv_proof.verify(&root));

        // Verify against CheckpointHeaderV2
        let header = CheckpointHeaderV2 {
            version: 2,
            chain_id: [0x55; 32],
            tree_size: 100,
            timestamp_ns: 1_700_000_000,
            events_root: [0; 32],
            uco_state_root: [0; 32],
            poo_archive_root: root,
            active_validators_hash: [0; 32],
        };
        assert!(spv_proof.verify_against_header(&header));
    }
}
