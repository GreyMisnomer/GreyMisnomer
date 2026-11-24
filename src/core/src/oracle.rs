//! RFC-007 §6: Hardened MRV Oracle Governance, Quorums & Buffer Pool.
//!
//! Addresses the single largest point of failure in carbon markets: fraudulent or
//! inaccurate MRV issuance at the physical-to-digital boundary.
//!
//! Primitives:
//! 1. Multi-VVB Quorum Verification ($k$-of-$n$ independent signatures).
//! 2. Scoped VVB Accreditation & Expiration Epochs.
//! 3. Mandatory Pre-Retirement Challenge Window (`challenge_until_epoch`).
//! 4. Protocol Buffer Pool Collateral Tracking & Fraud Revocation (`RevokeWithBuffer`).
//! 5. Oracle Slashed Record (`OracleSlash`).

use crate::auth::{enc_bytes32, enc_pubkey, enc_str, enc_u64, PubKey, Signature};
use crate::error::RegistryError;
use crate::uco::{OutPoint, UnretiredCreditOutput};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DOMAIN_ORACLE_SLASH: &str = "GM-v2-ORACLE-SLASH:";
pub const DOMAIN_REVOKE_BUFFER: &str = "GM-v2-REVOKE-BUFFER:";

// ---------------------------------------------------------------------------
// Scoped VVB Metadata
// ---------------------------------------------------------------------------

/// Accredited Validation & Verification Body with operational methodology scopes
/// and an explicit expiration epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedVvb {
    pub label: String,
    pub active: bool,
    /// Authorized methodology hashes or project types (e.g., "VM0007", "solar")
    pub authorized_scopes: Vec<String>,
    /// Log epoch beyond which attestations from this VVB are rejected
    pub expiration_epoch: u64,
}

impl ScopedVvb {
    pub fn is_valid_at(&self, epoch: u64, scope: &str) -> bool {
        if !self.active || epoch > self.expiration_epoch {
            return false;
        }
        if self.authorized_scopes.is_empty() {
            return true; // wildcard access if unspecified
        }
        self.authorized_scopes
            .iter()
            .any(|s| s == "*" || s == scope)
    }
}

// ---------------------------------------------------------------------------
// Methodology Quorum Configuration
// ---------------------------------------------------------------------------

/// Defines the minimum independent VVB signature quorum required to mint
/// credits under a given methodology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodologyQuorum {
    #[serde(with = "crate::auth::hex_bytes32")]
    pub methodology_hash: [u8; 32],
    /// Required valid signatures (k in k-of-n)
    pub required_signatures: usize,
    /// Minimum mandatory challenge window in log epochs before credits can be retired
    pub mandatory_challenge_epochs: u64,
    /// Percentage of minted credits automatically withheld into the buffer pool (e.g. 5 = 5%)
    pub buffer_withhold_percent: u8,
}

impl Default for MethodologyQuorum {
    fn default() -> Self {
        Self {
            methodology_hash: [0u8; 32],
            required_signatures: 1,
            mandatory_challenge_epochs: 10,
            buffer_withhold_percent: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol Buffer Pool
// ---------------------------------------------------------------------------

/// Protocol collateral reserve holding unretired credit micro-units to absorb
/// future reversals, leakage, or fraudulent issuances without breaking
/// ledger-wide conservation or retroactively invalidating honest downstream buyers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferPool {
    /// Total active micro-units deposited in reserve across all projects
    pub total_reserved_micro_units: u64,
    /// Per-project reserve balances: `project_id -> reserved_micro_units`
    pub project_reserves: BTreeMap<String, u64>,
}

impl BufferPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deposit micro-units into the project's reserve pool.
    pub fn deposit(&mut self, project_id: &str, units: u64) -> Result<(), RegistryError> {
        self.total_reserved_micro_units = self
            .total_reserved_micro_units
            .checked_add(units)
            .ok_or(RegistryError::Overflow)?;

        let proj_entry = self
            .project_reserves
            .entry(project_id.to_string())
            .or_insert(0);
        *proj_entry = proj_entry
            .checked_add(units)
            .ok_or(RegistryError::Overflow)?;

        Ok(())
    }

    /// Deduct micro-units from the project's reserve (or fallback to general reserve)
    /// to compensate for a revoked or reversed batch.
    pub fn deduct(&mut self, project_id: &str, required_units: u64) -> Result<(), RegistryError> {
        if self.total_reserved_micro_units < required_units {
            return Err(RegistryError::InsufficientBuffer {
                required: required_units,
                available: self.total_reserved_micro_units,
            });
        }

        // Deduct from project-specific reserve first
        if let Some(proj_balance) = self.project_reserves.get_mut(project_id) {
            if *proj_balance >= required_units {
                *proj_balance -= required_units;
            } else {
                let remainder = required_units - *proj_balance;
                *proj_balance = 0;
                // Remainder absorbed by general pool
                let _ = remainder;
            }
        }

        self.total_reserved_micro_units -= required_units;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Oracle Governance Transactions
// ---------------------------------------------------------------------------

/// Authority action slashing and revoking an accredited VVB for malfeasance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSlashTx {
    pub vvb: PubKey,
    pub authority_index: u64,
    pub reason: String,
    pub authority_sig: Signature,
}

impl OracleSlashTx {
    pub fn signing_preimage(&self, chain_id: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_str(DOMAIN_ORACLE_SLASH, &mut buf);
        enc_bytes32(chain_id, &mut buf);
        enc_pubkey(&self.vvb, &mut buf);
        enc_u64(self.authority_index, &mut buf);
        enc_str(&self.reason, &mut buf);
        buf
    }
}

/// Action revoking a fraudulent or reversed batch, burning active UCOs
/// and covering any spent shortfall from the protocol Buffer Pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeWithBufferTx {
    pub batch_id: String,
    pub project_id: String,
    pub authority_index: u64,
    /// Total issued units in this batch that must be neutralized
    pub batch_total_units: u64,
    pub authority_sig: Signature,
}

impl RevokeWithBufferTx {
    pub fn signing_preimage(&self, chain_id: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_str(DOMAIN_REVOKE_BUFFER, &mut buf);
        enc_bytes32(chain_id, &mut buf);
        enc_str(&self.batch_id, &mut buf);
        enc_str(&self.project_id, &mut buf);
        enc_u64(self.authority_index, &mut buf);
        enc_u64(self.batch_total_units, &mut buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// Evaluator: Quorum & Revocation Verification
// ---------------------------------------------------------------------------

/// Verifies that an attestation satisfies the methodology's k-of-n quorum rules.
pub fn verify_mrv_quorum(
    preimage: &[u8],
    vvb_sigs: &[(PubKey, Signature)],
    quorum: &MethodologyQuorum,
    vvb_registry: &BTreeMap<PubKey, ScopedVvb>,
    current_epoch: u64,
    scope: &str,
) -> Result<(), RegistryError> {
    if vvb_sigs.len() < quorum.required_signatures {
        return Err(RegistryError::OracleQuorumNotMet {
            required: quorum.required_signatures,
            found: vvb_sigs.len(),
        });
    }

    let mut valid_signers = BTreeSet::new();

    for (vvb, sig) in vvb_sigs {
        // Must be in registry and valid
        let info = vvb_registry
            .get(vvb)
            .ok_or_else(|| RegistryError::UnknownVvb { vvb: vvb.to_hex() })?;

        if !info.is_valid_at(current_epoch, scope) {
            return Err(RegistryError::VvbRevoked { vvb: vvb.to_hex() });
        }

        // Must strictly verify RFC 8032 signature
        vvb.verify_strict(preimage, sig)
            .map_err(|_| RegistryError::BadSignature)?;

        valid_signers.insert(*vvb);
    }

    // Must have at least k distinct valid signers
    if valid_signers.len() < quorum.required_signatures {
        return Err(RegistryError::OracleQuorumNotMet {
            required: quorum.required_signatures,
            found: valid_signers.len(),
        });
    }

    Ok(())
}

/// Applies a `RevokeWithBuffer` event:
/// 1. Identifies and consumes all unspent UCOs belonging to `batch_id`.
/// 2. If the unspent UCOs are less than `batch_total_units`, deducts the difference
///    from `buffer_pool`.
/// 3. Returns the list of canceled OutPoints and the compensation amount drawn from the buffer.
pub fn apply_revoke_with_buffer(
    unspent_ucos: &mut BTreeMap<OutPoint, UnretiredCreditOutput>,
    buffer_pool: &mut BufferPool,
    tx: &RevokeWithBufferTx,
    authority: &PubKey,
    chain_id: &[u8; 32],
) -> Result<(Vec<OutPoint>, u64), RegistryError> {
    // 1. Verify authority signature
    let preimage = tx.signing_preimage(chain_id);
    authority
        .verify_strict(&preimage, &tx.authority_sig)
        .map_err(|_| RegistryError::BadSignature)?;

    // 2. Locate all unspent UCOs for this batch
    let mut canceled_outpoints = Vec::new();
    let mut active_units_found = 0u64;

    for (outpoint, uco) in unspent_ucos.iter() {
        if uco.batch_id == tx.batch_id && uco.project_id == tx.project_id {
            canceled_outpoints.push(*outpoint);
            active_units_found = active_units_found
                .checked_add(uco.micro_units)
                .ok_or(RegistryError::Overflow)?;
        }
    }

    // Remove canceled UCOs from active circulation
    for op in &canceled_outpoints {
        unspent_ucos.remove(op);
    }

    // 3. If there is a shortfall (some units were already spent/retired),
    // deduct from buffer pool collateral to neutralize the net emissions deficit
    let shortfall = tx.batch_total_units.saturating_sub(active_units_found);
    if shortfall > 0 {
        buffer_pool.deduct(&tx.project_id, shortfall)?;
    }

    Ok((canceled_outpoints, shortfall))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;

    #[test]
    fn test_scoped_vvb_validity_and_expiration() {
        let vvb = ScopedVvb {
            label: "TUV-Nord".to_string(),
            active: true,
            authorized_scopes: vec!["solar".to_string(), "wind".to_string()],
            expiration_epoch: 100,
        };

        assert!(vvb.is_valid_at(50, "solar"));
        assert!(vvb.is_valid_at(100, "wind"));
        assert!(!vvb.is_valid_at(101, "solar")); // expired
        assert!(!vvb.is_valid_at(50, "forestry")); // unauthorized scope
    }

    #[test]
    fn test_k_of_n_quorum_verification() {
        let vvb1 = Keypair::generate();
        let vvb2 = Keypair::generate();
        let vvb3 = Keypair::generate();

        let mut registry = BTreeMap::new();
        registry.insert(
            vvb1.pubkey(),
            ScopedVvb {
                label: "VVB-1".to_string(),
                active: true,
                authorized_scopes: vec!["solar".to_string()],
                expiration_epoch: 500,
            },
        );
        registry.insert(
            vvb2.pubkey(),
            ScopedVvb {
                label: "VVB-2".to_string(),
                active: true,
                authorized_scopes: vec!["solar".to_string()],
                expiration_epoch: 500,
            },
        );
        registry.insert(
            vvb3.pubkey(),
            ScopedVvb {
                label: "VVB-3".to_string(),
                active: false, // inactive!
                authorized_scopes: vec!["solar".to_string()],
                expiration_epoch: 500,
            },
        );

        let quorum = MethodologyQuorum {
            methodology_hash: [0x11; 32],
            required_signatures: 2, // 2-of-3 required
            mandatory_challenge_epochs: 10,
            buffer_withhold_percent: 5,
        };

        let message = b"canonical MRV telemetry payload for batch B1";

        // 1-of-2 signatures: fails quorum
        let sig1 = vvb1.sign(message);
        let err1 = verify_mrv_quorum(
            message,
            &[(vvb1.pubkey(), sig1)],
            &quorum,
            &registry,
            100,
            "solar",
        )
        .unwrap_err();
        assert!(matches!(err1, RegistryError::OracleQuorumNotMet { .. }));

        // 2-of-2 valid signatures: passes
        let sig2 = vvb2.sign(message);
        assert!(verify_mrv_quorum(
            message,
            &[(vvb1.pubkey(), sig1), (vvb2.pubkey(), sig2)],
            &quorum,
            &registry,
            100,
            "solar",
        )
        .is_ok());

        // Attempt with inactive VVB-3: fails
        let sig3 = vvb3.sign(message);
        let err3 = verify_mrv_quorum(
            message,
            &[(vvb1.pubkey(), sig1), (vvb3.pubkey(), sig3)],
            &quorum,
            &registry,
            100,
            "solar",
        )
        .unwrap_err();
        assert!(matches!(err3, RegistryError::VvbRevoked { .. }));
    }

    #[test]
    fn test_buffer_pool_deposit_and_deduct() {
        let mut pool = BufferPool::new();
        pool.deposit("PROJ-01", 100_000).unwrap();
        pool.deposit("PROJ-02", 50_000).unwrap();

        assert_eq!(pool.total_reserved_micro_units, 150_000);
        assert_eq!(*pool.project_reserves.get("PROJ-01").unwrap(), 100_000);

        // Deduct 40_000 from PROJ-01
        pool.deduct("PROJ-01", 40_000).unwrap();
        assert_eq!(pool.total_reserved_micro_units, 110_000);
        assert_eq!(*pool.project_reserves.get("PROJ-01").unwrap(), 60_000);

        // Attempt to deduct more than total available: error
        let err = pool.deduct("PROJ-01", 200_000).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientBuffer { .. }));
    }

    #[test]
    fn test_revoke_with_buffer_compensation() {
        let authority = Keypair::generate();
        let chain_id = [0x55; 32];

        let mut unspent = BTreeMap::new();
        let owner = Keypair::generate();

        // Suppose 1,000,000 units were issued in batch B1.
        // 600,000 units are still unspent in an active UCO.
        // 400,000 units were already spent/retired.
        let op1 = OutPoint::new([0xAA; 32], 0);
        let uco = UnretiredCreditOutput {
            outpoint: op1,
            batch_id: "BATCH-FRAUD-01".to_string(),
            project_id: "PROJ-FOREST-01".to_string(),
            vintage_year: 2026,
            start_micro_unit: 0,
            end_micro_unit: 600_000,
            micro_units: 600_000,
            owner: owner.pubkey(),
            op_index: 0,
            methodology_hash: [0x11; 32],
            mrv_data_root: [0x22; 32],
            mrv_blob_mirrors: vec![],
            challenge_until_epoch: 0,
            locked_escrow_program: None,
        };
        unspent.insert(op1, uco);

        let mut pool = BufferPool::new();
        // Buffer pool has 500,000 units available
        pool.deposit("PROJ-FOREST-01", 500_000).unwrap();

        let mut tx = RevokeWithBufferTx {
            batch_id: "BATCH-FRAUD-01".to_string(),
            project_id: "PROJ-FOREST-01".to_string(),
            authority_index: 1,
            batch_total_units: 1_000_000,
            authority_sig: Signature::default(),
        };
        let preimage = tx.signing_preimage(&chain_id);
        tx.authority_sig = authority.sign(&preimage);

        let (canceled, shortfall) =
            apply_revoke_with_buffer(&mut unspent, &mut pool, &tx, &authority.pubkey(), &chain_id)
                .unwrap();

        // 1 active UCO was canceled
        assert_eq!(canceled, vec![op1]);
        assert!(!unspent.contains_key(&op1));

        // Shortfall was 1,000,000 - 600,000 = 400,000 units
        assert_eq!(shortfall, 400_000);
        // Buffer pool decreased by 400,000 units: 500,000 - 400,000 = 100,000 remaining
        assert_eq!(pool.total_reserved_micro_units, 100_000);
    }
}
