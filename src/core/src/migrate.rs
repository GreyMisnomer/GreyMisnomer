//! RFC-007 §2.3 & Task 4.6: Deterministic `v1.3 -> v2.0` Migration Converter.
//!
//! Converts a v1.3.0 `RegistryState` into a v2.0 `UcoState`.
//!
//! IMPORTANT NOTE ON TRUST BOUNDARIES:
//! Per RFC-007 §2.3, this converter is strictly a **deterministic mathematical adapter
//! for developer sandboxes, test fixtures, and off-chain data ingestion**.
//! It MUST NOT be used to fabricate cryptographic continuity or .ots provenance
//! over compromised alpha demo seed keys in production.
//! Live v2.0 networks initialize from a clean CSPRNG Genesis Ceremony (`chain_id_v2`).

use crate::credit::CreditStatus;
use crate::error::RegistryError;
use crate::registry::RegistryState;
use crate::uco::{OutPoint, PoOClaimType, ProofOfOffsetCommitment, UnretiredCreditOutput};
use crate::uco_engine::UcoState;
use crate::MICRO_UNITS_PER_CREDIT;

/// Prefix for synthetic migration OutPoint txids.
pub const MIGRATION_TXID_TAG: &[u8] = b"GM-v2-MIGRATE-V1:";

/// Deterministically converts a v1.3 `RegistryState` to a v2.0 `UcoState`.
///
/// Conversion Rules:
/// 1. `chain_id` is re-rooted under `BLAKE3("GM-v2-chain:" || v1_chain_id)`.
/// 2. Active `SerialSlice`s become `UnretiredCreditOutput`s with half-open intervals
///    `[start_micro_unit, end_micro_unit)` where:
///    - `start_micro_unit = (v1.start - 1) * MICRO_UNITS_PER_CREDIT`
///    - `end_micro_unit = v1.end * MICRO_UNITS_PER_CREDIT`
///    - `micro_units = end_micro_unit - start_micro_unit`
/// 3. Retired `SerialSlice`s become `ProofOfOffsetCommitment`s in `poo_archive`.
/// 4. Accredited VVBs in v1 become `active_vvbs` in v2.
/// 5. `used_data_roots` are retained to preserve double-counting defenses across versions.
/// 6. Monotonic `serial_cursors` are initialized to the highest `end_micro_unit` per `(project, vintage)`.
pub fn migrate_v1_to_v2(
    v1_state: &RegistryState,
    default_vintage: u16,
) -> Result<UcoState, RegistryError> {
    // Re-root chain_id for v2 domain separation
    let mut chain_buf = Vec::new();
    chain_buf.extend_from_slice(b"GM-v2-chain:");
    chain_buf.extend_from_slice(&v1_state.chain_id);
    let v2_chain_id = *blake3::hash(&chain_buf).as_bytes();

    let mut v2_state = UcoState::new(v2_chain_id);

    // 1. Migrate accredited VVBs
    for (vvb_key, info) in &v1_state.vvbs {
        if info.active {
            v2_state.active_vvbs.insert(*vvb_key, info.label.clone());
        }
    }

    // 2. Migrate used data roots
    v2_state.used_data_roots = v1_state.used_data_roots.clone();

    // 3. Migrate active credit batches into UCOs
    for batch in &v1_state.credits {
        // Deterministic synthetic txid for batch migration
        let mut txid_buf = Vec::new();
        txid_buf.extend_from_slice(MIGRATION_TXID_TAG);
        txid_buf.extend_from_slice(batch.credit_id.as_bytes());
        let migration_txid = *blake3::hash(&txid_buf).as_bytes();

        for (vout, slice) in batch.slices.iter().enumerate() {
            if slice.range.start == 0 {
                return Err(RegistryError::InvalidRange);
            }

            // Convert 1-indexed closed [start, end] into 0-indexed half-open [start_micro, end_micro)
            let start_credit_offset = slice
                .range
                .start
                .checked_sub(1)
                .ok_or(RegistryError::Overflow)?;
            let start_micro_unit = start_credit_offset
                .checked_mul(MICRO_UNITS_PER_CREDIT)
                .ok_or(RegistryError::Overflow)?;
            let end_micro_unit = slice
                .range
                .end
                .checked_mul(MICRO_UNITS_PER_CREDIT)
                .ok_or(RegistryError::Overflow)?;

            let micro_units = end_micro_unit
                .checked_sub(start_micro_unit)
                .ok_or(RegistryError::Overflow)?;

            let outpoint = OutPoint::new(migration_txid, vout as u32);

            match slice.status {
                CreditStatus::Active => {
                    let uco = UnretiredCreditOutput {
                        outpoint,
                        batch_id: batch.credit_id.clone(),
                        project_id: batch.project_id.clone(),
                        vintage_year: default_vintage,
                        start_micro_unit,
                        end_micro_unit,
                        micro_units,
                        owner: batch.owner,
                        op_index: batch.op_index,
                        methodology_hash: [0u8; 32],
                        mrv_data_root: batch.poi_hash,
                        mrv_blob_mirrors: Vec::new(),
                        challenge_until_epoch: 0,
                        locked_escrow_program: None,
                    };
                    uco.validate()?;
                    v2_state.unspent_outputs.insert(outpoint, uco);

                    // Update serial allocation cursor
                    let key = (batch.project_id.clone(), default_vintage);
                    let current_cursor = v2_state.serial_cursors.entry(key).or_insert(0);
                    if end_micro_unit > *current_cursor {
                        *current_cursor = end_micro_unit;
                    }
                }
                CreditStatus::Retired => {
                    let poo = ProofOfOffsetCommitment {
                        consumed_outpoint: outpoint,
                        batch_id: batch.credit_id.clone(),
                        project_id: batch.project_id.clone(),
                        vintage_year: default_vintage,
                        start_micro_unit,
                        end_micro_unit,
                        micro_units,
                        beneficiary: format!("Migrated v1.3 retirement ({})", batch.credit_id),
                        claim_type: PoOClaimType::Voluntary,
                        retirement_epoch: 0,
                        owner_sig: crate::auth::Signature::default(),
                    };
                    poo.validate()?;
                    v2_state.poo_archive.push(poo);
                }
                CreditStatus::Expired => {
                    // Expired credits do not enter active UCO state
                }
            }
        }
    }

    Ok(v2_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;
    use crate::credit::CreditBatch;
    use crate::registry::VvbInfo;
    use crate::serial::SerialRange;

    #[test]
    fn test_migrate_v1_to_v2_preserves_conservation() {
        let authority = Keypair::generate();
        let sequencer = Keypair::generate();
        let vvb = Keypair::generate();
        let owner = Keypair::generate();

        let mut v1 = RegistryState::default();
        v1.chain_id = [0x11; 32];
        v1.authority = authority.pubkey();
        v1.sequencer = sequencer.pubkey();
        v1.vvbs.insert(
            vvb.pubkey(),
            VvbInfo {
                label: "TUV-Nord".to_string(),
                active: true,
            },
        );

        // Mint 1,000 credits (serials 1..=1000)
        let batch = CreditBatch::new(
            "PROJ-01".to_string(),
            "CC-01".to_string(),
            SerialRange::new(1, 1000).unwrap(),
            owner.pubkey(),
            vvb.pubkey(),
            [0x22; 32],
        );
        v1.credits.push(batch);

        let v2 = migrate_v1_to_v2(&v1, 2026).unwrap();

        assert_eq!(v2.unspent_outputs.len(), 1);
        let (_, uco) = v2.unspent_outputs.iter().next().unwrap();
        assert_eq!(uco.start_micro_unit, 0);
        assert_eq!(uco.end_micro_unit, 1_000_000_000); // 1,000 * 1,000,000
        assert_eq!(uco.micro_units, 1_000_000_000);
        assert_eq!(uco.batch_id, "CC-01");
        assert_eq!(uco.project_id, "PROJ-01");
        assert_eq!(uco.vintage_year, 2026);
        assert_eq!(uco.owner, owner.pubkey());

        // Monotonic cursor is initialized to end_micro_unit
        assert_eq!(
            v2.serial_cursors.get(&("PROJ-01".to_string(), 2026)),
            Some(&1_000_000_000)
        );
    }
}
