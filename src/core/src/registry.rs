use crate::credit::{CreditBatch, CreditStatus, SerialSlice};
use crate::error::RegistryError;
use crate::poi::PoI;
use crate::poo::{ClaimType, PoO, PoOStatus};
use crate::serial::SerialRange;
use std::collections::HashSet;

// The Registry serves as the central state machine and source of truth for the entire GreyMisnomer protocol.
// It manages the global lifecycle of all Carbon Credits, ensuring compliance with RFC-001, RFC-002, and RFC-003.
#[derive(Default)]
pub struct Registry {
    // Active and retired credit batches representing all issued supply
    pub credits: Vec<CreditBatch>,
    // Globally immutable append-only record of all retired/burned ranges (Invariant 4 & 5)
    pub burned_ranges: Vec<SerialRange>,
    // Set of all MRV data roots (merkle roots) that have been minted, preventing double-counting (Bug 9)
    pub used_data_roots: HashSet<[u8; 32]>,
}

impl Registry {
    // Instantiates an empty protocol Registry state
    pub fn new() -> Self {
        Self::default()
    }

    // Validates a Proof-of-Integrity (PoI) before minting. Ensures the PoI hasn't been used and is semantically valid.
    pub fn validate_poi(&self, poi: &PoI) -> Result<(), RegistryError> {
        if poi.is_used() {
            return Err(RegistryError::PoIAlreadyUsed);
        }

        if !poi.is_valid_for_minting() {
            return Err(RegistryError::MissingPoI);
        }

        Ok(())
    }

    // Mint logic mapping: ingests a PoI and issues a new CreditBatch to the owner if invariants hold.
    pub fn mint(&mut self, poi: &mut PoI, owner: String) -> Result<CreditBatch, RegistryError> {
        self.validate_poi(poi)?;

        // Prevent historic replay! (Invariant 4 logic mapping)
        for burned in &self.burned_ranges {
            if burned.overlaps(&poi.serialization_range) {
                return Err(RegistryError::BurnIrreversible);
            }
        }

        // Enforce Invariant 3: Global Serialization lock against overlaps
        for existing in &self.credits {
            for slice in &existing.slices {
                if slice.status == CreditStatus::Active
                    && slice.range.overlaps(&poi.serialization_range)
                {
                    return Err(RegistryError::RangeOverlap);
                }
            }
        }

        // Enforce Invariant 2: The range must not exceed the PoI auth cap
        if poi.serialization_range.size()? > poi.cc_mint_amount {
            return Err(RegistryError::SupplyExceeded);
        }

        // Prevent duplicate credit_id (Bug 3)
        if self.credits.iter().any(|c| c.credit_id == poi.credit_id) {
            return Err(RegistryError::DuplicateCreditId);
        }

        // Prevent duplicate data_root (Bug 9: double-counting prevention)
        if self
            .used_data_roots
            .contains(&poi.mrv_commitment.merkle_root)
        {
            return Err(RegistryError::DuplicateDataRoot);
        }

        let batch = CreditBatch {
            project_id: poi.project_id.clone(),
            credit_id: poi.credit_id.clone(),
            original_range: poi.serialization_range,
            slices: vec![SerialSlice {
                range: poi.serialization_range,
                status: CreditStatus::Active,
            }],
            owner,
        };

        self.used_data_roots.insert(poi.mrv_commitment.merkle_root);
        poi.status = crate::poi::PoIStatus::Used;
        self.credits.push(batch.clone());
        Ok(batch)
    }

    // Transfer ownership of a credit seamlessly tracking lifecycle state
    pub fn transfer(&mut self, credit_id: &str, new_owner: String) -> Result<(), RegistryError> {
        let credit = self
            .credits
            .iter_mut()
            .find(|c| c.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound {
                id: credit_id.to_string(),
            })?;

        if !credit.is_active() {
            return Err(RegistryError::InvalidStateTransition {
                from: "Retired/Expired".to_string(),
                to: "Active".to_string(),
            });
        }

        credit.owner = new_owner;
        Ok(())
    }

    // Partial Burn logic mapping
    pub fn burn(
        &mut self,
        credit_id: &str,
        burn_range: SerialRange,
        beneficiary: String,
        claim_type: ClaimType,
    ) -> Result<PoO, RegistryError> {
        let batch = self
            .credits
            .iter_mut()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound {
                id: credit_id.to_string(),
            })?;

        // Invariant 5: Prevent double burning through historic overlap tracking
        for burned in &self.burned_ranges {
            if burned.overlaps(&burn_range) {
                return Err(RegistryError::PoOAlreadyIssued);
            }
        }

        // Find the active slice that strictly contains the burn envelope
        let slice_idx = batch
            .slices
            .iter()
            .position(|s| s.status == CreditStatus::Active && s.range.contains(&burn_range))
            .ok_or(RegistryError::BurnRangeNotFound {
                start: burn_range.start,
                end: burn_range.end,
            })?;

        // Excise target slice
        let target_slice = batch.slices.remove(slice_idx);

        // Run algorithmic slice split tracking active remainders
        let remainders = target_slice.range.slice(&burn_range)?;

        // Persist remainders to the batch's active state
        for r in remainders {
            batch.slices.push(SerialSlice {
                range: r,
                status: CreditStatus::Active,
            });
        }

        // Push the executed burn footprint onto the batch tracking object
        batch.slices.push(SerialSlice {
            range: burn_range,
            status: CreditStatus::Retired,
        });

        // Normalize slices to merge adjacent fragments and prevent infinite fragmentation
        crate::credit::normalize_slices(&mut batch.slices);

        // Fail-fast internal validation guard to prevent silent state corruption (Bug 15)
        if !batch.validate_internal() {
            return Err(RegistryError::CorruptedState);
        }

        // Lock globally
        self.burned_ranges.push(burn_range);

        let burn_size = burn_range.size()?;

        // Generate Settlement Artifact (PoO)
        let poo = PoO {
            project_id: batch.project_id.clone(),
            credit_id: credit_id.to_string(),
            serialization_range: burn_range,
            market_scope: crate::project::MarketScope::Vcm,
            cc_amount: burn_size,
            burn_tx_hash: format!("mock_burn_{}_{}", credit_id, burn_range.start),
            timestamp: 0,
            beneficiary,
            owner: batch.owner.clone(),
            claim_type,
            amount_tco2e: burn_size,
            status: PoOStatus::Finalized,
        };

        Ok(poo)
    }

    // ── Invariant Verification Engine (RFC-001 §5) ──────────────────────────────

    /// Invariant 1: PoI is Mandatory for Minting.
    /// Verifies that the registry enforces PoI validation and that every minted batch
    /// has non-empty identity and valid metadata.
    pub fn check_invariant_1(&self) -> bool {
        let dummy_range = match SerialRange::new(0, 0) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let invalid_poi = crate::poi::PoI {
            project_id: "DUMMY".to_string(),
            mrv_commitment: crate::mrv::MRVCommitment {
                merkle_root: [0u8; 32],
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 0,
                timestamp: 0,
            },
            methodology_hash: "0x0".to_string(),
            vvb_signature: "0x0".to_string(),
            serialization_range: dummy_range,
            amount_tco2e: 1,
            jurisdiction: "IN".to_string(),
            market_scope: crate::project::MarketScope::Vcm,
            credit_id: "DUMMY".to_string(),
            valid_from: 0,
            valid_until: 100,
            poi_valid: false,
            cc_mint_amount: 1,
            owner: "dummy".to_string(),
            status: crate::poi::PoIStatus::Valid,
        };
        if self.validate_poi(&invalid_poi).is_ok() {
            return false;
        }

        for batch in &self.credits {
            if batch.credit_id.is_empty() || batch.project_id.is_empty() || batch.owner.is_empty() {
                return false;
            }
        }
        true
    }

    /// Invariant 2: Supply Authorized Cap Limit & Conservation.
    /// Verifies that for every batch: slices are internally valid, and
    /// active + retired == original_range.size().
    pub fn check_invariant_2(&self) -> bool {
        for batch in &self.credits {
            if !batch.validate_internal() {
                return false;
            }
            let original_size = match batch.original_range.size() {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut active_sum: u64 = 0;
            let mut retired_sum: u64 = 0;
            for slice in &batch.slices {
                let sz = match slice.range.size() {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                match slice.status {
                    CreditStatus::Active => {
                        active_sum = match active_sum.checked_add(sz) {
                            Some(v) => v,
                            None => return false,
                        };
                    }
                    CreditStatus::Retired => {
                        retired_sum = match retired_sum.checked_add(sz) {
                            Some(v) => v,
                            None => return false,
                        };
                    }
                    CreditStatus::Expired => {}
                }
            }
            let total = match active_sum.checked_add(retired_sum) {
                Some(v) => v,
                None => return false,
            };
            if total != original_size {
                return false;
            }
        }
        true
    }

    /// Invariant 3: Global Serialization Locking Uniqueness.
    /// Verifies that no two active serial ranges overlap anywhere in the registry.
    pub fn check_invariant_3(&self) -> bool {
        let mut active_ranges: Vec<SerialRange> = Vec::new();
        for batch in &self.credits {
            for slice in &batch.slices {
                if slice.status == CreditStatus::Active {
                    active_ranges.push(slice.range);
                }
            }
        }
        for (i, r1) in active_ranges.iter().enumerate() {
            for r2 in active_ranges.iter().skip(i + 1) {
                if r1.overlaps(r2) {
                    return false;
                }
            }
        }
        true
    }

    /// Invariant 4: Burn Irreversibility.
    /// Verifies that no range recorded in burned_ranges overlaps with any Active slice.
    pub fn check_invariant_4(&self) -> bool {
        for burned in &self.burned_ranges {
            for batch in &self.credits {
                for slice in &batch.slices {
                    if slice.status == CreditStatus::Active && slice.range.overlaps(burned) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Invariant 5: PoO Uniqueness (Double-spending prevented).
    /// Verifies that all burned ranges on record are pairwise disjoint.
    pub fn check_invariant_5(&self) -> bool {
        for (i, b1) in self.burned_ranges.iter().enumerate() {
            for b2 in self.burned_ranges.iter().skip(i + 1) {
                if b1.overlaps(b2) {
                    return false;
                }
            }
        }
        true
    }

    /// Invariant 6: PoO Non-Transferability.
    /// Verifies that fully retired batches cannot be marked active or transferred.
    pub fn check_invariant_6(&self) -> bool {
        for batch in &self.credits {
            let active_count = batch
                .slices
                .iter()
                .filter(|s| s.status == CreditStatus::Active)
                .count();
            if active_count == 0 && batch.is_active() {
                return false;
            }
        }
        true
    }

    /// Invariant 7: PoI Single-use Consumed State.
    /// Verifies that every minted batch has a registered unique data root,
    /// and that spent PoIs are strictly rejected.
    pub fn check_invariant_7(&self) -> bool {
        if self.credits.len() != self.used_data_roots.len() {
            return false;
        }
        let dummy_range = match SerialRange::new(0, 0) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let spent_poi = crate::poi::PoI {
            project_id: "DUMMY".to_string(),
            mrv_commitment: crate::mrv::MRVCommitment {
                merkle_root: [0u8; 32],
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 0,
                timestamp: 0,
            },
            methodology_hash: "0x0".to_string(),
            vvb_signature: "0x0".to_string(),
            serialization_range: dummy_range,
            amount_tco2e: 1,
            jurisdiction: "IN".to_string(),
            market_scope: crate::project::MarketScope::Vcm,
            credit_id: "DUMMY".to_string(),
            valid_from: 0,
            valid_until: 100,
            poi_valid: true,
            cc_mint_amount: 1,
            owner: "dummy".to_string(),
            status: crate::poi::PoIStatus::Used,
        };
        if self.validate_poi(&spent_poi).is_ok() {
            return false;
        }
        true
    }

    /// Evaluates all 7 RFC-001 protocol invariants against current registry state.
    pub fn check_invariants(&self) -> InvariantReport {
        let inv1 = self.check_invariant_1();
        let inv2 = self.check_invariant_2();
        let inv3 = self.check_invariant_3();
        let inv4 = self.check_invariant_4();
        let inv5 = self.check_invariant_5();
        let inv6 = self.check_invariant_6();
        let inv7 = self.check_invariant_7();
        let all_passed = inv1 && inv2 && inv3 && inv4 && inv5 && inv6 && inv7;
        InvariantReport {
            inv1_poi_mandatory: inv1,
            inv2_supply_cap: inv2,
            inv3_serial_uniqueness: inv3,
            inv4_burn_irreversibility: inv4,
            inv5_poo_uniqueness: inv5,
            inv6_poo_non_transferable: inv6,
            inv7_poi_single_use: inv7,
            all_passed,
        }
    }
}

/// Comprehensive report of all 7 protocol invariants from RFC-001 §5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvariantReport {
    pub inv1_poi_mandatory: bool,
    pub inv2_supply_cap: bool,
    pub inv3_serial_uniqueness: bool,
    pub inv4_burn_irreversibility: bool,
    pub inv5_poo_uniqueness: bool,
    pub inv6_poo_non_transferable: bool,
    pub inv7_poi_single_use: bool,
    pub all_passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mrv::MRVCommitment;
    use crate::poi::PoIStatus;
    use crate::project::MarketScope;

    fn make_poi(credit_id: &str, start: u64, end: u64) -> PoI {
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
                timestamp: 0,
            },
            methodology_hash: "0xhash".to_string(),
            vvb_signature: "0xsig".to_string(),
            serialization_range: SerialRange::new(start, end).unwrap(),
            amount_tco2e: end - start + 1,
            jurisdiction: "IN".to_string(),
            market_scope: MarketScope::Vcm,
            credit_id: credit_id.to_string(),
            valid_from: 0,
            valid_until: 9_999_999_999,
            poi_valid: true,
            cc_mint_amount: end - start + 1,
            owner: "0xOwner".to_string(),
            status: PoIStatus::Valid,
        }
    }

    #[test]
    fn cannot_mint_without_valid_poi() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        poi.poi_valid = false;
        let result = registry.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::MissingPoI);
    }

    #[test]
    fn cannot_reuse_spent_poi() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::PoIAlreadyUsed);
    }

    #[test]
    fn cannot_mint_overlapping_range() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-2", 40, 100);
        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::RangeOverlap);
    }

    #[test]
    fn cannot_mint_beyond_authorized_supply() {
        let mut r = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        poi.cc_mint_amount = 5;
        let result = r.mint(&mut poi, "Alice".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::SupplyExceeded);
    }

    #[test]
    fn cannot_remint_burned_range() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        let mut new_poi = make_poi("CC-2", 0, 99);
        let result = registry.mint(&mut new_poi, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::BurnIrreversible);
    }

    #[test]
    fn test_valid_transfer() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry.transfer("CC-1", "Bob".to_string()).unwrap();
        assert_eq!(registry.credits[0].owner, "Bob");
    }

    #[test]
    fn burn_marks_credit_retired_and_issues_poo() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        let poo = registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        assert!(poo.is_finalized());
        assert_eq!(poo.beneficiary, "Corp_X");
        assert_eq!(registry.burned_ranges.len(), 1);
    }

    #[test]
    fn cannot_burn_twice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(0, 99).unwrap(),
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        let result = registry.burn(
            "CC-1",
            SerialRange::new(0, 99).unwrap(),
            "Corp_Y".to_string(),
            ClaimType::CorporateNetZero,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_burn_middle_slice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 999);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();

        let burn_range = SerialRange::new(200, 399).unwrap();
        let poo = registry
            .burn(
                "CC-1",
                burn_range,
                "Corp_X".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        assert_eq!(poo.cc_amount, 200);
        assert_eq!(registry.burned_ranges.len(), 1);
        assert_eq!(registry.burned_ranges[0], burn_range);

        let batch = registry.credits.first().unwrap();
        // Since it's normalized, left is active, middle is retired, right is active. Total 3 slices.
        assert_eq!(batch.slices.len(), 3);

        let active_slices: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Active)
            .collect();
        assert_eq!(active_slices.len(), 2);
        assert!(active_slices
            .iter()
            .any(|s| s.range == SerialRange::new(0, 199).unwrap()));
        assert!(active_slices
            .iter()
            .any(|s| s.range == SerialRange::new(400, 999).unwrap()));

        let retired_slices: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Retired)
            .collect();
        assert_eq!(retired_slices.len(), 1);
        assert_eq!(retired_slices[0].range, burn_range);
    }

    #[test]
    fn normalization_merges_adjacent_slices() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 999);

        registry.mint(&mut poi, "Alice".to_string()).unwrap();

        // Burn two adjacent ranges
        registry
            .burn(
                "CC-1",
                SerialRange::new(200, 299).unwrap(),
                "A".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        registry
            .burn(
                "CC-1",
                SerialRange::new(300, 399).unwrap(),
                "B".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();

        let batch = registry.credits.first().unwrap();

        let retired: Vec<_> = batch
            .slices
            .iter()
            .filter(|s| s.status == CreditStatus::Retired)
            .collect();

        // After normalization -> should merge into ONE slice
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].range, SerialRange::new(200, 399).unwrap());
    }

    #[test]
    fn cannot_mint_duplicate_credit_id() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-1", 50, 99); // Non-overlapping serials, but duplicate credit_id!

        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateCreditId);
    }

    #[test]
    fn cannot_mint_duplicate_data_root() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-1", 0, 49);
        let mut poi_b = make_poi("CC-2", 50, 99); // different credit_id, non-overlapping serials!
        poi_b.mrv_commitment.merkle_root = poi_a.mrv_commitment.merkle_root; // but same MRV data root!

        registry.mint(&mut poi_a, "Alice".to_string()).unwrap();
        let result = registry.mint(&mut poi_b, "Bob".to_string());
        assert_eq!(result.unwrap_err(), RegistryError::DuplicateDataRoot);
    }

    #[test]
    fn test_invariants_pass_normal_lifecycle() {
        let mut registry = Registry::new();
        // Empty registry passes invariants
        let initial_rep = registry.check_invariants();
        assert!(initial_rep.all_passed);

        // Mint a batch
        let mut poi = make_poi("CC-INVARIANT-1", 100, 199);
        registry.mint(&mut poi, "OwnerA".to_string()).unwrap();
        let mint_rep = registry.check_invariants();
        assert!(mint_rep.all_passed);
        assert!(mint_rep.inv1_poi_mandatory);
        assert!(mint_rep.inv2_supply_cap);
        assert!(mint_rep.inv3_serial_uniqueness);
        assert!(mint_rep.inv4_burn_irreversibility);
        assert!(mint_rep.inv5_poo_uniqueness);
        assert!(mint_rep.inv6_poo_non_transferable);
        assert!(mint_rep.inv7_poi_single_use);

        // Burn part of batch
        let burn_range = SerialRange::new(120, 149).unwrap();
        registry
            .burn(
                "CC-INVARIANT-1",
                burn_range,
                "CorpBeneficiary".to_string(),
                ClaimType::CorporateNetZero,
            )
            .unwrap();
        let burn_rep = registry.check_invariants();
        assert!(burn_rep.all_passed);
    }

    #[test]
    fn test_invariant_3_detects_active_overlap() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-A", 100, 199);
        registry.mint(&mut poi_a, "OwnerA".to_string()).unwrap();

        // Artificially inject an overlapping active slice to test detection
        registry.credits[0].slices.push(SerialSlice {
            range: SerialRange::new(150, 250).unwrap(),
            status: CreditStatus::Active,
        });

        assert!(!registry.check_invariant_3());
        assert!(!registry.check_invariants().all_passed);
    }

    #[test]
    fn test_invariant_4_detects_burned_in_active() {
        let mut registry = Registry::new();
        let mut poi_a = make_poi("CC-A", 100, 199);
        registry.mint(&mut poi_a, "OwnerA".to_string()).unwrap();

        // Record 150-160 as burned, while it's still in the active batch
        registry
            .burned_ranges
            .push(SerialRange::new(150, 160).unwrap());

        assert!(!registry.check_invariant_4());
        assert!(!registry.check_invariants().all_passed);
    }

    #[test]
    fn test_invariant_5_detects_burned_overlap() {
        let mut registry = Registry::new();
        registry
            .burned_ranges
            .push(SerialRange::new(100, 200).unwrap());
        registry
            .burned_ranges
            .push(SerialRange::new(150, 250).unwrap());

        assert!(!registry.check_invariant_5());
        assert!(!registry.check_invariants().all_passed);
    }
}
