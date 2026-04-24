use crate::error::RegistryError;
use crate::poi::PoI;
use crate::credit::{CreditBatch, CreditStatus, SerialSlice};
use crate::poo::{PoO, PoOStatus, ClaimType};
use crate::serial::SerialRange;

#[derive(Default)]
pub struct Registry {
    pub credits: Vec<CreditBatch>,
    pub burned_ranges: Vec<SerialRange>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_poi(&self, poi: &PoI) -> Result<(), RegistryError> {
        if poi.is_used() {
            return Err(RegistryError::PoIAlreadyUsed);
        }

        if !poi.is_valid_for_minting() {
            return Err(RegistryError::MissingPoI);
        }

        Ok(())
    }

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
                if slice.status == CreditStatus::Active && slice.range.overlaps(&poi.serialization_range) {
                    return Err(RegistryError::RangeOverlap);
                }
            }
        }

        // Enforce Invariant 2: The range must not exceed the PoI auth cap
        if poi.serialization_range.size() > poi.cc_mint_amount {
            return Err(RegistryError::SupplyExceeded);
        }

        let batch = CreditBatch {
            project_id: poi.project_id.clone(),
            credit_id: poi.credit_id.clone(),
            original_range: poi.serialization_range,
            slices: vec![SerialSlice { range: poi.serialization_range, status: CreditStatus::Active }],
            owner,
        };

        poi.status = crate::poi::PoIStatus::Used;
        self.credits.push(batch.clone());
        Ok(batch)
    }

    // Transfer ownership of a credit seamlessly tracking lifecycle state
    pub fn transfer(&mut self, credit_id: &str, new_owner: String) -> Result<(), RegistryError> {
        let credit = self.credits.iter_mut()
            .find(|c| c.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound { id: credit_id.to_string() })?;

        if !credit.is_active() {
            return Err(RegistryError::InvalidStateTransition { 
                from: "Retired/Expired".to_string(), 
                to: "Active".to_string() 
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

        let batch = self.credits.iter_mut()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound { id: credit_id.to_string() })?;

        // Invariant 5: Prevent double burning through historic overlap tracking
        for burned in &self.burned_ranges {
            if burned.overlaps(&burn_range) {
                return Err(RegistryError::PoOAlreadyIssued);
            }
        }

        // Find the active slice that strictly contains the burn envelope
        let slice_idx = batch.slices.iter()
            .position(|s| s.status == CreditStatus::Active && s.range.contains(&burn_range))
            .ok_or_else(|| RegistryError::BurnRangeNotFound { start: burn_range.start, end: burn_range.end })?;

        // Excise target slice
        let target_slice = batch.slices.remove(slice_idx);

        // Run algorithmic slice split tracking active remainders
        let remainders = target_slice.range.slice(&burn_range)?;

        // Persist remainders to the batch's active state
        for r in remainders {
            batch.slices.push(SerialSlice { range: r, status: CreditStatus::Active });
        }
        
        // Push the executed burn footprint onto the batch tracking object
        batch.slices.push(SerialSlice { range: burn_range, status: CreditStatus::Retired });

        // Lock globally 
        self.burned_ranges.push(burn_range);

        // Generate Settlement Artifact (PoO)
        let poo = PoO {
            project_id: batch.project_id.clone(),
            credit_id: credit_id.to_string(),
            serialization_range: burn_range,
            market_scope: crate::project::MarketScope::Vcm,
            cc_amount: burn_range.size(),
            burn_tx_hash: format!("mock_burn_{}_{}", credit_id, burn_range.start),
            timestamp: 0,
            beneficiary,
            owner: batch.owner.clone(),
            claim_type,
            amount_tco2e: burn_range.size(),
            status: PoOStatus::Finalized,
        };

        Ok(poo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poi::PoIStatus;
    use crate::mrv::MRVCommitment;
    use crate::project::MarketScope;

    fn make_poi(credit_id: &str, start: u64, end: u64) -> PoI {
        PoI {
            project_id: "PRJ-001".to_string(),
            mrv_commitment: MRVCommitment {
                merkle_root: [0; 32],
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
        registry.burn("CC-1", SerialRange::new(0, 99).unwrap(), "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();

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
        let poo = registry.burn("CC-1", SerialRange::new(0, 99).unwrap(), "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();
        assert!(poo.is_finalized());
        assert_eq!(poo.beneficiary, "Corp_X");
        assert_eq!(registry.burned_ranges.len(), 1);
    }

    #[test]
    fn cannot_burn_twice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry.burn("CC-1", SerialRange::new(0, 99).unwrap(), "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();
        let result = registry.burn("CC-1", SerialRange::new(0, 99).unwrap(), "Corp_Y".to_string(), ClaimType::CorporateNetZero);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_burn_middle_slice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 999);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        
        let burn_range = SerialRange::new(200, 399).unwrap();
        let poo = registry.burn("CC-1", burn_range, "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();
        
        assert_eq!(poo.cc_amount, 200);
        assert_eq!(registry.burned_ranges.len(), 1);
        assert_eq!(registry.burned_ranges[0], burn_range);

        let batch = registry.credits.first().unwrap();
        assert_eq!(batch.slices.len(), 3);
        
        let active_slices: Vec<_> = batch.slices.iter().filter(|s| s.status == CreditStatus::Active).collect();
        assert_eq!(active_slices.len(), 2);
        assert!(active_slices.iter().any(|s| s.range == SerialRange::new(0, 199).unwrap()));
        assert!(active_slices.iter().any(|s| s.range == SerialRange::new(400, 999).unwrap()));

        let retired_slices: Vec<_> = batch.slices.iter().filter(|s| s.status == CreditStatus::Retired).collect();
        assert_eq!(retired_slices.len(), 1);
        assert_eq!(retired_slices[0].range, burn_range);
    }
}
