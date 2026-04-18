use crate::error::RegistryError;
use crate::poi::PoI;
use crate::credit::{CreditBatch, CreditStatus};
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

        // Enforce Invariant 3: Global Serialization lock against overlaps (double-counting prevention)
        for existing in &self.credits {
            if existing.serial_range.overlaps(&poi.serialization_range) {
                return Err(RegistryError::RangeOverlap);
            }
        }

        // Enforce Invariant 2: The range must not exceed the PoI auth cap
        if poi.serialization_range.size() > poi.cc_mint_amount {
            return Err(RegistryError::SupplyExceeded);
        }

        let batch = CreditBatch {
            project_id: poi.project_id.clone(),
            credit_id: poi.credit_id.clone(),
            serial_range: poi.serialization_range,
            owner,
            status: CreditStatus::Active,
        };

        // Enforce Invariant 7: Lock the PoI instantly
        poi.status = crate::poi::PoIStatus::Used;
        self.credits.push(batch.clone());
        Ok(batch)
    }

    // Transfer ownership of a credit seamlessly tracking lifecycle state
    pub fn transfer(&mut self, credit_id: &str, new_owner: String) -> Result<(), RegistryError> {
        let credit = self.credits.iter_mut()
            .find(|c| c.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound { id: credit_id.to_string() })?;

        if credit.status != CreditStatus::Active {
            return Err(RegistryError::InvalidStateTransition { 
                from: "Retired/Expired".to_string(), 
                to: "Active".to_string() 
            });
        }

        credit.owner = new_owner;
        Ok(())
    }

    // Burn logic implementing Invariants 4, 5, 6 securely mapping back to source Project
    pub fn burn(
        &mut self,
        credit_id: &str,
        beneficiary: String,
        claim_type: ClaimType,
    ) -> Result<PoO, RegistryError> {

        let batch = self.credits.iter_mut()
            .find(|b| b.credit_id == credit_id)
            .ok_or_else(|| RegistryError::NotFound { id: credit_id.to_string() })?;

        if batch.status != CreditStatus::Active {
            return Err(RegistryError::BurnIrreversible);
        }

        let range = batch.serial_range;

        for burned in &self.burned_ranges {
            if burned.overlaps(&range) {
                return Err(RegistryError::PoOAlreadyIssued);
            }
        }

        batch.status = CreditStatus::Retired;
        self.burned_ranges.push(range);

        let poo = PoO {
            project_id: batch.project_id.clone(),
            credit_id: credit_id.to_string(),
            serialization_range: range,
            market_scope: crate::project::MarketScope::Vcm,
            cc_amount: range.size(),
            burn_tx_hash: format!("mock_burn_{}", credit_id),
            timestamp: 0,
            beneficiary,
            owner: batch.owner.clone(),
            claim_type,
            amount_tco2e: range.size(),
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
        registry.burn("CC-1", "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();

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
        let poo = registry.burn("CC-1", "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();
        assert!(poo.is_finalized());
        assert_eq!(poo.beneficiary, "Corp_X");
        assert_eq!(registry.burned_ranges.len(), 1);
    }

    #[test]
    fn cannot_burn_twice() {
        let mut registry = Registry::new();
        let mut poi = make_poi("CC-1", 0, 99);
        registry.mint(&mut poi, "Alice".to_string()).unwrap();
        registry.burn("CC-1", "Corp_X".to_string(), ClaimType::CorporateNetZero).unwrap();
        let result = registry.burn("CC-1", "Corp_Y".to_string(), ClaimType::CorporateNetZero);
        assert_eq!(result.unwrap_err(), RegistryError::BurnIrreversible);
    }
}
