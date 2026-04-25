use serde::{Deserialize, Serialize};
use crate::serial::SerialRange;
use crate::project::MarketScope;

// Represents the final state of a Proof-of-Offset.
// Finalized means it has been successfully issued and recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoOStatus {
    Finalized,
    Rejected,
}

// Defines the specific rationale for the carbon credit retirement.
// Enables transparent tracking of why a credit was burned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimType {
    CorporateNetZero,
    Payg,
    Compliance,
}

// Proof-of-Offset (PoO) represents a formally retired carbon credit.
// As defined in RFC-001 §3.2, it contains the immutable cryptographic proof 
// that specific serial ranges have been burned and claimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoO {
    pub project_id: String,
    pub credit_id: String,
    pub serialization_range: SerialRange,
    pub market_scope: MarketScope,
    pub cc_amount: u64,
    
    pub burn_tx_hash: String,
    pub timestamp: u64,
    pub beneficiary: String,
    pub owner: String,
    pub claim_type: ClaimType,
    pub amount_tco2e: u64,
    pub status: PoOStatus,
}

impl PoO {
    pub fn is_finalized(&self) -> bool {
        self.status == PoOStatus::Finalized
    }

    /// Validates cc_amount exactly matches physical serialized size
    pub fn amounts_are_consistent(&self) -> bool {
        self.cc_amount == self.serialization_range.size()
            && self.amount_tco2e == self.cc_amount
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_poo() -> PoO {
        PoO {
            project_id: "PRJ-001".to_string(),
            credit_id: "CC-001".to_string(),
            serialization_range: SerialRange::new(0, 99).unwrap(),
            market_scope: MarketScope::Vcm,
            cc_amount: 100,
            burn_tx_hash: "0x".to_string(),
            timestamp: 0,
            beneficiary: "Corp X".to_string(),
            owner: "0x".to_string(),
            claim_type: ClaimType::CorporateNetZero,
            amount_tco2e: 100,
            status: PoOStatus::Finalized,
        }
    }

    #[test]
    fn amounts_consistent() {
        let poo = make_poo();
        assert!(poo.amounts_are_consistent());
    }
}
