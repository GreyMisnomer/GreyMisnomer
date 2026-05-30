use serde::{Deserialize, Serialize};
use crate::serial::SerialRange;
use crate::mrv::MRVCommitment;
use crate::project::MarketScope;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoIStatus {
    Valid,
    Used,
    Revoked,
}

// Proof-of-Integrity (PoI) represents the cryptographic authorization to mint carbon credits.
// As defined in RFC-001 §3.1, it binds real-world MRV data to a specific serial range
// and must be digitally signed by a recognized VVB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoI {
    pub project_id: String,
    pub mrv_commitment: MRVCommitment,
    pub methodology_hash: String,
    pub vvb_signature: String,
    pub serialization_range: SerialRange,
    pub amount_tco2e: u64,
    pub jurisdiction: String,
    pub market_scope: MarketScope,
    
    pub credit_id: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub poi_valid: bool,
    pub cc_mint_amount: u64,
    pub owner: String,
    pub status: PoIStatus,
}

impl PoI {
    pub fn is_used(&self) -> bool {
        self.status == PoIStatus::Used
    }

    /// Checks if PoI is Valid, zk-proof (poi_valid mock) passed, & supply non-zero
    pub fn is_valid_for_minting(&self) -> bool {
        self.status == PoIStatus::Valid
            && self.poi_valid
            && self.cc_mint_amount > 0
            && self.serialization_range.is_valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poi_used_check() {
        let poi = PoI {
            project_id: "PRJ-001".to_string(),
            mrv_commitment: MRVCommitment {
                merkle_root: [0; 32],
                hash_algorithm: "BLAKE3".to_string(),
                leaf_count: 1,
                timestamp: 0,
            },
            methodology_hash: "0xhash".to_string(),
            vvb_signature: "0xsig".to_string(),
            serialization_range: SerialRange::new(0, 10).unwrap(),
            amount_tco2e: 11,
            jurisdiction: "US".to_string(),
            market_scope: MarketScope::Vcm,
            credit_id: "TEST".to_string(),
            valid_from: 0,
            valid_until: 0,
            poi_valid: true,
            cc_mint_amount: 11,
            owner: "test".to_string(),
            status: PoIStatus::Used,
        };

        assert!(poi.is_used());
        assert!(!poi.is_valid_for_minting());
    }
}
