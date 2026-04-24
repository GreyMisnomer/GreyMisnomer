use serde::{Deserialize, Serialize};
use crate::serial::SerialRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditStatus {
    Active,
    Retired,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialSlice {
    pub range: SerialRange,
    pub status: CreditStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditBatch {
    pub project_id: String,
    pub credit_id: String,
    pub original_range: SerialRange,
    pub slices: Vec<SerialSlice>,
    pub owner: String,
}

impl CreditBatch {
    pub fn is_active(&self) -> bool {
        self.slices.iter().any(|s| s.status == CreditStatus::Active)
    }
}
