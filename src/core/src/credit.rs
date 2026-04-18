use serde::{Deserialize, Serialize};
use crate::serial::SerialRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditStatus {
    Active,
    Retired,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditBatch {
    pub project_id: String,
    pub credit_id: String,
    pub serial_range: SerialRange,
    pub owner: String,
    pub status: CreditStatus,
}
