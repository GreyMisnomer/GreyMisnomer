use serde::{Deserialize, Serialize};
use crate::serial::SerialRange;

// Represents the operational lifecycle status of a credit fragment.


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditStatus {
    Active,
    Retired,
    Expired,
}

// A fragment of the original serial range, tracking its specific lifecycle state.
// This allows partial retirement and granular tracking of the credit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialSlice {
    pub range: SerialRange,
    pub status: CreditStatus,
}

// Represents the on-chain carbon credit asset mapping to a specific project.
// Tracks the full issuance provenance (`original_range`) and the fragmented operational state (`slices`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditBatch {
    pub project_id: String,
    pub credit_id: String,
    pub original_range: SerialRange, // Immutable — set at mint, audit trail only
    pub slices: Vec<SerialSlice>,    // Mutable — the operational truth
    pub owner: String,
}

impl CreditBatch {
    // Returns true if any slice within this batch is currently Active.
    pub fn is_active(&self) -> bool {
        self.slices.iter().any(|s| s.status == CreditStatus::Active)
    }

    pub fn summary(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("Credit ID: {}\n", self.credit_id));
        out.push_str(&format!("Owner: {}\n\n", self.owner));
        out.push_str(&format!("Original Range: {}–{}\n\n", self.original_range.start, self.original_range.end));

        out.push_str("Active:\n");
        for s in &self.slices {
            if s.status == CreditStatus::Active {
                out.push_str(&format!("  {}–{}\n", s.range.start, s.range.end));
            }
        }

        out.push_str("\nRetired:\n");
        for s in &self.slices {
            if s.status == CreditStatus::Retired {
                out.push_str(&format!("  {}–{}\n", s.range.start, s.range.end));
            }
        }

        out
    }

    // Validates the internal consistency of the CreditBatch to ensure no overlap or out-of-bounds slices exist.
    // Serves as a critical fail-fast invariant guard after any state mutation.
    pub fn validate_internal(&self) -> bool {
        // 1. All slices must lie within original_range
        for s in &self.slices {
            if !self.original_range.contains(&s.range) {
                return false;
            }
        }

        // 2. No overlaps between slices
        for i in 0..self.slices.len() {
            for j in i + 1..self.slices.len() {
                if self.slices[i].range.overlaps(&self.slices[j].range) {
                    return false;
                }
            }
        }

        true
    }
}

// Normalizes a list of slices by sorting them by start range and merging adjacent slices with the same status.
// This prevents infinite fragmentation of the serial range state.
pub fn normalize_slices(slices: &mut Vec<SerialSlice>) {
    slices.sort_by_key(|s| s.range.start);

    let mut merged: Vec<SerialSlice> = Vec::new();

    for slice in slices.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.status == slice.status && last.range.end + 1 == slice.range.start {
                last.range.end = slice.range.end;
                continue;
            }
        }
        merged.push(slice);
    }

    *slices = merged;
}
