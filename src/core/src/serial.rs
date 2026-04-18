use serde::{Deserialize, Serialize};
use crate::error::RegistryError;

// The SerialRange struct maps to our RFC-002 specification.
// It defines a contiguous block of carbon credits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialRange {
    pub start: u64,
    pub end: u64,
}

impl SerialRange {
    // A constructor function to safely create a new SerialRange.
    pub fn new(start: u64, end: u64) -> Result<Self, RegistryError> {
        if start > end {
            // Enforce basic invariant that range cannot end before it begins
            return Err(RegistryError::InvalidRange);
        }
        Ok(Self { start, end })
    }

    // Checking validity separately helps keeping registry state machine clean
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }

    // Calculates the total number of credits (tCO2e) in this range.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    // Checks if this range overlaps with another range to prevent double-counting.
    pub fn overlaps(&self, other: &SerialRange) -> bool {
        !(self.end < other.start || self.start > other.end)
    }

    // Checks if this range completely contains another range.
    pub fn contains(&self, other: &SerialRange) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_range() {
        let r = SerialRange::new(0, 10).unwrap();
        assert_eq!(r.size(), 11);
    }

    #[test]
    fn test_single_range() {
        let r = SerialRange::new(5, 5).unwrap();
        assert_eq!(r.size(), 1);
        assert!(r.is_valid());
    }

    #[test]
    fn test_invalid_range() {
        let result = SerialRange::new(10, 0);
        assert_eq!(result.unwrap_err(), RegistryError::InvalidRange);
    }

    #[test]
    fn test_overlap() {
        let a = SerialRange::new(0, 10).unwrap();
        let b = SerialRange::new(5, 15).unwrap();
        assert!(a.overlaps(&b));
    }

    #[test]
    fn test_no_overlap() {
        let a = SerialRange::new(0, 10).unwrap();
        let b = SerialRange::new(11, 20).unwrap();
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn test_containment() {
        let a = SerialRange::new(0, 100).unwrap();
        let b = SerialRange::new(10, 50).unwrap();
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }
}
