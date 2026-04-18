use serde::{Deserialize, Serialize};

// This represents the Merkle Root commitment of all underlying, off-chain MRV data (RFC-003).
// We store just the cryptographic proof rather than millions of sensor logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MRVCommitment {
    // The BLAKE3 hash of the Merkle Tree root containing the raw data
    pub merkle_root: [u8; 32],
    // The hashing algorithm used (e.g., "BLAKE3")
    pub hash_algorithm: String,
    // The number of data points (leaves) in the Merkle Tree
    pub leaf_count: u64,
    // Unix timestamp of when the commitment was finalized
    pub timestamp: u64,
}
