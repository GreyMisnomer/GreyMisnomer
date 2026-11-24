//! RFC-007 §4.2: Three-Root CheckpointHeaderV2.
//!
//! Compact binary checkpoint header committing three independent cryptographic roots:
//! 1. `events_root`: RFC 9162 log root committing all historical entries [0..tree_size).
//! 2. `uco_state_root`: Merkle root of all currently unspent UCOs sorted by OutPoint.
//! 3. `poo_archive_root`: Merkle root of all cumulative permanent Proof-of-Offset retirements.
//!
//! Total binary size is exactly 178 bytes (< 300-byte budget).

use crate::auth::{hash_checkpoint_v2, PubKey, Signature};
use crate::error::RegistryError;
use serde::{Deserialize, Serialize};

/// Canonical 178-byte binary layout for v2 checkpoint headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHeaderV2 {
    /// Protocol version (must be 2)
    pub version: u16,
    /// CSPRNG-rooted registry identifier
    #[serde(with = "crate::auth::hex_bytes32")]
    pub chain_id: [u8; 32],
    /// Total events committed in the RFC 9162 log
    pub tree_size: u64,
    /// Advisory UTC timestamp in nanoseconds
    pub timestamp_ns: u64,
    /// RFC 9162 Merkle root of all log entries
    #[serde(with = "crate::auth::hex_bytes32")]
    pub events_root: [u8; 32],
    /// Merkle root of all currently unspent UCOs (sorted by OutPoint)
    #[serde(with = "crate::auth::hex_bytes32")]
    pub uco_state_root: [u8; 32],
    /// Merkle root of all cumulative Proof-of-Offset retirements
    #[serde(with = "crate::auth::hex_bytes32")]
    pub poo_archive_root: [u8; 32],
    /// Hash of active VVB accreditation & witness quorum set
    #[serde(with = "crate::auth::hex_bytes32")]
    pub active_validators_hash: [u8; 32],
}

impl CheckpointHeaderV2 {
    pub const BYTE_SIZE: usize = 178;

    /// Serializes to the canonical 178-byte big-endian binary layout.
    pub fn to_canonical_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut buf = [0u8; Self::BYTE_SIZE];
        buf[0..2].copy_from_slice(&self.version.to_be_bytes());
        buf[2..34].copy_from_slice(&self.chain_id);
        buf[34..42].copy_from_slice(&self.tree_size.to_be_bytes());
        buf[42..50].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        buf[50..82].copy_from_slice(&self.events_root);
        buf[82..114].copy_from_slice(&self.uco_state_root);
        buf[114..146].copy_from_slice(&self.poo_archive_root);
        buf[146..178].copy_from_slice(&self.active_validators_hash);
        buf
    }

    /// Deserializes from the canonical 178-byte big-endian binary layout.
    pub fn from_canonical_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Result<Self, RegistryError> {
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != 2 {
            return Err(RegistryError::InvalidStateTransition {
                from: format!("version {version}"),
                to: "v2".to_string(),
            });
        }
        let mut chain_id = [0u8; 32];
        chain_id.copy_from_slice(&bytes[2..34]);

        let tree_size = u64::from_be_bytes([
            bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41],
        ]);
        let timestamp_ns = u64::from_be_bytes([
            bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49],
        ]);

        let mut events_root = [0u8; 32];
        events_root.copy_from_slice(&bytes[50..82]);

        let mut uco_state_root = [0u8; 32];
        uco_state_root.copy_from_slice(&bytes[82..114]);

        let mut poo_archive_root = [0u8; 32];
        poo_archive_root.copy_from_slice(&bytes[114..146]);

        let mut active_validators_hash = [0u8; 32];
        active_validators_hash.copy_from_slice(&bytes[146..178]);

        Ok(Self {
            version,
            chain_id,
            tree_size,
            timestamp_ns,
            events_root,
            uco_state_root,
            poo_archive_root,
            active_validators_hash,
        })
    }

    /// Domain-separated signing commitment: `BLAKE3("GM-v2-CHK:" || canonical_bytes)`
    pub fn signing_hash(&self) -> [u8; 32] {
        let bytes = self.to_canonical_bytes();
        hash_checkpoint_v2(&bytes)
    }

    /// Verifies that the sequencer's signature over `signing_hash()` is valid.
    pub fn verify_sequencer_sig(
        &self,
        sequencer: &PubKey,
        sig: &Signature,
    ) -> Result<(), RegistryError> {
        let h = self.signing_hash();
        sequencer.verify_strict(&h, sig)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keypair;

    #[test]
    fn test_checkpoint_header_v2_size_under_300_bytes() {
        assert_eq!(CheckpointHeaderV2::BYTE_SIZE, 178);
        const { assert!(CheckpointHeaderV2::BYTE_SIZE < 300) };
    }

    #[test]
    fn test_checkpoint_header_v2_canonical_roundtrip() {
        let header = CheckpointHeaderV2 {
            version: 2,
            chain_id: [0x11; 32],
            tree_size: 10_000,
            timestamp_ns: 1_776_000_000_000_000_000,
            events_root: [0x22; 32],
            uco_state_root: [0x33; 32],
            poo_archive_root: [0x44; 32],
            active_validators_hash: [0x55; 32],
        };

        let bytes = header.to_canonical_bytes();
        assert_eq!(bytes.len(), 178);

        let parsed = CheckpointHeaderV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_checkpoint_header_v2_signing_and_verification() {
        let sequencer = Keypair::generate();
        let header = CheckpointHeaderV2 {
            version: 2,
            chain_id: [0xAA; 32],
            tree_size: 256,
            timestamp_ns: 1_700_000_000,
            events_root: [0xBB; 32],
            uco_state_root: [0xCC; 32],
            poo_archive_root: [0xDD; 32],
            active_validators_hash: [0xEE; 32],
        };

        let sig = sequencer.sign(&header.signing_hash());
        assert!(header
            .verify_sequencer_sig(&sequencer.pubkey(), &sig)
            .is_ok());

        // Forged sequencer key fails
        let impostor = Keypair::generate();
        assert!(header
            .verify_sequencer_sig(&impostor.pubkey(), &sig)
            .is_err());
    }

    #[test]
    fn test_checkpoint_header_v2_rejects_bad_version() {
        let mut bytes = [0u8; 178];
        bytes[0..2].copy_from_slice(&1u16.to_be_bytes()); // version 1
        assert!(CheckpointHeaderV2::from_canonical_bytes(&bytes).is_err());
    }
}
