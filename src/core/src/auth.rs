//! RFC-005: Cryptographic Identity, Canonical Encoding & Strict Authorization
//!
//! Provides the core cryptographic primitives (Ed25519 strict verification),
//! canonical binary encoding (`enc`), and deterministic preimage builders for
//! all protocol state transitions.

use crate::error::RegistryError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

// --- PubKey (32 bytes Ed25519) --------------------------------------------

/// 32-byte Ed25519 public key.
/// Canonical text serialization is 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub [u8; 32]);

impl PubKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 64-character lowercase hex string and asserts that it decodes
    /// to a valid, non-small-order Ed25519 curve point per RFC 8032 strict verification.
    pub fn from_hex(s: &str) -> Result<Self, RegistryError> {
        if s.len() != 64 {
            return Err(RegistryError::InvalidPublicKey(format!(
                "expected 64 hex characters, found {}",
                s.len()
            )));
        }
        // Strict check: reject uppercase or invalid characters
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(RegistryError::InvalidPublicKey(
                "public key hex must be strictly lowercase".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|e| RegistryError::InvalidPublicKey(e.to_string()))?;

        // Strict curve-point validation: verify it decodes into a valid VerifyingKey
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| RegistryError::InvalidPublicKey(format!("invalid curve point: {e}")))?;

        Ok(Self(bytes))
    }

    /// Verifies an Ed25519 signature in RFC 8032 strict mode:
    /// - Rejects non-canonical scalar S >= L
    /// - Rejects small-order points
    pub fn verify_strict(&self, msg: &[u8], sig: &Signature) -> Result<(), RegistryError> {
        let verifying_key = VerifyingKey::from_bytes(&self.0)
            .map_err(|e| RegistryError::InvalidPublicKey(e.to_string()))?;

        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.0);

        verifying_key
            .verify_strict(msg, &ed_sig)
            .map_err(|_| RegistryError::BadSignature)
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PubKey({})", self.to_hex())
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PubKey::from_hex(&s).map_err(de::Error::custom)
    }
}

// --- Signature (64 bytes Ed25519) -----------------------------------------

/// 64-byte detached Ed25519 signature.
/// Canonical text serialization is 128 lowercase hexadecimal characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature(pub [u8; 64]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Signature {
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, RegistryError> {
        if s.len() != 128 {
            return Err(RegistryError::BadSignature);
        }
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(RegistryError::BadSignature);
        }
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| RegistryError::BadSignature)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({}..{})",
            &self.to_hex()[..16],
            &self.to_hex()[112..]
        )
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_hex(&s).map_err(de::Error::custom)
    }
}

// --- Keypair (for test, demo & CLI tooling) --------------------------------

/// Secret signing key wrapper for local signing operations.
pub struct Keypair {
    pub signing_key: SigningKey,
}

impl Keypair {
    pub fn from_bytes(secret_bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret_bytes),
        }
    }

    pub fn pubkey(&self) -> PubKey {
        PubKey(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.signing_key.sign(msg).to_bytes())
    }
}

// --- Canonical Binary Encoding (enc) --------------------------------------
// RFC-005 §3.2: Deterministic, big-endian binary byte layout for signing preimages.
// Completely decouples cryptographic hashes and signatures from JSON serialization.

#[inline]
pub fn enc_u64(v: u64, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&v.to_be_bytes());
}

#[inline]
pub fn enc_bytes32(b: &[u8; 32], buf: &mut Vec<u8>) {
    buf.extend_from_slice(b);
}

#[inline]
pub fn enc_pubkey(p: &PubKey, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&p.0);
}

#[inline]
pub fn enc_sig(s: &Signature, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&s.0);
}

#[inline]
pub fn enc_str(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    enc_u64(bytes.len() as u64, buf);
    buf.extend_from_slice(bytes);
}

#[inline]
pub fn enc_tag(tag: u8, buf: &mut Vec<u8>) {
    buf.push(tag);
}

// --- Preimage Builders ----------------------------------------------------

/// Computes the unique `chain_id` from the genesis event body bytes:
/// chain_id = BLAKE3(enc(str "GM/v1/chain") || genesis_body_bytes)
pub fn compute_chain_id(genesis_body_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    enc_str("GM/v1/chain", &mut buf);
    buf.extend_from_slice(genesis_body_bytes);
    *blake3::hash(&buf).as_bytes()
}

/// Genesis signing preimage:
/// str "GM/v1/genesis" || str chain_name || authority || sequencer || nonce || created_at
pub fn build_genesis_preimage(
    chain_name: &str,
    authority: &PubKey,
    sequencer: &PubKey,
    nonce: &[u8; 32],
    created_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str("GM/v1/genesis", &mut buf);
    enc_str(chain_name, &mut buf);
    enc_pubkey(authority, &mut buf);
    enc_pubkey(sequencer, &mut buf);
    enc_bytes32(nonce, &mut buf);
    enc_u64(created_at, &mut buf);
    buf
}

/// Genesis entry body bytes (for sequence 0 hashing):
/// tag(0) || str chain_name || authority || sequencer || nonce || created_at || authority_sig
pub fn build_genesis_body(
    chain_name: &str,
    authority: &PubKey,
    sequencer: &PubKey,
    nonce: &[u8; 32],
    created_at: u64,
    authority_sig: &Signature,
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_tag(0, &mut buf);
    enc_str(chain_name, &mut buf);
    enc_pubkey(authority, &mut buf);
    enc_pubkey(sequencer, &mut buf);
    enc_bytes32(nonce, &mut buf);
    enc_u64(created_at, &mut buf);
    enc_sig(authority_sig, &mut buf);
    buf
}

/// Authority event signing preimage:
/// str "GM/v1/<name>" || chain_id || u64 authority_index || payload_bytes
pub fn build_authority_event_preimage(
    action_name: &str,
    chain_id: &[u8; 32],
    authority_index: u64,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str(&format!("GM/v1/{action_name}"), &mut buf);
    enc_bytes32(chain_id, &mut buf);
    enc_u64(authority_index, &mut buf);
    buf.extend_from_slice(payload_bytes);
    buf
}

/// VVB registration payload bytes: pubkey vvb || str label
pub fn build_vvb_register_payload(vvb: &PubKey, label: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_pubkey(vvb, &mut buf);
    enc_str(label, &mut buf);
    buf
}

/// VVB revocation payload bytes: pubkey vvb
pub fn build_vvb_revoke_payload(vvb: &PubKey) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_pubkey(vvb, &mut buf);
    buf
}

/// Authority rotate payload bytes: pubkey new_authority
pub fn build_authority_rotate_payload(new_authority: &PubKey) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_pubkey(new_authority, &mut buf);
    buf
}

/// Sequencer rotate payload bytes: pubkey new_sequencer
pub fn build_sequencer_rotate_payload(new_sequencer: &PubKey) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_pubkey(new_sequencer, &mut buf);
    buf
}

/// Parameters required to construct the canonical mint attestation preimage (RFC-005 §3.5).
#[derive(Clone, Copy, Debug)]
pub struct MintAttestationParams<'a> {
    pub chain_id: &'a [u8; 32],
    pub project_id: &'a str,
    pub credit_id: &'a str,
    pub range_start: u64,
    pub range_end: u64,
    pub cc_mint_amount: u64,
    pub merkle_root: &'a [u8; 32],
    pub leaf_count: u64,
    pub mrv_timestamp: u64,
    pub methodology_hash: &'a str,
    pub jurisdiction: &'a str,
    pub market_scope: &'a str,
    pub valid_from: u64,
    pub valid_until: u64,
    pub initial_owner: &'a PubKey,
}

/// Mint attestation signing preimage (RFC-005 §3.5):
/// str "GM/v1/mint" || chain_id || project_id || credit_id || range.start || range.end ||
/// cc_mint_amount || merkle_root || leaf_count || mrv_timestamp || methodology_hash ||
/// jurisdiction || market_scope || valid_from || valid_until || initial_owner
pub fn build_mint_preimage(params: &MintAttestationParams<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str("GM/v1/mint", &mut buf);
    enc_bytes32(params.chain_id, &mut buf);
    enc_str(params.project_id, &mut buf);
    enc_str(params.credit_id, &mut buf);
    enc_u64(params.range_start, &mut buf);
    enc_u64(params.range_end, &mut buf);
    enc_u64(params.cc_mint_amount, &mut buf);
    enc_bytes32(params.merkle_root, &mut buf);
    enc_u64(params.leaf_count, &mut buf);
    enc_u64(params.mrv_timestamp, &mut buf);
    enc_str(params.methodology_hash, &mut buf);
    enc_str(params.jurisdiction, &mut buf);
    enc_str(params.market_scope, &mut buf);
    enc_u64(params.valid_from, &mut buf);
    enc_u64(params.valid_until, &mut buf);
    enc_pubkey(params.initial_owner, &mut buf);
    buf
}

/// Transfer authorization signing preimage (RFC-005 §3.5):
/// str "GM/v1/transfer" || chain_id || credit_id || op_index || new_owner
pub fn build_transfer_preimage(
    chain_id: &[u8; 32],
    credit_id: &str,
    op_index: u64,
    new_owner: &PubKey,
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str("GM/v1/transfer", &mut buf);
    enc_bytes32(chain_id, &mut buf);
    enc_str(credit_id, &mut buf);
    enc_u64(op_index, &mut buf);
    enc_pubkey(new_owner, &mut buf);
    buf
}

/// Burn authorization signing preimage (RFC-005 §3.5):
/// str "GM/v1/burn" || chain_id || credit_id || op_index || range.start || range.end ||
/// beneficiary || claim_type
pub fn build_burn_preimage(
    chain_id: &[u8; 32],
    credit_id: &str,
    op_index: u64,
    range_start: u64,
    range_end: u64,
    beneficiary: &str,
    claim_type: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str("GM/v1/burn", &mut buf);
    enc_bytes32(chain_id, &mut buf);
    enc_str(credit_id, &mut buf);
    enc_u64(op_index, &mut buf);
    enc_u64(range_start, &mut buf);
    enc_u64(range_end, &mut buf);
    enc_str(beneficiary, &mut buf);
    enc_str(claim_type, &mut buf);
    buf
}

/// Checkpoint signing preimage (RFC-005 §3.7):
/// str "GM/v1/checkpoint" || chain_id || size || head_hash || timestamp
pub fn build_checkpoint_preimage(
    chain_id: &[u8; 32],
    size: u64,
    head_hash: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    enc_str("GM/v1/checkpoint", &mut buf);
    enc_bytes32(chain_id, &mut buf);
    enc_u64(size, &mut buf);
    enc_bytes32(head_hash, &mut buf);
    enc_u64(timestamp, &mut buf);
    buf
}

/// Canonical entry hash preimage (RFC-005 §3.6):
/// BLAKE3(str "GM/v1/entry" || u64 seq || bytes32 prev_hash || body_bytes)
pub fn compute_entry_hash(seq: u64, prev_hash: &[u8; 32], body_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    enc_str("GM/v1/entry", &mut buf);
    enc_u64(seq, &mut buf);
    enc_bytes32(prev_hash, &mut buf);
    buf.extend_from_slice(body_bytes);
    *blake3::hash(&buf).as_bytes()
}

/// Computes the unique `poi_hash` for a minted credit batch (RFC-005 §3.5):
/// poi_hash = BLAKE3(enc(str "GM/v1/poi") || mint_msg || vvb_sig)
pub fn compute_poi_hash(mint_msg: &[u8], vvb_sig: &Signature) -> [u8; 32] {
    let mut buf = Vec::new();
    enc_str("GM/v1/poi", &mut buf);
    buf.extend_from_slice(mint_msg);
    enc_sig(vvb_sig, &mut buf);
    *blake3::hash(&buf).as_bytes()
}

/// Serde helper for 32-byte arrays formatted as 64 lowercase hexadecimal characters.
pub mod hex_bytes32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() != 64 {
            return Err(de::Error::custom("expected 64 hex chars for 32-byte value"));
        }
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(de::Error::custom("hex string must be strictly lowercase"));
        }
        let mut buf = [0u8; 32];
        hex::decode_to_slice(&s, &mut buf).map_err(de::Error::custom)?;
        Ok(buf)
    }
}

// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_roundtrip_and_strict_validation() {
        let secret = [42u8; 32];
        let kp = Keypair::from_bytes(&secret);
        let pk = kp.pubkey();
        let hex_str = pk.to_hex();
        assert_eq!(hex_str.len(), 64);

        let parsed = PubKey::from_hex(&hex_str).unwrap();
        assert_eq!(pk, parsed);

        // Reject uppercase hex
        let upper = hex_str.to_uppercase();
        assert!(PubKey::from_hex(&upper).is_err());

        // Reject invalid length
        assert!(PubKey::from_hex(&hex_str[..62]).is_err());
    }

    #[test]
    fn test_signature_verify_strict() {
        let kp = Keypair::from_bytes(&[7u8; 32]);
        let msg = b"Canonical test payload for GreyMisnomer";
        let sig = kp.sign(msg);

        // Valid signature verifies
        assert!(kp.pubkey().verify_strict(msg, &sig).is_ok());

        // Tampered message fails
        let tampered_msg = b"Tampered test payload";
        assert_eq!(
            kp.pubkey().verify_strict(tampered_msg, &sig).unwrap_err(),
            RegistryError::BadSignature
        );

        // Wrong public key fails
        let other_kp = Keypair::from_bytes(&[8u8; 32]);
        assert_eq!(
            other_kp.pubkey().verify_strict(msg, &sig).unwrap_err(),
            RegistryError::BadSignature
        );
    }

    #[test]
    fn test_canonical_preimage_determinism() {
        let chain_id = [1u8; 32];
        let p1 = build_transfer_preimage(&chain_id, "CC-001", 0, &PubKey([2u8; 32]));
        let p2 = build_transfer_preimage(&chain_id, "CC-001", 0, &PubKey([2u8; 32]));
        assert_eq!(p1, p2);

        // Preimage commits strictly to domain prefix
        assert!(p1.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\x0eGM/v1/transfer"));
    }

    #[test]
    fn test_cross_chain_replay_prevention() {
        let chain_a = [1u8; 32];
        let chain_b = [2u8; 32];
        let p_a = build_transfer_preimage(&chain_a, "CC-001", 0, &PubKey([9u8; 32]));
        let p_b = build_transfer_preimage(&chain_b, "CC-001", 0, &PubKey([9u8; 32]));
        assert_ne!(p_a, p_b);
    }

    #[test]
    fn test_op_index_replay_prevention() {
        let chain = [1u8; 32];
        let p_op0 = build_transfer_preimage(&chain, "CC-001", 0, &PubKey([9u8; 32]));
        let p_op1 = build_transfer_preimage(&chain, "CC-001", 1, &PubKey([9u8; 32]));
        assert_ne!(p_op0, p_op1);
    }

    #[test]
    fn test_mint_and_burn_preimages() {
        let chain = [5u8; 32];
        let owner = PubKey([7u8; 32]);
        let root = [9u8; 32];

        let mint_params = MintAttestationParams {
            chain_id: &chain,
            project_id: "PROJ-101",
            credit_id: "CC-2026-001",
            range_start: 1,
            range_end: 1000,
            cc_mint_amount: 1000,
            merkle_root: &root,
            leaf_count: 50,
            mrv_timestamp: 1776000000,
            methodology_hash: "blake3:abcd",
            jurisdiction: "US-CA",
            market_scope: "voluntary",
            valid_from: 1776000000,
            valid_until: 1800000000,
            initial_owner: &owner,
        };

        let mint_preimage = build_mint_preimage(&mint_params);
        assert!(mint_preimage.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\nGM/v1/mint"));

        let burn_preimage = build_burn_preimage(
            &chain,
            "CC-2026-001",
            1,
            1,
            500,
            "Acme Corp Scope 1 Retirement",
            "compliance",
        );
        assert!(burn_preimage.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\nGM/v1/burn"));

        let entry_hash = compute_entry_hash(1, &[0u8; 32], &mint_preimage);
        assert_ne!(entry_hash, [0u8; 32]);
    }
}
